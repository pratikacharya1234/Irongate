"""IronGate — Ban Service."""
import hashlib, json
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID
import httpx
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import get_settings
from app.core.redis import cache_service, pubsub_service
from app.core.security import sign_webhook_payload
from app.models.models import Agent, AgentStatus, AuditAction, AuditLog, Ban, BanScope, TrustNetworkPeer
from app.schemas.schemas import BanCreate

settings = get_settings()

class BanService:
    def __init__(self, db: AsyncSession): self.db = db

    async def create_ban(self, data: BanCreate, created_by=None) -> Ban:
        agent = (await self.db.execute(select(Agent).where(Agent.id == data.agent_id))).scalar_one_or_none()
        if not agent: raise ValueError("Agent not found")
        existing = (await self.db.execute(select(Ban).where(and_(Ban.agent_id == data.agent_id, Ban.is_active == True, Ban.scope == BanScope(data.scope))))).scalar_one_or_none()
        if existing: raise ValueError("Active ban already exists")
        expires_at = None
        if not data.is_permanent and data.expires_hours: expires_at = datetime.now(timezone.utc) + timedelta(hours=data.expires_hours)
        ban = Ban(agent_id=data.agent_id, reason=data.reason, scope=BanScope(data.scope), is_permanent=data.is_permanent, expires_at=expires_at, triggering_threat_ids=[str(t) for t in data.triggering_threat_ids], evidence_summary=data.evidence_summary, created_by=created_by, propagation_status="pending")
        self.db.add(ban); agent.status = AgentStatus.BANNED; agent.trust_score = 0; agent.banned_at = datetime.now(timezone.utc)
        await self.db.flush()
        await self._audit(AuditAction.BAN_CREATED, agent_id=agent.id, user_id=created_by, description=f"Ban for '{agent.name}': {data.reason}")
        await pubsub_service.publish("bans", {"event": "ban_created", "ban_id": str(ban.id), "agent_id": str(agent.id), "agent_name": agent.name, "agent_fingerprint": agent.fingerprint, "scope": data.scope})
        await cache_service.invalidate_pattern("bans:*"); await cache_service.invalidate_pattern("dashboard:*"); return ban

    async def propagate_ban(self, ban_id: UUID):
        ban = (await self.db.execute(select(Ban).where(Ban.id == ban_id))).scalar_one_or_none()
        if not ban: raise ValueError("Ban not found")
        agent = (await self.db.execute(select(Agent).where(Agent.id == ban.agent_id))).scalar_one_or_none()
        peers = list((await self.db.execute(select(TrustNetworkPeer).where(TrustNetworkPeer.is_active == True))).scalars().all())
        ban.propagation_status = "in_progress"; ban.propagation_started_at = datetime.now(timezone.utc); await self.db.flush()
        payload = {"event_type": "ban_notification", "source_node_id": settings.TRUST_NETWORK_NODE_ID, "timestamp": datetime.now(timezone.utc).isoformat(), "ban": {"ban_id": str(ban.id), "agent_fingerprint": agent.fingerprint if agent else None, "agent_name": agent.name if agent else None, "reason": ban.reason, "scope": str(ban.scope.value), "is_permanent": ban.is_permanent}}
        signature = sign_webhook_payload(json.dumps(payload, sort_keys=True).encode())
        results = []; success = 0
        async with httpx.AsyncClient(timeout=settings.BAN_PROPAGATION_WEBHOOK_TIMEOUT) as client:
            for peer in peers:
                try:
                    resp = await client.post(f"{peer.endpoint_url}/api/v1/trust/receive-intel", json=payload, headers={"X-IronGate-Signature": signature, "X-IronGate-Node": settings.TRUST_NETWORK_NODE_ID})
                    s = "success" if resp.status_code in (200,201,202) else f"error_{resp.status_code}"
                except: s = "error"
                results.append({"peer": peer.name, "status": s})
                if s == "success": success += 1; peer.intel_shared += 1; peer.last_sync_at = datetime.now(timezone.utc)
        ban.propagated_to = results; ban.propagation_count = success; ban.propagation_status = "completed" if success > 0 else "failed"; ban.propagation_completed_at = datetime.now(timezone.utc)
        await self.db.flush(); return {"ban_id": str(ban.id), "total_peers": len(peers), "success_count": success, "results": results}

    async def revoke_ban(self, ban_id: UUID, revoked_by: UUID, reason: str):
        ban = (await self.db.execute(select(Ban).where(Ban.id == ban_id))).scalar_one_or_none()
        if not ban or not ban.is_active: return None
        ban.is_active = False; ban.revoked_by = revoked_by; ban.revoked_at = datetime.now(timezone.utc); ban.revocation_reason = reason
        other = (await self.db.execute(select(func.count(Ban.id)).where(and_(Ban.agent_id == ban.agent_id, Ban.is_active == True, Ban.id != ban_id)))).scalar() or 0
        if other == 0:
            agent = (await self.db.execute(select(Agent).where(Agent.id == ban.agent_id))).scalar_one_or_none()
            if agent: agent.status = AgentStatus.SUSPICIOUS; agent.trust_score = 25
        await self.db.flush(); await cache_service.invalidate_pattern("bans:*"); await cache_service.invalidate_pattern("dashboard:*"); return ban

    async def list_bans(self, agent_id=None, active_only=True, scope=None, page=1, page_size=50):
        query = select(Ban); conds = []
        if agent_id: conds.append(Ban.agent_id == agent_id)
        if active_only: conds.append(Ban.is_active == True)
        if scope: conds.append(Ban.scope == BanScope(scope))
        if conds: query = query.where(and_(*conds))
        total = (await self.db.execute(select(func.count()).select_from(query.subquery()))).scalar() or 0
        query = query.order_by(Ban.created_at.desc()).offset((page-1)*page_size).limit(page_size)
        return list((await self.db.execute(query)).scalars().all()), total

    async def check_expired_bans(self):
        now = datetime.now(timezone.utc)
        expired = list((await self.db.execute(select(Ban).where(and_(Ban.is_active == True, Ban.is_permanent == False, Ban.expires_at <= now)))).scalars().all())
        for b in expired: b.is_active = False; b.revocation_reason = "Expired"; b.revoked_at = now
        await self.db.flush(); return len(expired)

    async def _audit(self, action, description, agent_id=None, user_id=None, details=None):
        prev = (await self.db.execute(select(AuditLog.entry_hash).order_by(AuditLog.created_at.desc()).limit(1))).scalar_one_or_none() or "genesis"
        entry_hash = hashlib.sha256(f"{action}|{agent_id}|{user_id}|{description}|{prev}".encode()).hexdigest()
        self.db.add(AuditLog(action=action, user_id=user_id, agent_id=agent_id, description=description, details=details or {}, previous_hash=prev, entry_hash=entry_hash))

"""IronGate — Agent Service."""
import hashlib
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import get_settings
from app.core.redis import cache_service, pubsub_service
from app.models.models import Agent, AgentStatus, AuditAction, AuditLog
from app.schemas.schemas import AgentRegister, AgentUpdate

settings = get_settings()

class AgentService:
    def __init__(self, db: AsyncSession): self.db = db

    async def register_agent(self, data: AgentRegister, fingerprint: str, ip_address: str, user_agent: str, country: Optional[str] = None) -> Agent:
        existing = await self.db.execute(select(Agent).where(Agent.fingerprint == fingerprint))
        if existing.scalar_one_or_none(): raise ValueError(f"Agent with fingerprint {fingerprint} already registered")
        agent = Agent(name=data.name, description=data.description, organization=data.organization, contact_email=data.contact_email, fingerprint=fingerprint, user_agent=user_agent, ip_addresses=[ip_address], status=AgentStatus.PENDING, trust_score=settings.TRUST_SCORE_INITIAL, purpose=data.purpose, declared_capabilities=data.declared_capabilities, model_provider=data.model_provider, model_name=data.model_name, sdk_version=data.sdk_version, country=country, agent_metadata=data.metadata, trust_score_history=[{"score": settings.TRUST_SCORE_INITIAL, "timestamp": datetime.now(timezone.utc).isoformat(), "reason": "Initial registration"}])
        self.db.add(agent); await self.db.flush()
        await self._audit(AuditAction.AGENT_REGISTERED, agent_id=agent.id, description=f"Agent '{data.name}' registered with fingerprint {fingerprint}", details={"organization": data.organization, "purpose": data.purpose})
        await pubsub_service.publish("agents", {"event": "agent_registered", "agent_id": str(agent.id), "fingerprint": fingerprint, "name": data.name})
        await cache_service.invalidate_pattern("agents:*"); await cache_service.invalidate_pattern("dashboard:*")
        return agent

    async def get_agent(self, agent_id: UUID) -> Optional[Agent]:
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id)); return result.scalar_one_or_none()

    async def get_agent_by_fingerprint(self, fingerprint: str) -> Optional[Agent]:
        result = await self.db.execute(select(Agent).where(Agent.fingerprint == fingerprint)); return result.scalar_one_or_none()

    async def list_agents(self, status=None, page=1, page_size=50, sort_by="last_active_at", sort_order="desc", search=None):
        query = select(Agent)
        if status: query = query.where(Agent.status == status)
        if search:
            sf = f"%{search}%"; query = query.where((Agent.name.ilike(sf)) | (Agent.organization.ilike(sf)) | (Agent.fingerprint.ilike(sf)))
        count_q = select(func.count()).select_from(query.subquery()); total = (await self.db.execute(count_q)).scalar() or 0
        sort_col = getattr(Agent, sort_by, Agent.last_active_at)
        query = query.order_by(sort_col.desc() if sort_order == "desc" else sort_col.asc())
        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await self.db.execute(query); return list(result.scalars().all()), total

    async def update_agent(self, agent_id: UUID, data: AgentUpdate):
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id)); agent = result.scalar_one_or_none()
        if not agent: return None
        for field, value in data.model_dump(exclude_unset=True).items(): setattr(agent, field, value)
        agent.updated_at = datetime.now(timezone.utc); await self.db.flush()
        await cache_service.invalidate_pattern(f"agents:{agent_id}*"); return agent

    async def change_status(self, agent_id: UUID, new_status: str, reason: str, changed_by=None):
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id)); agent = result.scalar_one_or_none()
        if not agent: return None
        old_status = agent.status; agent.status = AgentStatus(new_status)
        if new_status == "verified": agent.trust_score = max(agent.trust_score, 75); agent.verified_at = datetime.now(timezone.utc)
        elif new_status == "suspicious": agent.trust_score = min(agent.trust_score, 40)
        elif new_status == "banned": agent.trust_score = 0; agent.banned_at = datetime.now(timezone.utc)
        history = agent.trust_score_history or []; history.append({"score": agent.trust_score, "timestamp": datetime.now(timezone.utc).isoformat(), "reason": f"Status: {old_status}->{new_status}: {reason}"}); agent.trust_score_history = history
        await self.db.flush()
        action = {"verified": AuditAction.AGENT_VERIFIED, "banned": AuditAction.AGENT_BANNED}.get(new_status, AuditAction.AGENT_STATUS_CHANGED)
        await self._audit(action, agent_id=agent_id, user_id=changed_by, description=f"Status {old_status}->{new_status}: {reason}", details={"old_status": str(old_status), "new_status": new_status})
        await pubsub_service.publish("agents", {"event": "status_changed", "agent_id": str(agent_id), "old_status": str(old_status), "new_status": new_status})
        await cache_service.invalidate_pattern("agents:*"); await cache_service.invalidate_pattern("dashboard:*"); return agent

    async def record_activity(self, agent_id: UUID, endpoint: str, ip_address: str):
        result = await self.db.execute(select(Agent).where(Agent.id == agent_id)); agent = result.scalar_one_or_none()
        if not agent: return
        agent.last_active_at = datetime.now(timezone.utc); agent.total_requests += 1
        ips = agent.ip_addresses or []
        if ip_address not in ips: ips.append(ip_address); agent.ip_addresses = ips[-20:]
        endpoints = agent.typical_endpoints or []
        if endpoint not in endpoints: endpoints.append(endpoint); agent.typical_endpoints = endpoints[-50:]
        await self.db.flush()

    async def get_stats(self):
        cached = await cache_service.get("dashboard:agent_stats")
        if cached: return cached
        result = await self.db.execute(select(func.count(Agent.id).label("total"), func.count(Agent.id).filter(Agent.status == AgentStatus.VERIFIED).label("verified"), func.count(Agent.id).filter(Agent.status == AgentStatus.SUSPICIOUS).label("suspicious"), func.count(Agent.id).filter(Agent.status == AgentStatus.BANNED).label("banned"), func.count(Agent.id).filter(Agent.status == AgentStatus.PENDING).label("pending"), func.avg(Agent.trust_score).label("avg_trust")))
        row = result.one()
        stats = {"total": row.total, "verified": row.verified, "suspicious": row.suspicious, "banned": row.banned, "pending": row.pending, "avg_trust_score": round(float(row.avg_trust or 0), 1)}
        await cache_service.set("dashboard:agent_stats", stats, ttl=60); return stats

    async def _audit(self, action, description, agent_id=None, user_id=None, details=None):
        prev = await self.db.execute(select(AuditLog.entry_hash).order_by(AuditLog.created_at.desc()).limit(1))
        prev_hash = prev.scalar_one_or_none() or "genesis"
        entry_hash = hashlib.sha256(f"{action}|{agent_id}|{user_id}|{description}|{prev_hash}".encode()).hexdigest()
        self.db.add(AuditLog(action=action, user_id=user_id, agent_id=agent_id, description=description, details=details or {}, previous_hash=prev_hash, entry_hash=entry_hash))

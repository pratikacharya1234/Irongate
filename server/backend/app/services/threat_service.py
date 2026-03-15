"""IronGate -- Threat Detection Service.

Combines the rule-based threat detection engine with persistence, trust score
management, auto-banning, and real-time event publishing.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.redis import cache_service, pubsub_service
from app.models.models import (
    Agent, AgentStatus, Ban, BanScope, Severity, ThreatEvent, ThreatType,
)
from app.schemas.schemas import ThreatReport
from app.services.threat_detection_engine import (
    AgentBehaviorProfile, ThreatSignal, analyze_request,
)

settings = get_settings()
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3}


class ThreatDetectionService:
    def __init__(self, db: AsyncSession):
        self.db = db

    # ------------------------------------------------------------------
    # Active scanning: run the detection engine on raw request data
    # ------------------------------------------------------------------

    async def scan_request(
        self,
        agent_id: Optional[UUID] = None,
        agent_fingerprint: Optional[str] = None,
        content: str = "",
        target_url: str = "",
        target_endpoint: str = "",
        request_headers: Optional[dict] = None,
        request_size_bytes: int = 0,
        ip_address: str = "",
        computed_fingerprint: str = "",
        request_method: str = "",
    ) -> list[ThreatEvent]:
        """Run the full detection engine against a request and persist any findings.

        Returns a list of ThreatEvent objects created from detected signals.
        """
        agent = await self._resolve_agent(agent_id, agent_fingerprint)
        if not agent:
            return []

        profile = self._build_behavior_profile(agent)

        # Count recent requests for rate-based detectors
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        minute_ago = now - timedelta(minutes=1)
        req_hour = agent.total_requests  # approximation from stored total
        req_minute = 0

        # Use cached request counts if available
        cached_counts = await cache_service.get(f"agent_req_counts:{agent.id}")
        if cached_counts:
            req_hour = cached_counts.get("hour", req_hour)
            req_minute = cached_counts.get("minute", req_minute)

        signals = analyze_request(
            content=content,
            target_url=target_url,
            target_endpoint=target_endpoint,
            request_headers=request_headers,
            request_size_bytes=request_size_bytes,
            ip_address=ip_address,
            agent_fingerprint=agent_fingerprint or agent.fingerprint,
            computed_fingerprint=computed_fingerprint,
            agent_status=agent.status.value if agent.status else "pending",
            agent_profile=profile,
            current_request_count_hour=req_hour,
            current_request_count_minute=req_minute,
            metadata=None,
        )

        events = []
        for signal in signals:
            event = await self._persist_signal(agent, signal, ip_address, target_endpoint, request_method)
            events.append(event)

        return events

    async def _persist_signal(
        self,
        agent: Agent,
        signal: ThreatSignal,
        source_ip: str = "",
        target_endpoint: str = "",
        request_method: str = "",
    ) -> ThreatEvent:
        """Convert a ThreatSignal into a persisted ThreatEvent with all side effects."""
        sev = Severity(signal.severity)
        should_block = self._should_auto_block(sev, signal.confidence, agent.trust_score)

        event = ThreatEvent(
            agent_id=agent.id,
            threat_type=ThreatType(signal.threat_type),
            severity=sev,
            confidence=signal.confidence,
            description=signal.description,
            source_ip=source_ip,
            target_endpoint=target_endpoint,
            request_method=request_method,
            matched_signatures=signal.matched_patterns,
            raw_evidence=signal.evidence,
            detection_method="engine_scan",
            was_blocked=should_block,
            auto_response="blocked" if should_block else "flagged",
        )
        self.db.add(event)
        await self.db.flush()

        await self._apply_trust_penalty(agent, signal.severity, signal.threat_type)
        await self._check_auto_ban(agent)

        await pubsub_service.publish("threats", {
            "event": "threat_detected",
            "threat_id": str(event.id),
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "threat_type": signal.threat_type,
            "severity": signal.severity,
            "confidence": signal.confidence,
            "was_blocked": should_block,
            "detection_method": "engine_scan",
            "matched_patterns": signal.matched_patterns[:10],
        })
        await cache_service.invalidate_pattern("threats:*")
        await cache_service.invalidate_pattern("dashboard:*")
        return event

    def _build_behavior_profile(self, agent: Agent) -> AgentBehaviorProfile:
        """Build a behavior profile from the agent's stored attributes."""
        return AgentBehaviorProfile(
            avg_requests_per_hour=agent.avg_requests_per_hour or 0,
            max_requests_per_hour=agent.max_requests_per_hour or 0,
            typical_endpoints=agent.typical_endpoints or [],
            typical_request_sizes=[],
            ip_addresses=agent.ip_addresses or [],
            usual_active_hours=[],
            total_requests=agent.total_requests or 0,
        )

    # ------------------------------------------------------------------
    # External report ingestion (existing API)
    # ------------------------------------------------------------------

    async def analyze_and_report(self, data: ThreatReport, detection_method="api_report") -> ThreatEvent:
        """Accept an externally submitted threat report, validate it, and persist."""
        agent = await self._resolve_agent(data.agent_id, data.agent_fingerprint)
        if not agent:
            raise ValueError("Agent not found")

        # Run the detection engine on the report description + evidence for
        # additional signal enrichment beyond what the reporter claims
        enrichment_content = data.description
        evidence_text = " ".join(str(v) for v in data.evidence.values()) if data.evidence else ""
        enrichment_content = f"{enrichment_content} {evidence_text}".strip()

        engine_signals = analyze_request(
            content=enrichment_content,
            target_endpoint=data.target_endpoint or "",
            ip_address=data.source_ip or "",
        )

        # Use the reporter's claimed severity and type, but adjust confidence
        # upward if the engine independently confirms the threat type
        adjusted_confidence = data.confidence
        matched_sigs = []
        for sig in engine_signals:
            if sig.threat_type == data.threat_type:
                # Engine confirms the reported threat type -- boost confidence
                adjusted_confidence = min(
                    0.99,
                    1.0 - (1.0 - data.confidence) * (1.0 - sig.confidence),
                )
                matched_sigs.extend(sig.matched_patterns)

        sev = Severity(data.severity)
        should_block = self._should_auto_block(sev, adjusted_confidence, agent.trust_score)

        event = ThreatEvent(
            agent_id=agent.id,
            threat_type=ThreatType(data.threat_type),
            severity=sev,
            confidence=adjusted_confidence,
            description=data.description,
            source_ip=data.source_ip,
            target_endpoint=data.target_endpoint,
            request_method=data.request_method,
            matched_signatures=matched_sigs,
            raw_evidence=data.evidence,
            detection_method=detection_method,
            was_blocked=should_block,
            auto_response="blocked" if should_block else "flagged",
        )
        self.db.add(event)
        await self.db.flush()

        await self._apply_trust_penalty(agent, data.severity, data.threat_type)
        await self._check_auto_ban(agent)

        await pubsub_service.publish("threats", {
            "event": "threat_detected",
            "threat_id": str(event.id),
            "agent_id": str(agent.id),
            "agent_name": agent.name,
            "threat_type": data.threat_type,
            "severity": data.severity,
            "confidence": adjusted_confidence,
            "was_blocked": should_block,
            "detection_method": detection_method,
        })
        await cache_service.invalidate_pattern("threats:*")
        await cache_service.invalidate_pattern("dashboard:*")
        return event

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    async def get_threat(self, threat_id: UUID):
        r = await self.db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
        return r.scalar_one_or_none()

    async def list_threats(
        self,
        agent_id=None, severity=None, threat_type=None,
        blocked_only=False, unresolved_only=False,
        hours=24, page=1, page_size=50,
    ):
        query = select(ThreatEvent)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        conds = [ThreatEvent.detected_at >= since]
        if agent_id:
            conds.append(ThreatEvent.agent_id == agent_id)
        if severity:
            conds.append(ThreatEvent.severity == Severity(severity))
        if threat_type:
            conds.append(ThreatEvent.threat_type == ThreatType(threat_type))
        if blocked_only:
            conds.append(ThreatEvent.was_blocked == True)
        if unresolved_only:
            conds.append(ThreatEvent.resolved == False)
        query = query.where(and_(*conds))
        total = (await self.db.execute(
            select(func.count()).select_from(query.subquery())
        )).scalar() or 0
        query = query.order_by(ThreatEvent.detected_at.desc()).offset(
            (page - 1) * page_size
        ).limit(page_size)
        return list((await self.db.execute(query)).scalars().all()), total

    async def resolve_threat(self, threat_id: UUID, resolved_by: UUID, notes: str):
        r = await self.db.execute(select(ThreatEvent).where(ThreatEvent.id == threat_id))
        event = r.scalar_one_or_none()
        if not event:
            return None
        event.resolved = True
        event.resolved_by = resolved_by
        event.resolved_at = datetime.now(timezone.utc)
        event.resolution_notes = notes
        await self.db.flush()
        await cache_service.invalidate_pattern("threats:*")
        return event

    async def get_threat_stats(self, hours=24):
        cached = await cache_service.get(f"dashboard:threat_stats:{hours}")
        if cached:
            return cached
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        r = await self.db.execute(
            select(
                func.count(ThreatEvent.id).label("total"),
                func.count(ThreatEvent.id).filter(
                    ThreatEvent.was_blocked == True
                ).label("blocked"),
                func.count(ThreatEvent.id).filter(
                    ThreatEvent.severity == Severity.CRITICAL
                ).label("critical"),
            ).where(ThreatEvent.detected_at >= since)
        )
        row = r.one()
        dist = await self.db.execute(
            select(
                ThreatEvent.threat_type,
                func.count(ThreatEvent.id).label("count"),
            ).where(
                ThreatEvent.detected_at >= since
            ).group_by(ThreatEvent.threat_type).order_by(
                func.count(ThreatEvent.id).desc()
            )
        )
        stats = {
            "total": row.total,
            "blocked": row.blocked,
            "critical": row.critical,
            "block_rate": round(row.blocked / max(row.total, 1) * 100, 1),
            "distribution": [
                {"threat_type": str(r.threat_type), "count": r.count}
                for r in dist.all()
            ],
        }
        await cache_service.set(f"dashboard:threat_stats:{hours}", stats, ttl=30)
        return stats

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _resolve_agent(
        self, agent_id: Optional[UUID] = None, fingerprint: Optional[str] = None,
    ) -> Optional[Agent]:
        """Look up an agent by ID or fingerprint."""
        if agent_id:
            r = await self.db.execute(select(Agent).where(Agent.id == agent_id))
            return r.scalar_one_or_none()
        if fingerprint:
            r = await self.db.execute(select(Agent).where(Agent.fingerprint == fingerprint))
            return r.scalar_one_or_none()
        return None

    async def _apply_trust_penalty(self, agent: Agent, severity: str, threat_type: str):
        """Apply trust score penalty and record in history."""
        penalty = -SEVERITY_WEIGHTS.get(severity, 5)
        agent.trust_score = max(0, min(100, agent.trust_score + penalty))
        history = agent.trust_score_history or []
        history.append({
            "score": agent.trust_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": f"Threat: {threat_type}",
            "delta": penalty,
        })
        agent.trust_score_history = history[-100:]

    def _should_auto_block(self, severity, confidence, trust_score):
        if confidence >= settings.THREAT_AUTO_BAN_THRESHOLD:
            return True
        if severity == Severity.CRITICAL and confidence >= 0.8:
            return True
        if severity == Severity.HIGH and trust_score < 30:
            return True
        if trust_score < 10:
            return True
        return (
            confidence >= settings.THREAT_CONFIDENCE_THRESHOLD
            and severity in (Severity.CRITICAL, Severity.HIGH)
        )

    async def _check_auto_ban(self, agent):
        since = datetime.now(timezone.utc) - timedelta(
            hours=settings.ANOMALY_DETECTION_WINDOW_HOURS
        )
        count = (await self.db.execute(
            select(func.count(ThreatEvent.id)).where(and_(
                ThreatEvent.agent_id == agent.id,
                ThreatEvent.detected_at >= since,
                ThreatEvent.severity.in_([Severity.CRITICAL, Severity.HIGH]),
            ))
        )).scalar() or 0
        if count >= settings.THREAT_MAX_VIOLATIONS_BEFORE_BAN:
            agent.status = AgentStatus.BANNED
            agent.trust_score = 0
            agent.banned_at = datetime.now(timezone.utc)
            self.db.add(Ban(
                agent_id=agent.id,
                reason=f"Auto-banned: {count} critical/high violations in {settings.ANOMALY_DETECTION_WINDOW_HOURS}h",
                scope=BanScope.GLOBAL,
                is_permanent=False,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=72),
                propagation_status="pending",
            ))
            await pubsub_service.publish("bans", {
                "event": "auto_ban",
                "agent_id": str(agent.id),
                "agent_name": agent.name,
                "violations": count,
            })

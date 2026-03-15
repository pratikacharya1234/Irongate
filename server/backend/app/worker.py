"""IronGate -- Celery Worker.

Background task processing for ban propagation, trust score decay,
threat cleanup, and trust network intelligence exchange.
"""
import asyncio
import json
import hashlib
from datetime import datetime, timedelta, timezone

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "irongate",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.worker.propagate_ban_task": {"queue": "bans"},
        "app.worker.analyze_threat_task": {"queue": "threats"},
    },
    beat_schedule={
        "check-expired-bans": {
            "task": "app.worker.check_expired_bans_task",
            "schedule": crontab(minute="*/5"),
        },
        "decay-trust-scores": {
            "task": "app.worker.decay_trust_scores_task",
            "schedule": crontab(hour="*/1"),
        },
        "cleanup-old-threats": {
            "task": "app.worker.cleanup_old_threats_task",
            "schedule": crontab(hour=3, minute=0),
        },
        "sync-trust-network": {
            "task": "app.worker.sync_trust_network_task",
            "schedule": crontab(minute="*/10"),
        },
    },
)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task context."""
    return asyncio.run(coro)


@celery_app.task(name="app.worker.propagate_ban_task", bind=True, max_retries=3)
def propagate_ban_task(self, ban_id: str):
    """Propagate a ban to all trust network peers with retry."""
    from uuid import UUID
    from app.core.database import async_session_factory
    from app.services.ban_service import BanService

    async def _run():
        async with async_session_factory() as db:
            service = BanService(db)
            result = await service.propagate_ban(UUID(ban_id))
            await db.commit()
            return result

    try:
        return _run_async(_run())
    except Exception as exc:
        countdown = settings.BAN_PROPAGATION_RETRY_DELAY * (self.request.retries + 1)
        self.retry(exc=exc, countdown=countdown)


@celery_app.task(name="app.worker.check_expired_bans_task")
def check_expired_bans_task():
    """Deactivate expired bans."""
    from app.core.database import async_session_factory
    from app.services.ban_service import BanService

    async def _run():
        async with async_session_factory() as db:
            service = BanService(db)
            count = await service.check_expired_bans()
            await db.commit()
            return {"expired_bans_deactivated": count}

    return _run_async(_run())


@celery_app.task(name="app.worker.decay_trust_scores_task")
def decay_trust_scores_task():
    """Apply exponential trust score decay for inactive agents.

    Uses the TRUST_SCORE_DECAY_RATE from config. For each agent inactive
    longer than 7 days, the decay formula is:

        new_score = floor(score * (1 - rate) ^ days_inactive_beyond_threshold)

    Where rate = TRUST_SCORE_DECAY_RATE (default 0.01).
    This means an agent inactive for 30 days beyond the threshold would lose
    roughly 20% of their score at rate=0.01.

    Agents that are banned or already at minimum score are skipped.
    """
    import math
    from sqlalchemy import select
    from app.core.database import async_session_factory
    from app.models.models import Agent, AgentStatus

    decay_rate = settings.TRUST_SCORE_DECAY_RATE
    inactivity_threshold_days = 7

    async def _run():
        async with async_session_factory() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(days=inactivity_threshold_days)
            result = await db.execute(
                select(Agent).where(
                    Agent.last_active_at < cutoff,
                    Agent.status != AgentStatus.BANNED,
                    Agent.trust_score > 10,
                )
            )
            agents = list(result.scalars().all())
            decayed_count = 0

            for agent in agents:
                days_inactive = (datetime.now(timezone.utc) - agent.last_active_at).days
                days_beyond_threshold = max(0, days_inactive - inactivity_threshold_days)

                if days_beyond_threshold <= 0:
                    continue

                # Exponential decay: score * (1 - rate) ^ days
                decay_factor = (1.0 - decay_rate) ** days_beyond_threshold
                new_score = max(10, math.floor(agent.trust_score * decay_factor))

                if new_score < agent.trust_score:
                    delta = new_score - agent.trust_score
                    agent.trust_score = new_score

                    history = agent.trust_score_history or []
                    history.append({
                        "score": new_score,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "reason": f"Inactivity decay ({days_inactive}d inactive)",
                        "delta": delta,
                    })
                    agent.trust_score_history = history[-100:]
                    decayed_count += 1

            await db.commit()
            return {"agents_decayed": decayed_count, "total_checked": len(agents)}

    return _run_async(_run())


@celery_app.task(name="app.worker.cleanup_old_threats_task")
def cleanup_old_threats_task():
    """Archive resolved threat events older than 90 days."""
    from sqlalchemy import delete
    from app.core.database import async_session_factory
    from app.models.models import ThreatEvent

    async def _run():
        async with async_session_factory() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            result = await db.execute(
                delete(ThreatEvent).where(
                    ThreatEvent.detected_at < cutoff,
                    ThreatEvent.resolved == True,
                )
            )
            await db.commit()
            return {"deleted": result.rowcount}

    return _run_async(_run())


@celery_app.task(name="app.worker.sync_trust_network_task")
def sync_trust_network_task():
    """Exchange threat intelligence with trust network peers.

    For each active peer:
    1. Send our recent unshared threat summaries (agent fingerprints + threat types)
    2. Receive their recent threat summaries
    3. Cross-reference received intel against our local agent registry
    4. Update peer reliability scores based on response quality

    Threat intel payloads contain only fingerprints and threat metadata,
    never raw evidence or PII.
    """
    import httpx
    from sqlalchemy import and_, select, func
    from app.core.database import async_session_factory
    from app.core.security import sign_webhook_payload
    from app.models.models import (
        Agent, AgentStatus, ThreatEvent, TrustNetworkPeer, Severity,
    )

    async def _run():
        async with async_session_factory() as db:
            # Fetch active peers
            result = await db.execute(
                select(TrustNetworkPeer).where(TrustNetworkPeer.is_active == True)
            )
            peers = list(result.scalars().all())

            if not peers:
                return {"peers_synced": 0, "total_peers": 0, "intel_shared": 0}

            # Gather recent threat intel to share (last 24h, high+ severity)
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            threat_result = await db.execute(
                select(
                    ThreatEvent.threat_type,
                    ThreatEvent.severity,
                    ThreatEvent.confidence,
                    Agent.fingerprint,
                    Agent.name,
                ).join(Agent, ThreatEvent.agent_id == Agent.id).where(
                    ThreatEvent.detected_at >= since,
                    ThreatEvent.severity.in_([Severity.CRITICAL, Severity.HIGH]),
                ).order_by(ThreatEvent.detected_at.desc()).limit(100)
            )
            recent_threats = threat_result.all()

            intel_items = []
            for row in recent_threats:
                intel_items.append({
                    "agent_fingerprint": row.fingerprint,
                    "agent_name": row.name,
                    "threat_type": str(row.threat_type.value) if hasattr(row.threat_type, "value") else str(row.threat_type),
                    "severity": str(row.severity.value) if hasattr(row.severity, "value") else str(row.severity),
                    "confidence": row.confidence,
                })

            payload = {
                "event_type": "intel_sync",
                "source_node_id": settings.TRUST_NETWORK_NODE_ID,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "intel_items": intel_items,
                "item_count": len(intel_items),
            }
            payload_bytes = json.dumps(payload, sort_keys=True).encode()
            signature = sign_webhook_payload(payload_bytes)

            synced = 0
            total_intel_received = 0

            async with httpx.AsyncClient(timeout=settings.BAN_PROPAGATION_WEBHOOK_TIMEOUT) as client:
                for peer in peers:
                    try:
                        resp = await client.post(
                            f"{peer.endpoint_url}/api/v1/trust/receive-intel",
                            json=payload,
                            headers={
                                "X-IronGate-Signature": signature,
                                "X-IronGate-Node": settings.TRUST_NETWORK_NODE_ID,
                            },
                        )
                        if resp.status_code in (200, 201, 202):
                            synced += 1
                            peer.intel_shared += len(intel_items)
                            peer.last_sync_at = datetime.now(timezone.utc)

                            # Process received intel from the response
                            try:
                                resp_data = resp.json()
                                received_items = resp_data.get("intel_items", [])
                                for item in received_items:
                                    fp = item.get("agent_fingerprint")
                                    if not fp:
                                        continue
                                    # Check if this fingerprint matches any of our agents
                                    agent_result = await db.execute(
                                        select(Agent).where(Agent.fingerprint == fp)
                                    )
                                    local_agent = agent_result.scalar_one_or_none()
                                    if local_agent and local_agent.status != AgentStatus.BANNED:
                                        # Received external threat intel about one of our agents
                                        threat_severity = item.get("severity", "medium")
                                        peer_confidence = item.get("confidence", 0.5)

                                        # Apply a dampened trust penalty based on peer reliability
                                        dampen_factor = peer.reliability_score
                                        penalty_weight = {
                                            "critical": 15, "high": 8,
                                            "medium": 4, "low": 1,
                                        }.get(threat_severity, 3)
                                        penalty = -int(penalty_weight * dampen_factor * peer_confidence)

                                        if penalty < 0:
                                            local_agent.trust_score = max(
                                                0, min(100, local_agent.trust_score + penalty),
                                            )
                                            history = local_agent.trust_score_history or []
                                            history.append({
                                                "score": local_agent.trust_score,
                                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                                "reason": f"Peer intel from {peer.name}: {item.get('threat_type', 'unknown')}",
                                                "delta": penalty,
                                            })
                                            local_agent.trust_score_history = history[-100:]

                                    total_intel_received += 1
                                    peer.intel_received += 1
                            except (ValueError, KeyError):
                                pass

                            # Update peer reliability upward on success
                            peer.reliability_score = min(
                                1.0, peer.reliability_score + 0.01,
                            )
                        else:
                            # Non-success response degrades reliability
                            peer.reliability_score = max(
                                0, peer.reliability_score - 0.05,
                            )
                    except Exception:
                        # Connection failure degrades reliability
                        peer.reliability_score = max(
                            0, peer.reliability_score - 0.02,
                        )

            await db.commit()
            return {
                "peers_synced": synced,
                "total_peers": len(peers),
                "intel_shared": len(intel_items) * synced,
                "intel_received": total_intel_received,
            }

    return _run_async(_run())

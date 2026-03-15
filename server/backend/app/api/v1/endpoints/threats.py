"""IronGate -- Threat Endpoints."""
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, validate_api_key
from app.schemas.schemas import (
    PaginatedResponse, ThreatReport, ThreatResolve, ThreatResponse,
)
from app.services.threat_service import ThreatDetectionService

router = APIRouter(prefix="/threats", tags=["threats"])


class ScanRequest(BaseModel):
    """Request body for the active scan endpoint."""
    agent_id: Optional[UUID] = None
    agent_fingerprint: Optional[str] = None
    content: str = ""
    target_url: str = ""
    target_endpoint: str = ""
    request_headers: Optional[dict[str, str]] = None
    request_size_bytes: int = 0
    ip_address: str = ""
    computed_fingerprint: str = ""
    request_method: str = ""


class ScanResult(BaseModel):
    """Response from the active scan endpoint."""
    threats_detected: int
    events: list[ThreatResponse]


@router.post("/scan", response_model=ScanResult, status_code=200)
async def scan_request(
    data: ScanRequest,
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    """Actively scan a request payload through the threat detection engine.

    Runs all 10 detectors (prompt injection, data exfiltration, identity
    spoofing, privilege escalation, scraping, manipulation, DDoS, social
    engineering, model poisoning, supply chain) and returns any findings.
    """
    service = ThreatDetectionService(db)
    events = await service.scan_request(
        agent_id=data.agent_id,
        agent_fingerprint=data.agent_fingerprint,
        content=data.content,
        target_url=data.target_url,
        target_endpoint=data.target_endpoint,
        request_headers=data.request_headers,
        request_size_bytes=data.request_size_bytes,
        ip_address=data.ip_address,
        computed_fingerprint=data.computed_fingerprint,
        request_method=data.request_method,
    )
    return ScanResult(
        threats_detected=len(events),
        events=[ThreatResponse.model_validate(e) for e in events],
    )


@router.post("/report", response_model=ThreatResponse, status_code=201)
async def report_threat(
    data: ThreatReport,
    db: AsyncSession = Depends(get_db),
    api_key=Depends(validate_api_key),
):
    try:
        return await ThreatDetectionService(db).analyze_and_report(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=PaginatedResponse)
async def list_threats(
    agent_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    blocked_only: bool = False,
    unresolved_only: bool = False,
    hours: int = Query(24, ge=1, le=720),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    threats, total = await ThreatDetectionService(db).list_threats(
        agent_id=agent_id, severity=severity, threat_type=threat_type,
        blocked_only=blocked_only, unresolved_only=unresolved_only,
        hours=hours, page=page, page_size=page_size,
    )
    return PaginatedResponse(
        items=[ThreatResponse.model_validate(t) for t in threats],
        total=total, page=page, page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/stats/summary")
async def threat_stats(
    hours: int = Query(24, ge=1, le=720),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    return await ThreatDetectionService(db).get_threat_stats(hours)


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: UUID,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    event = await ThreatDetectionService(db).get_threat(threat_id)
    if not event:
        raise HTTPException(status_code=404, detail="Not found")
    return event


@router.post("/{threat_id}/resolve", response_model=ThreatResponse)
async def resolve_threat(
    threat_id: UUID,
    data: ThreatResolve,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    event = await ThreatDetectionService(db).resolve_threat(
        threat_id, user.id, data.resolution_notes,
    )
    if not event:
        raise HTTPException(status_code=404, detail="Not found")
    return event

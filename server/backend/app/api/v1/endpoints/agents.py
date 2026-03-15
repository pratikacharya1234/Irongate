"""IronGate — Agent Endpoints."""
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.security import generate_agent_fingerprint, get_current_admin, get_current_user, validate_api_key
from app.schemas.schemas import AgentDetailResponse, AgentRegister, AgentResponse, AgentUpdate, AgentVerify, PaginatedResponse
from app.services.agent_service import AgentService

router = APIRouter(prefix="/agents", tags=["agents"])

@router.post("/register", response_model=AgentResponse, status_code=201)
async def register_agent(data: AgentRegister, request: Request, db: AsyncSession = Depends(get_db), api_key=Depends(validate_api_key)):
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    fingerprint = generate_agent_fingerprint(
        user_agent=ua,
        ip_address=ip,
        headers=dict(request.headers),
        declared_name=data.name,
        sdk_version=data.sdk_version or "",
    )
    try: return await AgentService(db).register_agent(data=data, fingerprint=fingerprint, ip_address=ip, user_agent=ua, country=request.headers.get("cf-ipcountry"))
    except ValueError as e: raise HTTPException(status_code=409, detail=str(e))

@router.get("", response_model=PaginatedResponse)
async def list_agents(status_filter: Optional[str] = Query(None, alias="status"), search: Optional[str] = Query(None, max_length=200), page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), sort_by: str = Query("last_active_at"), sort_order: str = Query("desc"), db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    agents, total = await AgentService(db).list_agents(status=status_filter, page=page, page_size=page_size, sort_by=sort_by, sort_order=sort_order, search=search)
    return PaginatedResponse(items=[AgentResponse.model_validate(a) for a in agents], total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size)

@router.get("/{agent_id}", response_model=AgentDetailResponse)
async def get_agent(agent_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    agent = await AgentService(db).get_agent(agent_id)
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(agent_id: UUID, data: AgentUpdate, db: AsyncSession = Depends(get_db), user=Depends(get_current_admin)):
    agent = await AgentService(db).update_agent(agent_id, data)
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.post("/{agent_id}/verify", response_model=AgentResponse)
async def verify_agent(agent_id: UUID, data: AgentVerify, db: AsyncSession = Depends(get_db), user=Depends(get_current_admin)):
    agent = await AgentService(db).change_status(agent_id=agent_id, new_status=data.status, reason=data.reason, changed_by=user.id)
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return agent

@router.post("/{agent_id}/heartbeat", status_code=204)
async def agent_heartbeat(agent_id: UUID, request: Request, db: AsyncSession = Depends(get_db), api_key=Depends(validate_api_key)):
    await AgentService(db).record_activity(agent_id, request.headers.get("x-original-uri", "/"), request.client.host if request.client else "unknown")

@router.get("/fingerprint/{fingerprint}", response_model=AgentResponse)
async def lookup_by_fingerprint(fingerprint: str, db: AsyncSession = Depends(get_db), api_key=Depends(validate_api_key)):
    agent = await AgentService(db).get_agent_by_fingerprint(fingerprint)
    if not agent: raise HTTPException(status_code=404, detail="Agent not found")
    return agent

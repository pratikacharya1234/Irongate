"""IronGate — Ban Endpoints."""
from typing import Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.core.security import get_current_admin, get_current_user
from app.models.models import Agent, Ban
from app.schemas.schemas import BanCreate, BanResponse, BanRevoke, PaginatedResponse
from app.services.ban_service import BanService

router = APIRouter(prefix="/bans", tags=["bans"])

@router.post("", response_model=BanResponse, status_code=201)
async def create_ban(data: BanCreate, db: AsyncSession = Depends(get_db), user=Depends(get_current_admin)):
    try: return await BanService(db).create_ban(data, created_by=user.id)
    except ValueError as e: raise HTTPException(status_code=400, detail=str(e))

@router.get("", response_model=PaginatedResponse)
async def list_bans(agent_id: Optional[UUID] = None, active_only: bool = True, scope: Optional[str] = None, page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200), db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    bans, total = await BanService(db).list_bans(agent_id=agent_id, active_only=active_only, scope=scope, page=page, page_size=page_size)
    return PaginatedResponse(items=[BanResponse.model_validate(b) for b in bans], total=total, page=page, page_size=page_size, total_pages=(total + page_size - 1) // page_size)

@router.post("/{ban_id}/propagate")
async def propagate_ban(ban_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(get_current_admin)):
    try: return await BanService(db).propagate_ban(ban_id)
    except ValueError as e: raise HTTPException(status_code=404, detail=str(e))

@router.post("/{ban_id}/revoke", response_model=BanResponse)
async def revoke_ban(ban_id: UUID, data: BanRevoke, db: AsyncSession = Depends(get_db), user=Depends(get_current_admin)):
    ban = await BanService(db).revoke_ban(ban_id, user.id, data.reason)
    if not ban: raise HTTPException(status_code=404, detail="Not found or inactive")
    return ban

@router.get("/check/{fingerprint}")
async def check_ban_status(fingerprint: str, db: AsyncSession = Depends(get_db)):
    """PUBLIC endpoint — any platform can check if an agent is banned."""
    agent = (await db.execute(select(Agent).where(Agent.fingerprint == fingerprint))).scalar_one_or_none()
    if not agent: return {"fingerprint": fingerprint, "found": False, "banned": False}
    ban = (await db.execute(select(Ban).where(and_(Ban.agent_id == agent.id, Ban.is_active == True)).order_by(Ban.created_at.desc()).limit(1))).scalar_one_or_none()
    return {"fingerprint": fingerprint, "found": True, "banned": ban is not None, "agent_status": agent.status.value, "trust_score": agent.trust_score, "ban_scope": ban.scope.value if ban else None, "ban_reason": ban.reason if ban else None, "ban_permanent": ban.is_permanent if ban else None, "ban_expires_at": ban.expires_at.isoformat() if ban and ban.expires_at else None}

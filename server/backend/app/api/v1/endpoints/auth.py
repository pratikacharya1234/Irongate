"""IronGate — Auth Endpoints."""
from datetime import datetime, timedelta, timezone
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_access_token, create_refresh_token, decode_token, generate_api_key, get_current_user, hash_password, verify_password
from app.models.models import APIKey, User, UserRole
from app.schemas.schemas import APIKeyCreate, APIKeyCreated, APIKeyResponse, LoginRequest, RefreshRequest, TokenResponse, UserCreate, UserResponse

settings = get_settings()
router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse, status_code=201)
async def register_user(data: UserCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where((User.email == data.email) | (User.username == data.username)))
    if existing.scalar_one_or_none(): raise HTTPException(status_code=409, detail="Email or username taken")
    user = User(email=data.email, username=data.username, hashed_password=hash_password(data.password), full_name=data.full_name, role=UserRole.VIEWER)
    db.add(user); await db.flush(); return user

@router.post("/login", response_model=TokenResponse)
async def login(data: LoginRequest, db: AsyncSession = Depends(get_db)):
    user = (await db.execute(select(User).where(User.email == data.email))).scalar_one_or_none()
    if not user or not verify_password(data.password, user.hashed_password): raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active: raise HTTPException(status_code=403, detail="Account deactivated")
    user.last_login_at = datetime.now(timezone.utc)
    return TokenResponse(access_token=create_access_token(str(user.id), {"role": user.role.value}), refresh_token=create_refresh_token(str(user.id)), expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(data: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(data.refresh_token)
    if payload.get("type") != "refresh": raise HTTPException(status_code=401, detail="Invalid token type")
    user = (await db.execute(select(User).where(User.id == payload["sub"], User.is_active == True))).scalar_one_or_none()
    if not user: raise HTTPException(status_code=401, detail="User not found")
    return TokenResponse(access_token=create_access_token(str(user.id), {"role": user.role.value}), refresh_token=create_refresh_token(str(user.id)), expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)

@router.get("/me", response_model=UserResponse)
async def get_me(user=Depends(get_current_user)): return user

@router.post("/api-keys", response_model=APIKeyCreated, status_code=201)
async def create_api_key(data: APIKeyCreate, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    raw_key, hashed_key = generate_api_key()
    expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_days) if data.expires_days else None
    key = APIKey(user_id=user.id, name=data.name, key_hash=hashed_key, key_prefix=raw_key[:10], scopes=data.scopes, rate_limit=data.rate_limit, expires_at=expires_at)
    db.add(key); await db.flush()
    resp = APIKeyCreated.model_validate(key); resp.raw_key = raw_key; return resp

@router.get("/api-keys")
async def list_api_keys(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return [APIKeyResponse.model_validate(k) for k in (await db.execute(select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc()))).scalars().all()]

@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(key_id: UUID, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    key = (await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id))).scalar_one_or_none()
    if not key: raise HTTPException(status_code=404, detail="Not found")
    key.is_active = False

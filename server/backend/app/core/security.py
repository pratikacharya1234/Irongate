"""IronGate -- Authentication & Security."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db

settings = get_settings()
pwd_context = CryptContext(
    schemes=["bcrypt"], deprecated="auto",
    bcrypt__rounds=settings.BCRYPT_ROUNDS,
)
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, extra: dict[str, Any] | None = None) -> str:
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        ),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(subject: str) -> str:
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS,
        ),
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token, settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def generate_api_key() -> tuple[str, str]:
    raw = f"ig_{secrets.token_urlsafe(48)}"
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def sign_webhook_payload(payload: bytes) -> str:
    return hmac.new(
        settings.WEBHOOK_SECRET.encode(), payload, hashlib.sha256,
    ).hexdigest()


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign_webhook_payload(payload), signature)


def generate_agent_fingerprint(
    user_agent: str,
    ip_address: str,
    headers: dict[str, str],
    body_hash: str = "",
    declared_name: str = "",
    sdk_version: str = "",
) -> str:
    """Generate a stable fingerprint for an AI agent.

    Uses a multi-signal approach that combines:
    - Declared identity (name, SDK version) -- things the agent controls
    - Network identity (IP, TLS characteristics) -- things the network controls
    - Behavioral identity (User-Agent, Accept headers) -- things the runtime controls

    The fingerprint is a SHA-256 of all components, prefixed with FP- for readability.
    Unlike browser fingerprinting, this is designed to be reproducible by honest agents
    and costly to spoof for malicious ones (requires matching all signals simultaneously).
    """
    components = [
        # Declared identity signals
        declared_name,
        sdk_version,
        user_agent,

        # Network signals
        ip_address,

        # Header-derived signals (ordered, normalized)
        headers.get("accept", ""),
        headers.get("accept-encoding", ""),
        headers.get("accept-language", ""),
        headers.get("content-type", ""),
        headers.get("connection", ""),

        # TLS / proxy signals
        headers.get("x-forwarded-proto", ""),
        headers.get("sec-ch-ua", ""),
        headers.get("sec-ch-ua-platform", ""),

        # Body content hash (if provided)
        body_hash,
    ]

    # Normalize: lowercase, strip whitespace, sort for determinism
    normalized = "|".join(c.strip().lower() for c in components)
    raw_hash = hashlib.sha256(normalized.encode()).hexdigest()
    return f"FP-{raw_hash[:32].upper()}"


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
):
    if not credentials:
        raise HTTPException(
            status_code=401, detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    from app.models.models import User
    result = await db.execute(
        select(User).where(User.id == payload["sub"], User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


async def get_current_admin(user=Depends(get_current_user)):
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def validate_api_key(
    request: Request, db: AsyncSession = Depends(get_db),
):
    api_key = request.headers.get(settings.API_KEY_HEADER)
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail=f"Missing {settings.API_KEY_HEADER} header",
        )
    from app.models.models import APIKey
    result = await db.execute(
        select(APIKey).where(
            APIKey.key_hash == hash_api_key(api_key),
            APIKey.is_active == True,
        )
    )
    key_record = result.scalar_one_or_none()
    if not key_record:
        raise HTTPException(status_code=401, detail="Invalid API key")
    key_record.last_used_at = datetime.now(timezone.utc)
    key_record.request_count += 1
    return key_record

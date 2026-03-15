"""IronGate — Main Application."""
import time
from contextlib import asynccontextmanager
import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from app.core.config import get_settings
from app.core.database import engine
from app.core.redis import redis_client
from app.middleware.security import RequestLoggingMiddleware, SecurityHeadersMiddleware, TrustedProxyMiddleware

settings = get_settings()
logger = structlog.get_logger()
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])
start_time = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("IronGate starting", version=settings.APP_VERSION, env=settings.APP_ENV)
    try:
        async with engine.begin() as conn: await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        logger.info("Database connected")
    except Exception as e: logger.error("DB failed", error=str(e))
    try:
        await redis_client.ping()
        logger.info("Redis connected")
    except Exception as e:
        logger.warning("Redis unavailable, running in degraded mode", error=str(e))
    yield
    logger.info("IronGate shutting down")
    await engine.dispose()
    try:
        await redis_client.close()
    except Exception:
        pass

app = FastAPI(title="IronGate API", description="Enterprise AI Agent Security Platform", version=settings.APP_VERSION, docs_url="/api/docs" if settings.APP_ENV != "production" else None, redoc_url="/api/redoc" if settings.APP_ENV != "production" else None, openapi_url="/api/openapi.json" if settings.APP_ENV != "production" else None, default_response_class=ORJSONResponse, lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"], expose_headers=["X-Request-ID", "X-Response-Time"])
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(TrustedProxyMiddleware)

from app.api.v1.endpoints import agents, auth, bans, threats, websocket
API = "/api/v1"
app.include_router(auth.router, prefix=API)
app.include_router(agents.router, prefix=API)
app.include_router(threats.router, prefix=API)
app.include_router(bans.router, prefix=API)
app.include_router(websocket.router, prefix=API)

@app.get("/api/v1/health", tags=["system"])
async def health_check():
    db_s = redis_s = "healthy"
    try:
        async with engine.begin() as conn: await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
    except: db_s = "unhealthy"
    try:
        await redis_client.ping()
    except Exception:
        redis_s = "unhealthy"
    return {"status": "healthy" if db_s == redis_s == "healthy" else "degraded", "version": settings.APP_VERSION, "database": db_s, "redis": redis_s, "uptime_seconds": round(time.time() - start_time, 1)}

@app.get("/", include_in_schema=False)
async def root(): return {"name": "IronGate API", "version": settings.APP_VERSION, "docs": "/api/docs"}

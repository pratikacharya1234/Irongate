"""IronGate — Security Middleware."""
import time, uuid
from typing import Callable
import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = structlog.get_logger()

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())[:8]; start = time.perf_counter()
        try:
            response = await call_next(request)
            ms = round((time.perf_counter() - start) * 1000, 2)
            response.headers["X-Request-ID"] = request_id; response.headers["X-Response-Time"] = f"{ms}ms"
            logger.info("request", status=response.status_code, ms=ms, path=request.url.path)
            return response
        except Exception as e:
            logger.error("request_failed", error=str(e)); raise

class TrustedProxyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        for h in ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"]:
            val = request.headers.get(h)
            if val: request.scope["client"] = (val.split(",")[0].strip(), request.scope.get("client", ("",0))[1]); break
        return await call_next(request)

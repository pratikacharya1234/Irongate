"""IronGate -- WebSocket Endpoint.

Authenticated real-time event feed. Clients must provide a valid JWT or API
key as a query parameter (token=...) when connecting. Unauthenticated
connections are rejected immediately.
"""
import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import JWTError, jwt
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import async_session_factory
from app.core.redis import pubsub_service

settings = get_settings()
router = APIRouter(tags=["websocket"])


async def _authenticate_websocket(websocket: WebSocket) -> bool:
    """Validate the token query parameter on a WebSocket connection.

    Accepts either a JWT access token or a hashed API key. Returns True
    if authentication succeeds, False otherwise.
    """
    token = websocket.query_params.get("token")
    if not token:
        return False

    # Try JWT first
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") != "access":
            return False
        user_id = payload.get("sub")
        if not user_id:
            return False
        return True
    except JWTError:
        pass

    # Fall back to API key verification
    from app.core.security import hash_api_key
    from app.models.models import APIKey
    key_hash = hash_api_key(token)
    try:
        async with async_session_factory() as db:
            result = await db.execute(
                select(APIKey).where(
                    APIKey.key_hash == key_hash,
                    APIKey.is_active == True,
                )
            )
            key_record = result.scalar_one_or_none()
            if key_record:
                return True
    except Exception:
        pass

    return False


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for c in self.active:
            try:
                await c.send_json(msg)
            except Exception:
                dead.append(c)
        for c in dead:
            if c in self.active:
                self.active.remove(c)


manager = ConnectionManager()


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """Authenticated WebSocket endpoint for real-time threat, ban, and agent events."""
    authenticated = await _authenticate_websocket(websocket)
    if not authenticated:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    pubsubs = []
    try:
        for ch in ["threats", "bans", "agents"]:
            pubsubs.append(await pubsub_service.subscribe(ch))
        while True:
            for ps in pubsubs:
                msg = await ps.get_message(
                    ignore_subscribe_messages=True, timeout=0.1,
                )
                if msg and msg.get("type") == "message":
                    try:
                        await websocket.send_json(json.loads(msg["data"]))
                    except Exception:
                        pass
            # Also check for incoming messages (ping/pong, close)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.05)
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                raise
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
    finally:
        for ps in pubsubs:
            try:
                await ps.unsubscribe()
                await ps.close()
            except Exception:
                pass

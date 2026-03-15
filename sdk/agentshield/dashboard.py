"""Local FastAPI dashboard for IronGate.

Run as module:
    python -m irongate.dashboard

This starts a server on http://localhost:9123 serving a minimal UI and
endpoints to view events and approve/block pending actions.

ALL endpoints require a bearer token that is generated at startup and
printed to the console. Remote binding (non-localhost) requires explicit
opt-in via IRONGATE_ALLOW_REMOTE=1 environment variable.

All dashboard actions (approve, block, policy changes) are audit-logged.
CSRF tokens are generated per-session and tied to the auth token.
"""
import os
import sys
import secrets
import time
import datetime
import hashlib
import json
from collections import defaultdict

from fastapi import (
    FastAPI, HTTPException, Body, Depends, Header, Request, Response,
)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, field_validator
import uvicorn
import jsonschema

from .startup_checks import run_startup_checks, StartupValidationError
from .storage import LocalStorage
from .policy import PolicyEngine


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'"
        )
        return response


# Per-session CSRF token storage: maps auth_token_hash -> csrf_token
_csrf_tokens: dict[str, str] = {}
_CSRF_TOKEN_MAX_SESSIONS = 1000


def _get_csrf_token_for_session(auth_token: str) -> str:
    """Get or create a CSRF token tied to the given auth session."""
    token_hash = hashlib.sha256(auth_token.encode()).hexdigest()[:16]
    if token_hash not in _csrf_tokens:
        # Evict oldest entries if over limit
        if len(_csrf_tokens) >= _CSRF_TOKEN_MAX_SESSIONS:
            oldest_key = next(iter(_csrf_tokens))
            del _csrf_tokens[oldest_key]
        _csrf_tokens[token_hash] = secrets.token_urlsafe(32)
    return _csrf_tokens[token_hash]


def _validate_csrf_token(
    request: Request,
    authorization: str = Header(None),
    x_csrf_token: str = Header(None, alias="X-CSRF-Token"),
):
    """Validate CSRF token for state-changing operations.

    The CSRF token must match the one issued for this auth session.
    """
    if not authorization or not x_csrf_token:
        raise HTTPException(status_code=403, detail="Missing CSRF token")

    parts = authorization.split(" ", 1)
    auth_token = parts[1] if len(parts) == 2 else authorization
    token_hash = hashlib.sha256(auth_token.encode()).hexdigest()[:16]

    expected = _csrf_tokens.get(token_hash)
    if not expected or x_csrf_token != expected:
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


app = FastAPI(title="IronGate Dashboard")
app.add_middleware(SecurityHeadersMiddleware)

storage = LocalStorage()
_policy_engine = None
_dashboard_token = None

# Rate limiting
_rate_limits: dict[str, list] = defaultdict(list)
_RATE_LIMIT_REQUESTS = 100
_RATE_LIMIT_WINDOW = 60


def _check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    requests = _rate_limits[client_ip]
    requests[:] = [t for t in requests if now - t < _RATE_LIMIT_WINDOW]
    if len(requests) >= _RATE_LIMIT_REQUESTS:
        return False
    requests.append(now)
    return True


def _validate_policy_json(policy: dict) -> bool:
    if not isinstance(policy, dict):
        return False
    if "rules" not in policy or not isinstance(policy["rules"], list):
        return False
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            return False
        if "decision" not in rule:
            return False
        if rule["decision"] not in ("allow", "review", "block"):
            return False
    return True


def init_dashboard(policy_engine: PolicyEngine = None, token: str = None):
    """Initialize dashboard with shared policy engine and auth token.

    Returns the auth token (generated or provided).
    """
    try:
        policy_file = os.environ.get("IRONGATE_POLICY_FILE")
        run_startup_checks(
            policy_file=policy_file,
            remote_dashboard=True,
            strict=True,
        )
    except StartupValidationError as e:
        print(f"[IronGate] DASHBOARD STARTUP CHECK FAILED:\n{e}", file=sys.stderr)
        sys.exit(1)

    global _policy_engine, _dashboard_token
    _policy_engine = policy_engine
    _dashboard_token = token or secrets.token_urlsafe(32)
    return _dashboard_token


def _get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine(storage=storage)
    return _policy_engine


def _require_auth(request: Request, authorization: str = Header(None)):
    """Dependency that requires a valid bearer token on ALL endpoints."""
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    if _dashboard_token is None:
        init_dashboard()
        print(
            f"[IronGate] WARNING: Dashboard token was not pre-configured.",
            file=sys.stderr,
        )
        print(f"[IronGate] Dashboard token: {_dashboard_token}", file=sys.stderr)

    if not authorization:
        raise HTTPException(
            status_code=401, detail="Authorization header required",
        )

    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=401, detail="Authorization must be: Bearer <token>",
        )

    if parts[1] != _dashboard_token:
        raise HTTPException(status_code=403, detail="Invalid dashboard token")


def _audit_log_dashboard_action(action_type: str, details: dict):
    action = {
        "type": "dashboard",
        "subtype": action_type,
        "agent": "dashboard_user",
        "timestamp": time.time(),
    }
    action.update(details)
    try:
        storage.log_event(action, decision="allow", reason=f"dashboard_{action_type}")
    except Exception:
        pass


static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")


def _ts_to_iso(ts):
    try:
        return datetime.datetime.fromtimestamp(float(ts)).isoformat()
    except Exception:
        return ts


@app.get("/csrf-token")
def get_csrf_token(
    _auth=Depends(_require_auth),
    authorization: str = Header(None),
):
    """Get a CSRF token for the current session. Must be included in
    X-CSRF-Token header for all state-changing requests."""
    parts = authorization.split(" ", 1)
    auth_token = parts[1] if len(parts) == 2 else authorization
    token = _get_csrf_token_for_session(auth_token)
    return {"csrf_token": token}


@app.get("/events")
def get_events(limit: int = 100, _auth=Depends(_require_auth)):
    limit = min(limit, 10000)
    rows = storage.recent(limit)
    for r in rows:
        r["timestamp"] = _ts_to_iso(r["timestamp"])
        if "matched_rule" not in r or r["matched_rule"] is None:
            r["matched_rule"] = None
    return rows


@app.get("/approvals")
def get_approvals(limit: int = 100, _auth=Depends(_require_auth)):
    limit = min(limit, 10000)
    rows = storage.pending(limit)
    for r in rows:
        r["timestamp"] = _ts_to_iso(r["timestamp"])
    return rows


class DecisionBody(BaseModel):
    event_id: int
    decision: str

    @field_validator("event_id")
    @classmethod
    def event_id_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("event_id must be positive")
        return v

    @field_validator("decision")
    @classmethod
    def decision_must_be_valid(cls, v):
        if v not in ("allow", "block"):
            raise ValueError("decision must be allow or block")
        return v


class PolicyTestBody(BaseModel):
    type: str
    tool_name: str | None = None
    agent: str | None = None

    @field_validator("type")
    @classmethod
    def type_must_be_valid(cls, v):
        valid_types = ["file", "network", "process", "tool", "credential"]
        if v not in valid_types:
            raise ValueError(f"type must be one of: {valid_types}")
        return v


@app.post("/approve")
def approve(
    body: DecisionBody,
    _auth=Depends(_require_auth),
    _csrf=Depends(_validate_csrf_token),
):
    if body.decision not in ("allow", "block"):
        raise HTTPException(
            status_code=400, detail="decision must be allow or block",
        )
    try:
        storage.set_decision(body.event_id, body.decision)
    except ValueError:
        raise HTTPException(status_code=404, detail="event not found")

    _audit_log_dashboard_action("decision", {
        "event_id": body.event_id,
        "decision_made": body.decision,
    })
    return {"ok": True}


@app.post("/block")
def block(
    body: DecisionBody,
    _auth=Depends(_require_auth),
    _csrf=Depends(_validate_csrf_token),
):
    body.decision = "block"
    try:
        storage.set_decision(body.event_id, body.decision)
    except ValueError:
        raise HTTPException(status_code=404, detail="event not found")

    _audit_log_dashboard_action("decision", {
        "event_id": body.event_id,
        "decision_made": body.decision,
    })
    return {"ok": True}


@app.post("/policy/test")
def test_policy(
    body: PolicyTestBody,
    _auth=Depends(_require_auth),
    _csrf=Depends(_validate_csrf_token),
):
    pe = _get_policy_engine()
    try:
        pe.reload_policy()
    except Exception:
        pass

    action = {
        "type": body.type,
        "tool_name": body.tool_name,
        "agent": body.agent,
    }

    try:
        result = pe.evaluate(action)
    except Exception:
        raise HTTPException(status_code=500, detail="policy evaluation failed")

    _audit_log_dashboard_action("policy_test", {
        "test_action": action,
        "result_decision": (
            result.get("decision")
            if isinstance(result, dict)
            else (result[0] if isinstance(result, tuple) and len(result) > 0 else "unknown")
        ),
        "result_reason": (
            result.get("reason")
            if isinstance(result, dict)
            else (result[1] if isinstance(result, tuple) and len(result) > 1 else "unknown")
        ),
    })

    if isinstance(result, dict):
        return {
            "decision": result.get("decision"),
            "reason": result.get("reason"),
            "rule": result.get("rule"),
        }
    try:
        decision, reason = result
    except Exception:
        raise HTTPException(
            status_code=500, detail="invalid policy evaluate result",
        )
    return {"decision": decision, "reason": reason, "rule": None}


@app.delete("/events")
def delete_events(
    _auth=Depends(_require_auth),
    _csrf=Depends(_validate_csrf_token),
):
    try:
        storage.clear_events()
    except Exception:
        raise HTTPException(status_code=500, detail="failed to clear events")

    _audit_log_dashboard_action("clear_events", {})
    return {"ok": True}


@app.get("/status")
def get_status(_auth=Depends(_require_auth)):
    return {
        "status": "running",
        "storage": "SQLite (local)",
        "policy_engine": "active" if _policy_engine is not None else "default",
        "auth": "bearer token",
    }


@app.get("/")
def index(
    _auth=Depends(_require_auth),
    authorization: str = Header(None),
):
    html_path = os.path.join(static_dir, "index.html")
    if not os.path.exists(html_path):
        return {"ok": "no UI installed; create agentshield/static/index.html"}

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # Generate a per-session CSRF token
    parts = authorization.split(" ", 1) if authorization else ["", ""]
    auth_token = parts[1] if len(parts) == 2 else ""
    csrf_token = _get_csrf_token_for_session(auth_token) if auth_token else ""

    html_content = html_content.replace("{{ csrf_token }}", csrf_token)

    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html_content)


@app.get("/policy")
def get_policy(_auth=Depends(_require_auth)):
    pe = _get_policy_engine()
    try:
        pe.reload_policy()
    except Exception:
        pass
    return pe.policies


@app.post("/policy/update")
def update_policy(
    new_policy: dict = Body(...),
    _auth=Depends(_require_auth),
    _csrf=Depends(_validate_csrf_token),
):
    if not _validate_policy_json(new_policy):
        raise HTTPException(status_code=400, detail="invalid policy structure")

    pe = _get_policy_engine()
    try:
        pe.set_policy(new_policy)
    except jsonschema.ValidationError as e:
        raise HTTPException(
            status_code=400, detail=f"policy validation failed: {e.message}",
        )
    except Exception:
        raise HTTPException(status_code=500, detail="failed to write policy")

    _audit_log_dashboard_action("policy_update", {
        "rule_count": len(new_policy.get("rules", [])),
    })
    return {"ok": True}


if __name__ == "__main__":
    token = init_dashboard()
    print(f"[IronGate] Dashboard token: {token}")

    host = "127.0.0.1"
    if os.environ.get("IRONGATE_ALLOW_REMOTE") == "1":
        host = "0.0.0.0"
        print(
            f"[IronGate] WARNING: Dashboard bound to {host} (remote access enabled)",
            file=sys.stderr,
        )
        print(
            "[IronGate] Ensure network-level access control is in place.",
            file=sys.stderr,
        )
    else:
        print(f"[IronGate] Dashboard bound to {host} (localhost only)")
        print("[IronGate] Set IRONGATE_ALLOW_REMOTE=1 to allow remote access.")

    if not os.environ.get("IRONGATE_HTTPS_ENABLED"):
        print(
            "[IronGate] WARNING: Dashboard running without HTTPS encryption",
            file=sys.stderr,
        )
        print(
            "[IronGate] This is acceptable for localhost development but NOT for production.",
            file=sys.stderr,
        )
        print(
            "[IronGate] Set IRONGATE_HTTPS_ENABLED=1 and configure TLS for production.",
            file=sys.stderr,
        )

    uvicorn.run("agentshield.dashboard:app", host=host, port=9123, reload=False)

"""IronGate — Pydantic Schemas."""
from datetime import datetime
from typing import Any, List, Optional
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, field_validator

class LoginRequest(BaseModel):
    email: str; password: str
class TokenResponse(BaseModel):
    access_token: str; refresh_token: str; token_type: str = "bearer"; expires_in: int
class RefreshRequest(BaseModel):
    refresh_token: str
class UserCreate(BaseModel):
    email: EmailStr; username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$"); password: str = Field(min_length=12, max_length=128); full_name: Optional[str] = None
    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not any(c.isupper() for c in v): raise ValueError("Need uppercase")
        if not any(c.islower() for c in v): raise ValueError("Need lowercase")
        if not any(c.isdigit() for c in v): raise ValueError("Need digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v): raise ValueError("Need special char")
        return v
class UserResponse(BaseModel):
    id: UUID; email: str; username: str; full_name: Optional[str]; role: str; is_active: bool; created_at: datetime
    model_config = {"from_attributes": True}

class AgentRegister(BaseModel):
    name: str = Field(min_length=1, max_length=255); description: Optional[str] = None; organization: Optional[str] = None; contact_email: Optional[EmailStr] = None; purpose: Optional[str] = None; declared_capabilities: List[str] = []; model_provider: Optional[str] = None; model_name: Optional[str] = None; sdk_version: Optional[str] = None; metadata: dict[str, Any] = {}
class AgentUpdate(BaseModel):
    name: Optional[str] = None; description: Optional[str] = None; organization: Optional[str] = None; contact_email: Optional[EmailStr] = None; purpose: Optional[str] = None; declared_capabilities: Optional[List[str]] = None; metadata: Optional[dict[str, Any]] = None
class AgentResponse(BaseModel):
    id: UUID; name: str; description: Optional[str]; organization: Optional[str]; organization_verified: bool; fingerprint: str; status: str; trust_score: int; verification_level: int; purpose: Optional[str]; country: Optional[str]; model_provider: Optional[str]; model_name: Optional[str]; avg_requests_per_hour: float; total_requests: int; first_seen_at: datetime; last_active_at: datetime; created_at: datetime
    model_config = {"from_attributes": True}
class AgentDetailResponse(AgentResponse):
    contact_email: Optional[str]; ip_addresses: list; declared_capabilities: list; observed_capabilities: list; typical_endpoints: list; max_requests_per_hour: int; trust_score_history: list; autonomous_system: Optional[str]; sdk_version: Optional[str]; metadata: dict = Field(default_factory=dict, alias="agent_metadata"); verified_at: Optional[datetime]; banned_at: Optional[datetime]
    model_config = {"from_attributes": True, "populate_by_name": True}
class AgentVerify(BaseModel):
    status: str = Field(pattern=r"^(verified|suspicious|banned)$"); reason: str = Field(min_length=1, max_length=1000); verification_level: Optional[int] = Field(default=None, ge=0, le=3)

class ThreatReport(BaseModel):
    agent_id: Optional[UUID] = None; agent_fingerprint: Optional[str] = None; threat_type: str; severity: str = "medium"; confidence: float = Field(ge=0.0, le=1.0); description: str; source_ip: Optional[str] = None; target_endpoint: Optional[str] = None; request_method: Optional[str] = None; evidence: dict[str, Any] = {}
class ThreatResponse(BaseModel):
    id: UUID; agent_id: UUID; threat_type: str; severity: str; confidence: float; description: str; source_ip: Optional[str]; target_endpoint: Optional[str]; was_blocked: bool; auto_response: Optional[str]; resolved: bool; detection_method: Optional[str]; detected_at: datetime
    model_config = {"from_attributes": True}
class ThreatResolve(BaseModel):
    resolution_notes: str = Field(min_length=1, max_length=2000)

class BanCreate(BaseModel):
    agent_id: UUID; reason: str = Field(min_length=1, max_length=2000); scope: str = "global"; is_permanent: bool = False; expires_hours: Optional[int] = Field(default=None, ge=1, le=8760); triggering_threat_ids: List[UUID] = []; evidence_summary: Optional[str] = None
class BanResponse(BaseModel):
    id: UUID; agent_id: UUID; reason: str; scope: str; is_permanent: bool; is_active: bool; expires_at: Optional[datetime]; propagation_status: str; propagation_count: int; created_at: datetime
    model_config = {"from_attributes": True}
class BanRevoke(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)

class PolicyRuleCreate(BaseModel):
    name: str; description: Optional[str] = None; priority: int = 100; rule_type: str; conditions: dict[str, Any]; actions: dict[str, Any]; applies_to_statuses: List[str] = []; applies_to_endpoints: List[str] = []
class PolicyRuleResponse(BaseModel):
    id: UUID; name: str; description: Optional[str]; is_active: bool; priority: int; rule_type: str; conditions: dict; actions: dict; trigger_count: int; last_triggered_at: Optional[datetime]; created_at: datetime
    model_config = {"from_attributes": True}

class PeerRegister(BaseModel):
    node_id: str; name: str; endpoint_url: str; shared_secret: str = Field(min_length=32)
class PeerResponse(BaseModel):
    id: UUID; node_id: str; name: str; endpoint_url: str; is_active: bool; agents_monitored: int; intel_shared: int; intel_received: int; peer_trust_score: int; reliability_score: float; last_sync_at: Optional[datetime]
    model_config = {"from_attributes": True}

class PaginatedResponse(BaseModel):
    items: List[Any]; total: int; page: int; page_size: int; total_pages: int
class DashboardStats(BaseModel):
    total_agents: int; verified_agents: int; suspicious_agents: int; banned_agents: int; pending_agents: int; threats_24h: int; threats_blocked_24h: int; critical_threats_24h: int; active_bans: int; trust_network_peers: int; avg_trust_score: float
class HealthResponse(BaseModel):
    status: str; version: str; database: str; redis: str; uptime_seconds: float

class APIKeyCreate(BaseModel):
    name: str; scopes: List[str] = ["agents:read", "threats:read"]; rate_limit: int = Field(default=1000, ge=10, le=100000); expires_days: Optional[int] = Field(default=None, ge=1, le=365)
class APIKeyResponse(BaseModel):
    id: UUID; name: str; key_prefix: str; scopes: list; is_active: bool; rate_limit: int; request_count: int; last_used_at: Optional[datetime]; expires_at: Optional[datetime]; created_at: datetime
    model_config = {"from_attributes": True}
class APIKeyCreated(APIKeyResponse):
    raw_key: str

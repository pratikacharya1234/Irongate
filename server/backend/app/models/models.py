"""IronGate -- Database Models."""
import enum
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from app.core.database import Base

def utcnow(): return datetime.now(timezone.utc)
def new_uuid(): return uuid4()

class AgentStatus(str, enum.Enum):
    PENDING = "pending"; VERIFIED = "verified"; SUSPICIOUS = "suspicious"; BANNED = "banned"; REVOKED = "revoked"

class ThreatType(str, enum.Enum):
    PROMPT_INJECTION = "prompt_injection"; DATA_EXFILTRATION = "data_exfiltration"; IDENTITY_SPOOFING = "identity_spoofing"
    PRIVILEGE_ESCALATION = "privilege_escalation"; SCRAPING = "scraping"; MANIPULATION = "manipulation"
    DDOS = "ddos"; SOCIAL_ENGINEERING = "social_engineering"; MODEL_POISONING = "model_poisoning"; SUPPLY_CHAIN = "supply_chain"

class Severity(str, enum.Enum):
    CRITICAL = "critical"; HIGH = "high"; MEDIUM = "medium"; LOW = "low"; INFO = "info"

class BanScope(str, enum.Enum):
    GLOBAL = "global"; PLATFORM = "platform"; ENDPOINT = "endpoint"; ORGANIZATION = "organization"

class UserRole(str, enum.Enum):
    VIEWER = "viewer"; ANALYST = "analyst"; ADMIN = "admin"; SUPERADMIN = "superadmin"

class AuditAction(str, enum.Enum):
    AGENT_REGISTERED = "agent_registered"; AGENT_VERIFIED = "agent_verified"; AGENT_BANNED = "agent_banned"
    AGENT_UNBANNED = "agent_unbanned"; AGENT_STATUS_CHANGED = "agent_status_changed"
    THREAT_DETECTED = "threat_detected"; THREAT_RESOLVED = "threat_resolved"
    BAN_CREATED = "ban_created"; BAN_PROPAGATED = "ban_propagated"; BAN_REVOKED = "ban_revoked"
    POLICY_CREATED = "policy_created"; POLICY_UPDATED = "policy_updated"
    USER_LOGIN = "user_login"; API_KEY_CREATED = "api_key_created"; TRUST_SCORE_UPDATED = "trust_score_updated"

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")

class APIKey(Base):
    __tablename__ = "api_keys"
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(10), nullable=False)
    scopes = Column(JSONB, default=list)
    is_active = Column(Boolean, default=True, nullable=False)
    expires_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))
    request_count = Column(Integer, default=0)
    rate_limit = Column(Integer, default=1000)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    user = relationship("User", back_populates="api_keys")

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (Index("ix_agents_status_trust", "status", "trust_score"), Index("ix_agents_fingerprint", "fingerprint"), Index("ix_agents_org", "organization"), UniqueConstraint("fingerprint", name="uq_agents_fingerprint"))
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    organization = Column(String(255))
    organization_verified = Column(Boolean, default=False)
    contact_email = Column(String(255))
    fingerprint = Column(String(64), unique=True, nullable=False, index=True)
    user_agent = Column(String(512))
    ip_addresses = Column(JSONB, default=list)
    headers_hash = Column(String(64))
    status = Column(Enum(AgentStatus), default=AgentStatus.PENDING, nullable=False, index=True)
    trust_score = Column(Integer, default=50, nullable=False)
    trust_score_history = Column(JSONB, default=list)
    verification_level = Column(Integer, default=0)
    purpose = Column(String(100))
    declared_capabilities = Column(JSONB, default=list)
    observed_capabilities = Column(JSONB, default=list)
    typical_endpoints = Column(JSONB, default=list)
    avg_requests_per_hour = Column(Float, default=0)
    max_requests_per_hour = Column(Integer, default=0)
    total_requests = Column(Integer, default=0)
    country = Column(String(2))
    autonomous_system = Column(String(255))
    model_provider = Column(String(100))
    model_name = Column(String(100))
    sdk_version = Column(String(50))
    agent_metadata = Column("metadata", JSONB, default=dict)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_active_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    verified_at = Column(DateTime(timezone=True))
    banned_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    threats = relationship("ThreatEvent", back_populates="agent", cascade="all, delete-orphan")
    bans = relationship("Ban", back_populates="agent", cascade="all, delete-orphan")

class ThreatEvent(Base):
    __tablename__ = "threat_events"
    __table_args__ = (Index("ix_threats_agent_time", "agent_id", "detected_at"), Index("ix_threats_severity", "severity"), Index("ix_threats_type", "threat_type"))
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_type = Column(Enum(ThreatType), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    confidence = Column(Float, nullable=False)
    description = Column(Text, nullable=False)
    source_ip = Column(String(45))
    target_endpoint = Column(String(512))
    request_method = Column(String(10))
    request_payload_hash = Column(String(64))
    request_headers = Column(JSONB, default=dict)
    detection_method = Column(String(100))
    detection_rule_id = Column(String(100))
    matched_signatures = Column(JSONB, default=list)
    raw_evidence = Column(JSONB, default=dict)
    was_blocked = Column(Boolean, default=False, nullable=False)
    auto_response = Column(String(50))
    resolved = Column(Boolean, default=False)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at = Column(DateTime(timezone=True))
    resolution_notes = Column(Text)
    detected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    agent = relationship("Agent", back_populates="threats")

class Ban(Base):
    __tablename__ = "bans"
    __table_args__ = (Index("ix_bans_agent_active", "agent_id", "is_active"), Index("ix_bans_scope", "scope"))
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    scope = Column(Enum(BanScope), default=BanScope.GLOBAL, nullable=False)
    is_permanent = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True, nullable=False)
    triggering_threat_ids = Column(JSONB, default=list)
    evidence_summary = Column(Text)
    propagation_status = Column(String(20), default="pending")
    propagated_to = Column(JSONB, default=list)
    propagation_count = Column(Integer, default=0)
    propagation_started_at = Column(DateTime(timezone=True))
    propagation_completed_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    revoked_at = Column(DateTime(timezone=True))
    revocation_reason = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    agent = relationship("Agent", back_populates="bans")

class PolicyRule(Base):
    __tablename__ = "policy_rules"
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100)
    rule_type = Column(String(50), nullable=False)
    conditions = Column(JSONB, nullable=False)
    actions = Column(JSONB, nullable=False)
    applies_to_statuses = Column(JSONB, default=list)
    applies_to_endpoints = Column(JSONB, default=list)
    trigger_count = Column(Integer, default=0)
    last_triggered_at = Column(DateTime(timezone=True))
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

class TrustNetworkPeer(Base):
    __tablename__ = "trust_network_peers"
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    node_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    endpoint_url = Column(String(512), nullable=False)
    shared_secret_hash = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    agents_monitored = Column(Integer, default=0)
    intel_shared = Column(Integer, default=0)
    intel_received = Column(Integer, default=0)
    last_sync_at = Column(DateTime(timezone=True))
    avg_response_ms = Column(Float, default=0)
    peer_trust_score = Column(Integer, default=50)
    reliability_score = Column(Float, default=1.0)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_action_time", "action", "created_at"), Index("ix_audit_user", "user_id"), Index("ix_audit_agent", "agent_id"))
    id = Column(UUID(as_uuid=True), primary_key=True, default=new_uuid)
    action = Column(Enum(AuditAction), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL"))
    description = Column(Text, nullable=False)
    details = Column(JSONB, default=dict)
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    previous_hash = Column(String(64))
    entry_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

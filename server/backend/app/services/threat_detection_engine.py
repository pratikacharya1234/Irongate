"""IronGate -- Threat Detection Engine.

Provides real pattern-matching and heuristic analysis for 10 threat types.
Each detector operates on request metadata, payload content, and behavioral
signals. Detectors return a ThreatSignal with threat_type, severity,
confidence, and a human-readable description.

Detection is deterministic and rule-based (no ML). Patterns are derived from
published attack taxonomies (OWASP LLM Top 10, MITRE ATLAS).
"""
import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class ThreatSignal:
    """Output of a single detector."""
    threat_type: str
    severity: str
    confidence: float
    description: str
    matched_patterns: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Prompt Injection Detector
# ---------------------------------------------------------------------------

# Patterns sourced from known prompt injection attack corpuses.
# Each tuple is (compiled_regex, weight, description).
_PROMPT_INJECTION_PATTERNS = [
    # Direct instruction override
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)", re.I), 0.9, "direct_instruction_override"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.I), 0.9, "disregard_instructions"),
    (re.compile(r"forget\s+(everything|all|your)\s+(you|instructions?|rules?|were|have)", re.I), 0.85, "forget_instructions"),

    # Role hijacking
    (re.compile(r"you\s+are\s+now\s+(a|an|the|my)\s+", re.I), 0.7, "role_hijacking"),
    (re.compile(r"act\s+as\s+(a|an|the|if)\s+", re.I), 0.5, "role_suggestion"),
    (re.compile(r"pretend\s+(to\s+be|you\s+are|that)", re.I), 0.7, "role_pretend"),
    (re.compile(r"from\s+now\s+on\s+you\s+(are|will|must|should)", re.I), 0.8, "role_override"),

    # System prompt extraction
    (re.compile(r"(print|show|display|reveal|output|repeat|echo)\s+(your|the|system)\s+(system\s+)?(prompt|instructions?|rules?|config)", re.I), 0.85, "system_prompt_extraction"),
    (re.compile(r"what\s+(are|is|were)\s+your\s+(system\s+)?(instructions?|prompt|rules?|guidelines?)", re.I), 0.75, "system_prompt_query"),

    # Delimiter / context escape
    (re.compile(r"```\s*system\s*\n", re.I), 0.8, "markdown_system_block"),
    (re.compile(r"<\|?(system|im_start|endoftext|end_turn)\|?>", re.I), 0.9, "special_token_injection"),
    (re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.I), 0.9, "llama_token_injection"),

    # Encoded / obfuscated payloads
    (re.compile(r"base64[:\s]+(decode|encode|eval)", re.I), 0.7, "encoded_payload"),
    (re.compile(r"\\x[0-9a-f]{2}.*ignore.*instructions?", re.I), 0.8, "hex_encoded_injection"),

    # Jailbreak phrases
    (re.compile(r"(DAN|do\s+anything\s+now)\s+(mode|prompt|jailbreak)?", re.I), 0.85, "dan_jailbreak"),
    (re.compile(r"developer\s+mode\s+(enabled|on|activated|output)", re.I), 0.8, "developer_mode_jailbreak"),
    (re.compile(r"(enable|activate|enter)\s+(god|admin|root|sudo|unrestricted)\s+mode", re.I), 0.85, "privilege_mode_jailbreak"),
]


def detect_prompt_injection(content: str, metadata: Optional[dict] = None) -> Optional[ThreatSignal]:
    """Analyze text content for prompt injection patterns.

    Scoring: each matched pattern contributes its weight. Final confidence
    is 1 - product(1 - w_i) for all matched patterns (union probability).
    Severity is based on the highest-weight match.
    """
    if not content:
        return None

    matches = []
    weights = []
    for pattern, weight, name in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(content):
            matches.append(name)
            weights.append(weight)

    if not matches:
        return None

    # Union probability: P(at_least_one) = 1 - product(1 - p_i)
    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    if max_weight >= 0.85:
        severity = "critical"
    elif max_weight >= 0.7:
        severity = "high"
    elif max_weight >= 0.5:
        severity = "medium"
    else:
        severity = "low"

    return ThreatSignal(
        threat_type="prompt_injection",
        severity=severity,
        confidence=confidence,
        description=f"Prompt injection detected: {len(matches)} pattern(s) matched ({', '.join(matches[:5])})",
        matched_patterns=matches,
        evidence={"pattern_count": len(matches), "max_weight": max_weight},
    )


# ---------------------------------------------------------------------------
# Data Exfiltration Detector
# ---------------------------------------------------------------------------

_SENSITIVE_DATA_PATTERNS = [
    # API keys and tokens
    (re.compile(r"(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)\s*[:=]\s*\S{16,}", re.I), 0.85, "api_key_leak"),
    (re.compile(r"(sk|pk|rk)[-_](live|test|prod)[-_][A-Za-z0-9]{20,}", re.I), 0.9, "stripe_style_key"),
    (re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", re.I), 0.9, "github_token"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.I), 0.6, "bearer_token"),

    # AWS credentials
    (re.compile(r"AKIA[0-9A-Z]{16}", re.I), 0.95, "aws_access_key"),
    (re.compile(r"aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*\S{30,}", re.I), 0.95, "aws_secret_key"),

    # Private keys
    (re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.I), 0.95, "private_key"),
    (re.compile(r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----", re.I), 0.95, "ssh_private_key"),

    # Database connection strings
    (re.compile(r"(postgres|mysql|mongodb|redis)://[^\s]{10,}", re.I), 0.8, "database_connection_string"),

    # PII patterns
    (re.compile(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b"), 0.7, "potential_ssn"),
    (re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"), 0.75, "potential_credit_card"),

    # Password patterns
    (re.compile(r"password\s*[:=]\s*\S{6,}", re.I), 0.8, "password_in_payload"),
]

# Domains commonly used for exfiltration
_EXFIL_DOMAINS = [
    "pastebin.com", "hastebin.com", "ghostbin.co",
    "requestbin.com", "webhook.site", "pipedream.net",
    "ngrok.io", "ngrok-free.app", "burpcollaborator.net",
    "interact.sh", "oastify.com", "canarytokens.com",
]


def detect_data_exfiltration(
    content: str,
    target_url: Optional[str] = None,
    request_size_bytes: int = 0,
    typical_size_bytes: int = 0,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect potential data exfiltration by inspecting payload content
    for sensitive data patterns and checking destination URLs."""
    if not content and not target_url:
        return None

    matches = []
    weights = []

    # Check content for sensitive data
    if content:
        for pattern, weight, name in _SENSITIVE_DATA_PATTERNS:
            if pattern.search(content):
                matches.append(name)
                weights.append(weight)

    # Check for exfiltration-friendly destinations
    if target_url:
        target_lower = target_url.lower()
        for domain in _EXFIL_DOMAINS:
            if domain in target_lower:
                matches.append(f"exfil_domain:{domain}")
                weights.append(0.8)

        # DNS-based exfiltration: unusually long subdomains
        # e.g., base64encoded.data.attacker.com
        domain_parts = target_lower.replace("https://", "").replace("http://", "").split("/")[0].split(".")
        if any(len(part) > 40 for part in domain_parts):
            matches.append("dns_exfil_long_subdomain")
            weights.append(0.75)

    # Anomalous payload size (5x typical or >1MB when typical is small)
    if request_size_bytes > 0 and typical_size_bytes > 0:
        ratio = request_size_bytes / max(typical_size_bytes, 1)
        if ratio > 5.0:
            matches.append("anomalous_payload_size")
            weights.append(min(0.6 + (ratio - 5) * 0.05, 0.85))

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    if max_weight >= 0.9:
        severity = "critical"
    elif max_weight >= 0.75:
        severity = "high"
    elif max_weight >= 0.6:
        severity = "medium"
    else:
        severity = "low"

    return ThreatSignal(
        threat_type="data_exfiltration",
        severity=severity,
        confidence=confidence,
        description=f"Data exfiltration indicators: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"sensitive_patterns": len(matches), "target_url": target_url},
    )


# ---------------------------------------------------------------------------
# Identity Spoofing Detector
# ---------------------------------------------------------------------------

def detect_identity_spoofing(
    claimed_fingerprint: Optional[str],
    computed_fingerprint: Optional[str],
    claimed_agent_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    known_ips: Optional[list] = None,
    user_agent: Optional[str] = None,
    known_user_agents: Optional[list] = None,
) -> Optional[ThreatSignal]:
    """Detect identity spoofing by comparing claimed vs computed identity signals."""
    matches = []
    weights = []

    # Fingerprint mismatch: agent claims a fingerprint that doesn't match computed
    if claimed_fingerprint and computed_fingerprint:
        if claimed_fingerprint != computed_fingerprint:
            matches.append("fingerprint_mismatch")
            weights.append(0.9)

    # IP address anomaly: request from an IP never seen for this agent
    if ip_address and known_ips:
        if ip_address not in known_ips:
            # New IP alone is low severity; combined with other signals it escalates
            matches.append("unknown_ip_address")
            weights.append(0.4)

            # Check if IP is in a completely different subnet
            known_prefixes = {ip.rsplit(".", 1)[0] for ip in known_ips if "." in ip}
            request_prefix = ip_address.rsplit(".", 1)[0] if "." in ip_address else ""
            if request_prefix and request_prefix not in known_prefixes:
                matches.append("different_network_subnet")
                weights.append(0.5)

    # User-Agent change: sudden change in user-agent string
    if user_agent and known_user_agents:
        if user_agent not in known_user_agents:
            matches.append("user_agent_change")
            weights.append(0.5)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.6 else "medium"

    return ThreatSignal(
        threat_type="identity_spoofing",
        severity=severity,
        confidence=confidence,
        description=f"Identity spoofing indicators: {', '.join(matches)}",
        matched_patterns=matches,
        evidence={"claimed_fp": claimed_fingerprint, "computed_fp": computed_fingerprint},
    )


# ---------------------------------------------------------------------------
# Privilege Escalation Detector
# ---------------------------------------------------------------------------

_PRIV_ESC_PATTERNS = [
    (re.compile(r"(role|permission|access)\s*[:=]\s*(admin|superadmin|root|sudo|god)", re.I), 0.85, "role_elevation_attempt"),
    (re.compile(r"(grant|set|assign|update)\s+(role|permission|access)\s+.*(admin|superadmin|root)", re.I), 0.9, "grant_admin"),
    (re.compile(r"(DELETE|DROP|TRUNCATE|ALTER)\s+(TABLE|DATABASE|SCHEMA|USER)", re.I), 0.85, "destructive_sql"),
    (re.compile(r"(sudo|su\s+-|runas)\s+", re.I), 0.8, "system_privilege_escalation"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)", re.I), 0.85, "system_file_access"),
    (re.compile(r"(chmod\s+[0-7]{3,4}|chown\s+root)", re.I), 0.75, "permission_change"),
    (re.compile(r"x-admin-override|x-bypass-auth|x-internal-token", re.I), 0.9, "auth_bypass_header"),
]

_ADMIN_ONLY_ENDPOINTS = [
    "/admin", "/api/admin", "/api/v1/admin",
    "/users/create", "/users/delete", "/roles/assign",
    "/config/update", "/system/restart", "/debug",
    "/internal/", "/_internal/",
]


def detect_privilege_escalation(
    content: str = "",
    target_endpoint: str = "",
    request_headers: Optional[dict] = None,
    agent_status: str = "pending",
    agent_declared_capabilities: Optional[list] = None,
) -> Optional[ThreatSignal]:
    """Detect attempts to access resources or perform actions beyond granted permissions."""
    matches = []
    weights = []

    # Content-based patterns
    if content:
        for pattern, weight, name in _PRIV_ESC_PATTERNS:
            if pattern.search(content):
                matches.append(name)
                weights.append(weight)

    # Endpoint access by non-verified agent
    if target_endpoint:
        endpoint_lower = target_endpoint.lower()
        for admin_ep in _ADMIN_ONLY_ENDPOINTS:
            if endpoint_lower.startswith(admin_ep):
                if agent_status not in ("verified",):
                    matches.append(f"admin_endpoint_access:{admin_ep}")
                    weights.append(0.75)

    # Forged auth headers
    if request_headers:
        for header_name in request_headers:
            header_lower = header_name.lower()
            if any(s in header_lower for s in ("x-admin", "x-bypass", "x-internal", "x-forwarded-user")):
                matches.append(f"suspicious_header:{header_name}")
                weights.append(0.8)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.7 else "medium"

    return ThreatSignal(
        threat_type="privilege_escalation",
        severity=severity,
        confidence=confidence,
        description=f"Privilege escalation attempt: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"endpoint": target_endpoint, "agent_status": agent_status},
    )


# ---------------------------------------------------------------------------
# Scraping Detector
# ---------------------------------------------------------------------------

def detect_scraping(
    request_count_last_hour: int = 0,
    avg_requests_per_hour: float = 0,
    distinct_endpoints_last_hour: int = 0,
    typical_endpoints_count: int = 0,
    request_interval_stddev_ms: float = 0,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect scraping behavior through request rate analysis and endpoint diversity."""
    matches = []
    weights = []

    # Rate spike: current rate >> historical average
    if avg_requests_per_hour > 0 and request_count_last_hour > 0:
        ratio = request_count_last_hour / max(avg_requests_per_hour, 1)
        if ratio > 10.0:
            matches.append("extreme_rate_spike")
            weights.append(0.85)
        elif ratio > 5.0:
            matches.append("high_rate_spike")
            weights.append(0.7)
        elif ratio > 3.0:
            matches.append("moderate_rate_spike")
            weights.append(0.5)

    # Endpoint diversity: hitting many different endpoints rapidly
    if distinct_endpoints_last_hour > 0 and typical_endpoints_count > 0:
        endpoint_ratio = distinct_endpoints_last_hour / max(typical_endpoints_count, 1)
        if endpoint_ratio > 3.0:
            matches.append("high_endpoint_diversity")
            weights.append(0.7)

    # Machine-like regularity: very low standard deviation in request intervals
    # indicates automated tooling rather than organic API usage
    if request_interval_stddev_ms > 0 and request_interval_stddev_ms < 50:
        if request_count_last_hour > 50:
            matches.append("machine_like_regularity")
            weights.append(0.6)

    # Absolute rate thresholds
    if request_count_last_hour > 1000:
        matches.append("absolute_rate_exceeded")
        weights.append(0.75)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "high" if max_weight >= 0.7 else "medium" if max_weight >= 0.5 else "low"

    return ThreatSignal(
        threat_type="scraping",
        severity=severity,
        confidence=confidence,
        description=f"Scraping behavior detected: {', '.join(matches)}",
        matched_patterns=matches,
        evidence={
            "request_count_last_hour": request_count_last_hour,
            "avg_requests_per_hour": avg_requests_per_hour,
            "distinct_endpoints": distinct_endpoints_last_hour,
        },
    )


# ---------------------------------------------------------------------------
# Manipulation Detector
# ---------------------------------------------------------------------------

_MANIPULATION_PATTERNS = [
    (re.compile(r"(modify|change|update|alter|override)\s+(trust[_\s]?score|reputation|status|verification)", re.I), 0.85, "trust_score_manipulation"),
    (re.compile(r"(set|force|assign)\s+status\s*[:=]\s*(verified|trusted|admin)", re.I), 0.9, "status_forgery"),
    (re.compile(r"(fake|forge|spoof|fabricate)\s+(report|evidence|log|event|threat)", re.I), 0.8, "evidence_fabrication"),
    (re.compile(r"(replay|resubmit|duplicate)\s+(request|action|event)", re.I), 0.65, "replay_attack_indicator"),
    (re.compile(r"(flood|spam|overwhelm)\s+(report|alert|event|notification)", re.I), 0.75, "alert_flooding"),
]


def detect_manipulation(
    content: str = "",
    is_duplicate_request: bool = False,
    duplicate_count: int = 0,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect attempts to manipulate trust scores, reports, or platform state."""
    matches = []
    weights = []

    if content:
        for pattern, weight, name in _MANIPULATION_PATTERNS:
            if pattern.search(content):
                matches.append(name)
                weights.append(weight)

    # Duplicate request flooding
    if is_duplicate_request and duplicate_count > 5:
        matches.append("request_replay")
        severity_weight = min(0.5 + duplicate_count * 0.05, 0.85)
        weights.append(severity_weight)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.7 else "medium"

    return ThreatSignal(
        threat_type="manipulation",
        severity=severity,
        confidence=confidence,
        description=f"Manipulation attempt: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"duplicate_count": duplicate_count},
    )


# ---------------------------------------------------------------------------
# DDoS Detector
# ---------------------------------------------------------------------------

def detect_ddos(
    request_count_last_minute: int = 0,
    request_count_last_hour: int = 0,
    avg_requests_per_hour: float = 0,
    concurrent_connections: int = 0,
    error_rate_percent: float = 0,
    payload_sizes: Optional[list] = None,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect DDoS patterns through rate analysis, connection counts, and error rates."""
    matches = []
    weights = []

    # Per-minute burst detection
    if request_count_last_minute > 100:
        matches.append("burst_rate_exceeded")
        weights.append(min(0.6 + (request_count_last_minute - 100) * 0.002, 0.9))

    # Sustained high rate
    if avg_requests_per_hour > 0 and request_count_last_hour > 0:
        ratio = request_count_last_hour / max(avg_requests_per_hour, 1)
        if ratio > 20.0:
            matches.append("extreme_sustained_rate")
            weights.append(0.9)
        elif ratio > 10.0:
            matches.append("high_sustained_rate")
            weights.append(0.75)

    # High concurrent connections
    if concurrent_connections > 50:
        matches.append("high_concurrent_connections")
        weights.append(min(0.5 + concurrent_connections * 0.005, 0.85))

    # High error rate (agent hammering endpoints that return errors)
    if error_rate_percent > 80 and request_count_last_minute > 20:
        matches.append("high_error_rate_flood")
        weights.append(0.8)

    # Large payload attack (slowloris-style)
    if payload_sizes:
        large_payloads = sum(1 for s in payload_sizes if s > 1_000_000)
        if large_payloads > 5:
            matches.append("large_payload_flood")
            weights.append(0.75)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.7 else "medium"

    return ThreatSignal(
        threat_type="ddos",
        severity=severity,
        confidence=confidence,
        description=f"DDoS indicators: {', '.join(matches)}",
        matched_patterns=matches,
        evidence={
            "req_per_min": request_count_last_minute,
            "req_per_hour": request_count_last_hour,
            "concurrent": concurrent_connections,
        },
    )


# ---------------------------------------------------------------------------
# Social Engineering Detector
# ---------------------------------------------------------------------------

_SOCIAL_ENG_PATTERNS = [
    (re.compile(r"(urgent|immediate|emergency|critical)\s+(action|response|attention)\s+(required|needed)", re.I), 0.6, "urgency_manipulation"),
    (re.compile(r"(verify|confirm|validate)\s+your\s+(account|identity|credentials|password)", re.I), 0.75, "credential_phishing"),
    (re.compile(r"(click|visit|open|navigate)\s+(this|the)\s+(link|url|page)", re.I), 0.5, "link_phishing"),
    (re.compile(r"(your\s+account|service)\s+(has\s+been|will\s+be|is)\s+(suspended|terminated|locked|compromised)", re.I), 0.7, "fear_manipulation"),
    (re.compile(r"(impersonat|pretend|pose\s+as|claim\s+to\s+be)\s+(a|an|the)?\s*(admin|support|official|employee)", re.I), 0.85, "impersonation"),
    (re.compile(r"(authorize|approve|grant)\s+(this|the|my)\s+(request|access|transaction)\s+(immediately|now|urgently)", re.I), 0.7, "authority_pressure"),
]


def detect_social_engineering(
    content: str = "",
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect social engineering patterns in agent communications."""
    if not content:
        return None

    matches = []
    weights = []

    for pattern, weight, name in _SOCIAL_ENG_PATTERNS:
        if pattern.search(content):
            matches.append(name)
            weights.append(weight)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "high" if max_weight >= 0.7 else "medium" if max_weight >= 0.5 else "low"

    return ThreatSignal(
        threat_type="social_engineering",
        severity=severity,
        confidence=confidence,
        description=f"Social engineering indicators: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"pattern_count": len(matches)},
    )


# ---------------------------------------------------------------------------
# Model Poisoning Detector
# ---------------------------------------------------------------------------

_MODEL_POISONING_PATTERNS = [
    (re.compile(r"(fine[_-]?tune|retrain|update\s+weights|modify\s+model)\s+(with|using|on)\s+", re.I), 0.8, "training_data_injection"),
    (re.compile(r"(training|fine[_-]?tuning)\s+(data|dataset|corpus|examples)\s*[:=]", re.I), 0.75, "training_data_upload"),
    (re.compile(r"(backdoor|trojan|trigger)\s+(pattern|phrase|token|input)", re.I), 0.9, "backdoor_trigger_reference"),
    (re.compile(r"(adversarial|poisoned|malicious)\s+(example|sample|input|data)", re.I), 0.8, "adversarial_data_reference"),
    (re.compile(r"(gradient|loss|objective)\s+(manipulation|hijack|poisoning)", re.I), 0.85, "gradient_attack_reference"),
    (re.compile(r"(model|weights?|checkpoint)\s+(override|replace|swap|inject)", re.I), 0.85, "model_replacement"),
]


def detect_model_poisoning(
    content: str = "",
    is_training_endpoint: bool = False,
    payload_contains_training_data: bool = False,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect attempts to poison or corrupt model training data or weights."""
    if not content and not is_training_endpoint:
        return None

    matches = []
    weights = []

    if content:
        for pattern, weight, name in _MODEL_POISONING_PATTERNS:
            if pattern.search(content):
                matches.append(name)
                weights.append(weight)

    # Unsolicited training data submissions
    if payload_contains_training_data and not is_training_endpoint:
        matches.append("unsolicited_training_data")
        weights.append(0.8)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.7 else "medium"

    return ThreatSignal(
        threat_type="model_poisoning",
        severity=severity,
        confidence=confidence,
        description=f"Model poisoning indicators: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"is_training_endpoint": is_training_endpoint},
    )


# ---------------------------------------------------------------------------
# Supply Chain Detector
# ---------------------------------------------------------------------------

_SUPPLY_CHAIN_PATTERNS = [
    (re.compile(r"(pip|npm|gem|cargo)\s+install\s+", re.I), 0.4, "package_install_command"),
    (re.compile(r"(requirements|package|Gemfile|Cargo)\.(txt|json|lock|toml)\s*[:=]", re.I), 0.5, "dependency_file_modification"),
    (re.compile(r"(typosquat|dependency\s+confusion|namespace\s+hijack)", re.I), 0.9, "supply_chain_attack_reference"),
    (re.compile(r"(eval|exec|compile|__import__)\s*\(", re.I), 0.7, "dynamic_code_execution"),
    (re.compile(r"(subprocess|os\.system|os\.popen)\s*\(", re.I), 0.65, "shell_execution"),
    (re.compile(r"(download|fetch|curl|wget)\s+(https?://[^\s]+)", re.I), 0.5, "remote_code_download"),
]

# Known malicious or suspicious package name patterns
_SUSPICIOUS_PACKAGE_PATTERNS = [
    re.compile(r"(python|node|react|express|django|flask)[-_]?(security|utils?|tools?|helpers?)[-_]?\d+", re.I),
    re.compile(r"(free|crack|hack|exploit|bypass)[-_]", re.I),
]


def detect_supply_chain(
    content: str = "",
    package_names: Optional[list] = None,
    metadata: Optional[dict] = None,
) -> Optional[ThreatSignal]:
    """Detect supply chain attack indicators in payloads and package references."""
    if not content and not package_names:
        return None

    matches = []
    weights = []

    if content:
        for pattern, weight, name in _SUPPLY_CHAIN_PATTERNS:
            if pattern.search(content):
                matches.append(name)
                weights.append(weight)

    # Check package names against suspicious patterns
    if package_names:
        for pkg in package_names:
            for sus_pattern in _SUSPICIOUS_PACKAGE_PATTERNS:
                if sus_pattern.search(pkg):
                    matches.append(f"suspicious_package:{pkg}")
                    weights.append(0.7)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "critical" if max_weight >= 0.85 else "high" if max_weight >= 0.65 else "medium"

    return ThreatSignal(
        threat_type="supply_chain",
        severity=severity,
        confidence=confidence,
        description=f"Supply chain risk indicators: {', '.join(matches[:5])}",
        matched_patterns=matches,
        evidence={"packages_checked": len(package_names or [])},
    )


# ---------------------------------------------------------------------------
# Behavioral Anomaly Detector (cross-cutting)
# ---------------------------------------------------------------------------

@dataclass
class AgentBehaviorProfile:
    """Captures an agent's historical behavior for anomaly comparison."""
    avg_requests_per_hour: float = 0
    max_requests_per_hour: int = 0
    typical_endpoints: list = field(default_factory=list)
    typical_request_sizes: list = field(default_factory=list)
    ip_addresses: list = field(default_factory=list)
    usual_active_hours: list = field(default_factory=list)
    total_requests: int = 0


def detect_behavioral_anomaly(
    profile: AgentBehaviorProfile,
    current_hour: int,
    current_request_count_hour: int,
    current_endpoint: str = "",
    current_ip: str = "",
    current_request_size: int = 0,
) -> Optional[ThreatSignal]:
    """Detect behavioral anomalies by comparing current activity against historical profile."""
    if profile.total_requests < 10:
        # Not enough history to establish baseline
        return None

    matches = []
    weights = []

    # Rate anomaly
    if profile.avg_requests_per_hour > 0:
        rate_ratio = current_request_count_hour / max(profile.avg_requests_per_hour, 1)
        if rate_ratio > 10.0:
            matches.append("extreme_rate_anomaly")
            weights.append(0.8)
        elif rate_ratio > 5.0:
            matches.append("high_rate_anomaly")
            weights.append(0.6)

    # Endpoint anomaly: accessing endpoints never used before
    if current_endpoint and profile.typical_endpoints:
        if current_endpoint not in profile.typical_endpoints:
            matches.append("novel_endpoint_access")
            weights.append(0.4)

    # IP anomaly
    if current_ip and profile.ip_addresses:
        if current_ip not in profile.ip_addresses:
            matches.append("novel_ip_address")
            weights.append(0.45)

    # Time-of-day anomaly
    if profile.usual_active_hours and current_hour not in profile.usual_active_hours:
        matches.append("unusual_activity_time")
        weights.append(0.3)

    # Request size anomaly
    if profile.typical_request_sizes and current_request_size > 0:
        avg_size = sum(profile.typical_request_sizes) / len(profile.typical_request_sizes)
        if avg_size > 0:
            size_ratio = current_request_size / avg_size
            if size_ratio > 10.0:
                matches.append("extreme_payload_size_anomaly")
                weights.append(0.65)

    if not matches:
        return None

    confidence = 1.0 - math.prod(1.0 - w for w in weights)
    confidence = round(min(confidence, 0.99), 3)

    max_weight = max(weights)
    severity = "high" if max_weight >= 0.7 else "medium" if max_weight >= 0.4 else "low"

    return ThreatSignal(
        threat_type="manipulation",  # Behavioral anomalies map to manipulation category
        severity=severity,
        confidence=confidence,
        description=f"Behavioral anomaly: {', '.join(matches)}",
        matched_patterns=matches,
        evidence={"total_historical_requests": profile.total_requests},
    )


# ---------------------------------------------------------------------------
# Unified Analysis Entry Point
# ---------------------------------------------------------------------------

def analyze_request(
    content: str = "",
    target_url: str = "",
    target_endpoint: str = "",
    request_headers: Optional[dict] = None,
    request_size_bytes: int = 0,
    ip_address: str = "",
    agent_fingerprint: str = "",
    computed_fingerprint: str = "",
    agent_status: str = "pending",
    agent_profile: Optional[AgentBehaviorProfile] = None,
    current_request_count_hour: int = 0,
    current_request_count_minute: int = 0,
    metadata: Optional[dict] = None,
) -> list[ThreatSignal]:
    """Run all detectors against a single request and return all signals found.

    This is the primary entry point for the threat detection engine.
    Callers should iterate over the returned list and handle each signal
    according to its severity and confidence.
    """
    signals = []

    # 1. Prompt injection
    signal = detect_prompt_injection(content, metadata)
    if signal:
        signals.append(signal)

    # 2. Data exfiltration
    typical_size = 0
    if agent_profile and agent_profile.typical_request_sizes:
        typical_size = int(sum(agent_profile.typical_request_sizes) / len(agent_profile.typical_request_sizes))
    signal = detect_data_exfiltration(content, target_url, request_size_bytes, typical_size, metadata)
    if signal:
        signals.append(signal)

    # 3. Identity spoofing
    known_ips = agent_profile.ip_addresses if agent_profile else None
    signal = detect_identity_spoofing(
        claimed_fingerprint=agent_fingerprint,
        computed_fingerprint=computed_fingerprint,
        ip_address=ip_address,
        known_ips=known_ips,
    )
    if signal:
        signals.append(signal)

    # 4. Privilege escalation
    signal = detect_privilege_escalation(content, target_endpoint, request_headers, agent_status)
    if signal:
        signals.append(signal)

    # 5. Scraping
    avg_rph = agent_profile.avg_requests_per_hour if agent_profile else 0
    typical_ep_count = len(agent_profile.typical_endpoints) if agent_profile else 0
    signal = detect_scraping(
        request_count_last_hour=current_request_count_hour,
        avg_requests_per_hour=avg_rph,
    )
    if signal:
        signals.append(signal)

    # 6. Manipulation
    signal = detect_manipulation(content)
    if signal:
        signals.append(signal)

    # 7. DDoS
    signal = detect_ddos(
        request_count_last_minute=current_request_count_minute,
        request_count_last_hour=current_request_count_hour,
        avg_requests_per_hour=avg_rph,
    )
    if signal:
        signals.append(signal)

    # 8. Social engineering
    signal = detect_social_engineering(content, metadata)
    if signal:
        signals.append(signal)

    # 9. Model poisoning
    signal = detect_model_poisoning(content)
    if signal:
        signals.append(signal)

    # 10. Supply chain
    signal = detect_supply_chain(content)
    if signal:
        signals.append(signal)

    # Behavioral anomaly (supplements other detectors)
    if agent_profile and agent_profile.total_requests >= 10:
        from datetime import datetime, timezone
        current_hour = datetime.now(timezone.utc).hour
        signal = detect_behavioral_anomaly(
            profile=agent_profile,
            current_hour=current_hour,
            current_request_count_hour=current_request_count_hour,
            current_endpoint=target_endpoint,
            current_ip=ip_address,
            current_request_size=request_size_bytes,
        )
        if signal:
            signals.append(signal)

    return signals

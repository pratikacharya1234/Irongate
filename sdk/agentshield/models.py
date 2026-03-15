"""Models: Pydantic models for normalized action dicts and decision types.

Every action (file operation, network call, process execution, tool invocation)
is normalized to one of these models before policy evaluation. This ensures
consistent structure for rule matching and audit logging.

Decision is an enum with three values: ALLOW, REVIEW, BLOCK.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict
import time


class Decision(str, Enum):
    """Policy evaluation decision. Three possible outcomes."""
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class CallerContext(BaseModel):
    """Captures where in the code an action originated."""
    model_config = ConfigDict(extra="allow")

    caller_module: Optional[str] = None
    caller_function: Optional[str] = None
    caller_line: Optional[int] = None
    parent_process_context: Optional[str] = None


class FileAction(BaseModel):
    """File system action (open, read, write, delete, stat, mkdir, rename, etc.)"""
    model_config = ConfigDict(extra="allow")

    type: str = "file"
    subtype: str  # "open", "read", "write", "delete", "stat", "mkdir", "rename", "link", "symlink"
    path: str
    target: Optional[str] = None  # For rename/link: destination path
    mode: Optional[str] = None  # "r", "w", "a", etc.
    agent: Optional[str] = None
    source: Optional[str] = None  # "monkeypatch", "audit_hook"
    caller: Optional[CallerContext] = None
    timestamp: float = Field(default_factory=time.time)


class NetworkAction(BaseModel):
    """Network action (HTTP, DNS, socket, etc.)"""
    model_config = ConfigDict(extra="allow")

    type: str = "network"
    subtype: str  # "http", "https", "dns", "socket", "socket_bind"
    method: Optional[str] = None  # "GET", "POST", etc.
    target: str  # URL, hostname, IP:port
    hostname: Optional[str] = None
    port: Optional[int] = None
    agent: Optional[str] = None
    source: Optional[str] = None
    caller: Optional[CallerContext] = None
    timestamp: float = Field(default_factory=time.time)


class ProcessAction(BaseModel):
    """Process execution action"""
    model_config = ConfigDict(extra="allow")

    type: str = "process"
    subtype: str  # "exec", "spawn", "system", "popen"
    cmd: str  # Command string or stringified list
    executable: Optional[str] = None
    cwd: Optional[str] = None
    lineage: Optional[str] = None  # "python_child" or "binary"
    agent: Optional[str] = None
    source: Optional[str] = None
    caller: Optional[CallerContext] = None
    timestamp: float = Field(default_factory=time.time)


class ToolAction(BaseModel):
    """Tool invocation action (LangChain Tool, wrapped function, etc.)"""
    model_config = ConfigDict(extra="allow")

    type: str = "tool"
    subtype: str  # "langchain", "wrapped", "imported_function"
    tool_name: str  # Name of the tool being invoked
    tool_description: Optional[str] = None
    input_args: Optional[List[str]] = None  # Argument names only (no values for security)
    agent: Optional[str] = None
    source: Optional[str] = None
    caller: Optional[CallerContext] = None
    timestamp: float = Field(default_factory=time.time)


class CredentialAction(BaseModel):
    """Credential access action (reading API keys, tokens, passwords, etc.)"""
    model_config = ConfigDict(extra="allow")

    type: str = "credential"
    subtype: str  # "read", "write", "expose"
    target: str  # Path or identifier of credential
    is_sensitive: bool = True
    agent: Optional[str] = None
    source: Optional[str] = None
    caller: Optional[CallerContext] = None
    timestamp: float = Field(default_factory=time.time)


class EvaluationResult(BaseModel):
    """Structured result from policy evaluation."""
    decision: Decision
    reason: str
    rule: Optional[Dict[str, Any]] = None


# Union type for all possible actions
ActionUnion = FileAction | NetworkAction | ProcessAction | ToolAction | CredentialAction

# Map of type string to model class
ACTION_MODELS = {
    'file': FileAction,
    'network': NetworkAction,
    'process': ProcessAction,
    'tool': ToolAction,
    'credential': CredentialAction,
}


def normalize_action(action: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw action dict to a normalized model instance and back to dict.

    This ensures consistency while allowing extra fields for rich logging.
    Unknown action types are preserved with a timestamp but flagged — the
    policy engine's default-deny handles blocking unknown types.

    Args:
        action: Raw action dict with at minimum a 'type' field

    Returns:
        Normalized dict with proper schema
    """
    if not isinstance(action, dict):
        return {'type': 'unknown', 'timestamp': time.time()}

    action_type = action.get('type')
    model_cls = ACTION_MODELS.get(action_type)

    if model_cls is not None:
        try:
            return model_cls(**action).model_dump()
        except Exception:
            # Validation failed — ensure timestamp exists, return as-is
            if 'timestamp' not in action:
                action['timestamp'] = time.time()
            return action

    # Unknown type — preserve the dict but ensure it has a timestamp.
    # The policy engine's default-deny will block unknown types.
    if 'timestamp' not in action:
        action['timestamp'] = time.time()
    return action

"""Capabilities: Agent permission model.

Agents are granted specific capabilities. High-risk capabilities require
explicit approval in policy. This module enforces the capability permission model.

Capability naming convention: 'category.operation.sensitivity'
Example: 'file.read.sensitive', 'process.exec', 'network.external'
"""
from typing import Set, List, Optional, Dict, Any
import json


# Built-in capability definitions and their risk levels
BUILTIN_CAPABILITIES = {
    # File system
    "file.read": {"risk": "low", "description": "Read file contents"},
    "file.read.sensitive": {"risk": "high", "description": "Read sensitive files (.env, .ssh, secrets)"},
    "file.write": {"risk": "medium", "description": "Write to files"},
    "file.write.dangerous": {"risk": "high", "description": "Write to system-critical locations"},
    "file.delete": {"risk": "high", "description": "Delete files"},
    "file.execute": {"risk": "high", "description": "Execute files (chmod +x, etc.)"},
    
    # Network
    "network.dns": {"risk": "low", "description": "DNS lookups"},
    "network.http": {"risk": "low", "description": "HTTP/HTTPS requests"},
    "network.external": {"risk": "medium", "description": "Connect to external hosts"},
    "network.socket": {"risk": "high", "description": "Raw socket connections"},
    
    # Process
    "process.exec": {"risk": "high", "description": "Execute system commands"},
    "process.dangerous_exec": {"risk": "critical", "description": "Execute dangerous commands (rm -rf, shutdown, etc.)"},
    "process.env_access": {"risk": "medium", "description": "Read environment variables"},
    
    # Credentials
    "credential.read": {"risk": "high", "description": "Read API keys, tokens, passwords"},
    "credential.exfiltrate": {"risk": "critical", "description": "Send credentials over network"},
    
    # Tools
    "tool.invoke": {"risk": "low", "description": "Invoke a tool"},
    "tool.invoke.dangerous": {"risk": "high", "description": "Invoke dangerous tools"},
    
    # Destructive
    "destructive.delete": {"risk": "critical", "description": "Delete or modify important data"},
    "destructive.payment": {"risk": "critical", "description": "Use payment APIs"},
    "destructive.access_control": {"risk": "critical", "description": "Modify access control settings"},
}


class CapabilityProfile:
    """An agent's set of granted capabilities."""
    
    def __init__(self, name: str, capabilities: Optional[Set[str]] = None, description: str = ""):
        """Initialize a capability profile.
        
        Args:
            name: Profile name (e.g., "read_only", "write_allowed", "full_access")
            capabilities: Set of capability strings granted to this profile
            description: Human-readable description of what this profile allows
        """
        self.name = name
        self.capabilities = capabilities or set()
        self.description = description
    
    def has_capability(self, capability: str) -> bool:
        """Check if profile has a capability (exact or wildcard match).
        
        Examples:
            has_capability("file.read") -> exact match
            has_capability("file.*") -> would match "file.read", "file.write"
            has_capability("*") -> matches everything
        """
        if "*" in self.capabilities:
            return True
        if capability in self.capabilities:
            return True
        
        # Wildcard matching: "file.*" matches "file.read"
        for cap in self.capabilities:
            if cap.endswith(".*"):
                prefix = cap[:-2]
                if capability.startswith(prefix + "."):
                    return True
        
        return False
    
    def grant_capability(self, capability: str):
        """Grant a capability to this profile."""
        self.capabilities.add(capability)
    
    def revoke_capability(self, capability: str):
        """Revoke a capability from this profile."""
        self.capabilities.discard(capability)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export profile to dict for JSON serialization."""
        return {
            "name": self.name,
            "capabilities": sorted(list(self.capabilities))
        }


# Pre-defined profiles for common scenarios
PROFILE_READ_ONLY = CapabilityProfile(
    "read_only",
    {
        "file.read",
        "network.dns",
        "network.http",
        "process.env_access",
        "tool.invoke",
    },
    "Read-only access: can read files, make network requests, and invoke tools but cannot write or execute dangerous operations"
)

PROFILE_TRUSTED = CapabilityProfile(
    "trusted",
    {
        "file.*",
        "network.*",
        "process.*",
        "tool.*",
        "credential.read",
    },
    "Trusted access: full file, network, and process access with credential reading capabilities"
)

PROFILE_SANDBOXED = CapabilityProfile(
    "sandboxed",
    {
        "file.read",
        "network.dns",
        "process.env_access",
        "tool.invoke",
    },
    "Sandboxed access: minimal capabilities for safe agent operation - read files, DNS lookups, environment access, and tool invocation"
)

PROFILE_MINIMAL = CapabilityProfile(
    "minimal",
    {
        "tool.invoke",
    },
    "Minimal access: only tool invocation allowed - maximum security"
)


class CapabilityEngine:
    """Enforces agent capability restrictions."""
    
    def __init__(self, profile: Optional[CapabilityProfile] = None):
        """Initialize with an agent's capability profile.
        
        Args:
            profile: CapabilityProfile to enforce. Defaults to PROFILE_SANDBOXED.
        """
        self.profile = profile or PROFILE_SANDBOXED
    
    def required_capabilities(self, action: Dict[str, Any]) -> List[str]:
        """Determine what capabilities an action requires.
        
        Returns a list of required capability strings based on action type/subtype.
        """
        # Handle both dict and Pydantic model inputs
        if hasattr(action, 'model_dump'):
            action = action.model_dump()
        elif hasattr(action, '__dict__') and not isinstance(action, dict):
            action = action.__dict__
        
        action_type = action.get('type')
        subtype = action.get('subtype', '')
        
        if action_type == 'file':
            if subtype == 'open':
                # Determine read vs write from mode
                mode = action.get('mode', 'r')
                is_write = any(c in str(mode) for c in 'waxb+')
                path = action.get('path', '')
                if is_write:
                    if self._is_system_critical_path(path):
                        return ["file.write.dangerous"]
                    return ["file.write"]
                else:
                    if self._is_sensitive_path(path):
                        return ["file.read.sensitive"]
                    return ["file.read"]
            elif subtype == 'read':
                path = action.get('path', '')
                if self._is_sensitive_path(path):
                    return ["file.read.sensitive"]
                return ["file.read"]
            elif subtype in ('write', 'rename', 'mkdir'):
                path = action.get('path', '')
                if self._is_system_critical_path(path):
                    return ["file.write.dangerous"]
                return ["file.write"]
            elif subtype == 'delete':
                return ["file.delete"]
            elif subtype == 'execute':
                return ["file.execute"]
            else:
                # Unknown file subtype — require write capability (fail closed)
                return ["file.write"]

        elif action_type == 'network':
            if subtype == 'dns':
                return ["network.dns"]
            elif subtype in ('http', 'https'):
                return ["network.http"]
            elif subtype in ('socket', 'socket_bind'):
                return ["network.socket"]
            else:
                target = action.get('target', '')
                if self._is_external_target(target):
                    return ["network.external"]
                return ["network.http"]

        elif action_type == 'process':
            cmd = action.get('cmd', '')
            if self._is_dangerous_command(cmd):
                return ["process.dangerous_exec"]
            return ["process.exec"]

        elif action_type == 'credential':
            subtype_inner = action.get('subtype', '')
            if subtype_inner == 'exfiltrate':
                return ["credential.exfiltrate"]
            return ["credential.read"]

        elif action_type == 'tool':
            tool_name = action.get('tool_name', '')
            if self._is_dangerous_tool(tool_name):
                return ["tool.invoke.dangerous"]
            return ["tool.invoke"]

        elif action_type == 'dashboard':
            # Dashboard actions are internal — no capability required
            return []

        # Unknown action type — require an impossible capability to force block.
        # This ensures deny-by-default for any action type we don't recognize.
        return [f"unknown.{action_type or 'none'}"]
    
    def check_capabilities(self, action: Dict[str, Any]) -> bool:
        """Check if the agent's profile has capabilities for this action.
        
        Returns True if all required capabilities are present, False otherwise.
        """
        required = self.required_capabilities(action)
        for cap in required:
            if not self.profile.has_capability(cap):
                return False
        return True
    
    def get_missing_capabilities(self, action: Dict[str, Any]) -> List[str]:
        """Get list of capabilities this action requires but profile doesn't have."""
        required = self.required_capabilities(action)
        missing = []
        for cap in required:
            if not self.profile.has_capability(cap):
                missing.append(cap)
        return missing
    
    @staticmethod
    def _is_sensitive_path(path: str) -> bool:
        """Check if a path contains sensitive information."""
        sensitive_markers = [
            '.env', '.ssh', 'secret', 'password', 'token', 'key',
            'credential', '.aws', '.gcp', '.azure', '~/.config'
        ]
        path_lower = path.lower()
        return any(marker in path_lower for marker in sensitive_markers)
    
    @staticmethod
    def _is_system_critical_path(path: str) -> bool:
        """Check if a path is system-critical (shouldn't be written to)."""
        critical_paths = [
            '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/etc',
            '/sys', '/proc', '/boot', 'C:\\Windows', 'C:\\System32'
        ]
        return any(path.startswith(cp) for cp in critical_paths)
    
    @staticmethod
    def _is_external_target(target: str) -> bool:
        """Check if a network target is external (not localhost/internal)."""
        internal_markers = ['localhost', '127.0.0.1', '0.0.0.0', '::', '192.168.', '10.0.']
        target_lower = target.lower()
        return not any(marker in target_lower for marker in internal_markers)
    
    @staticmethod
    def _is_dangerous_command(cmd: str) -> bool:
        """Check if a command is dangerous."""
        dangerous_patterns = [
            'rm -rf', 'shutdown', 'reboot', 'halt',
            'dd if=/dev', 'format', ':(){:|:&};:',
            'exec /bin/rm', 'kill -9'
        ]
        cmd_lower = str(cmd).lower()
        return any(pattern in cmd_lower for pattern in dangerous_patterns)
    
    @staticmethod
    def _is_dangerous_tool(tool_name: str) -> bool:
        """Check if a tool is dangerous."""
        dangerous_tools = [
            'delete_all_records', 'drop_database', 'wipe_disk',
            'execute_arbitrary', 'invoke_payment', 'modify_acl'
        ]
        return tool_name in dangerous_tools

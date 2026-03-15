"""PolicyEngine for deterministic runtime security.

It loads policies from ~/.agentshield/policies.json if present, otherwise uses
the built-in default policy. The evaluate(action) method returns a dict with
decision, reason, and matched rule.

Rules support advanced matching:
- Exact match: "type": "file" matches action.type == "file"
- List match: "path_contains": [".env", ".ssh"] matches if path contains any
- Regex match: "cmd_pattern": "^sudo" matches if cmd matches regex
- Predicates: "path_startswith": "/sensitive" for prefix matching

Rules are evaluated in order; first match wins.
"""
import json
import os
import re
from typing import Tuple, Optional, Dict, Any, List

import jsonschema
from .capabilities import CapabilityEngine, PROFILE_SANDBOXED


def _load_default_policy():
    """Load the built-in default policy from default_policy.json."""
    default_policy_path = os.path.join(
        os.path.dirname(__file__),
        'default_policy.json'
    )
    try:
        with open(default_policy_path, 'r') as f:
            return json.load(f)
    except Exception:
        # Fallback if default_policy.json is missing: deny everything
        return {
            "rules": [
                {"decision": "block", "reason": "default_deny"}
            ],
        }


DEFAULT_POLICIES = _load_default_policy()


class PolicyEngine:
    def __init__(self, storage=None, policy_path=None, capability_profile=None):
        self.storage = storage
        self.policy_path = policy_path or os.path.expanduser("~/.agentshield/policies.json")
        self.capability_profile = capability_profile or PROFILE_SANDBOXED
        self.policies = DEFAULT_POLICIES.copy()
        self._load()

    def set_capability_profile(self, profile):
        """Set the active capability profile for enforcement.

        Args:
            profile: CapabilityProfile instance
        """
        self.capability_profile = profile

    def reload_policy(self):
        """Reload policies from disk, replacing current in-memory policies.

        If the policy file does not exist, create it with defaults.
        """
        # reset to defaults then load file
        self.policies = DEFAULT_POLICIES.copy()
        self._load()

    def set_policy(self, new_policy: dict):
        """Overwrite the policy file with new_policy (a dict) and reload."""
        # validate before writing
        self.validate_policy(new_policy)
        # ensure dir
        d = os.path.dirname(self.policy_path)
        os.makedirs(d, exist_ok=True)
        try:
            with open(self.policy_path, 'w') as f:
                json.dump(new_policy, f, indent=2)
        except Exception:
            raise
        # reload into memory
        self.reload_policy()

    def validate_policy(self, policy_obj: dict):
        """Validate policy object against JSON schema. Raise jsonschema.ValidationError on failure.

        Rules require a 'decision' field but 'type' is optional (catch-all rules omit it).
        """
        schema = {
            "type": "object",
            "properties": {
                "rules": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "tool_name": { "type": "string" },
                            "decision": {
                                "type": "string",
                                "enum": ["allow", "review", "block"]
                            }
                        },
                        "required": ["decision"]
                    }
                }
            },
            "required": ["rules"]
        }

        jsonschema.validate(policy_obj, schema)

    def _load(self):
        try:
            if os.path.exists(self.policy_path):
                with open(self.policy_path, 'r') as f:
                    data = json.load(f)
                    self.policies.update(data)
        except (json.JSONDecodeError, OSError) as e:
            # Fail closed: if policy file is corrupt, keep default deny policy
            # and log the error. Do not silently use an empty/broken policy.
            import sys
            print(f"[AgentShield] WARNING: Failed to load policy from {self.policy_path}: {e}",
                  file=sys.stderr)
        except Exception as e:
            import sys
            print(f"[AgentShield] WARNING: Unexpected error loading policy: {e}",
                  file=sys.stderr)

    def _match_rule(self, rule: Dict[str, Any], action: Dict[str, Any]) -> bool:
        """Check if a rule matches an action using various predicate types.
        
        Supported predicates:
        - Exact match: "type": "file" matches action.type == "file"
        - List match: "path_contains": [".env", ".ssh"] matches if path contains any
        - Regex match: "cmd_pattern": "^sudo" matches if cmd matches regex
        - Prefix match: "path_startswith": "/sensitive" 
        - Substring match: "target_contains": "payment"
        - Tool name list: "tool_name_contains": ["delete", "drop"]
        
        Returns True if all predicates in the rule match the action.
        """
        for key, expected in rule.items():
            if key in ('decision', 'reason', 'priority', 'capabilities'):
                continue  # Metadata fields, not predicates
            
            # Determine the base field name and predicate type
            if key.endswith('_contains'):
                base_key = key[:-9]  # Remove "_contains"
                actual = action.get(base_key)
                if not isinstance(expected, list):
                    expected = [expected]
                actual_str = str(actual) if actual is not None else ""
                if not any(marker in actual_str for marker in expected):
                    return False
                continue
            
            elif key.endswith('_pattern'):
                base_key = key[:-8]  # Remove "_pattern"
                actual = action.get(base_key)
                actual_str = str(actual) if actual is not None else ""
                try:
                    if not re.search(expected, actual_str):
                        return False
                except Exception:
                    return False
                continue
            
            elif key.endswith('_startswith'):
                base_key = key[:-11]  # Remove "_startswith"
                actual = action.get(base_key)
                actual_str = str(actual) if actual is not None else ""
                if not actual_str.startswith(str(expected)):
                    return False
                continue
            
            # Exact match for simple types (no special suffix)
            else:
                actual = action.get(key)
                if actual != expected:
                    return False
        
        return True

    def evaluate(self, action: dict) -> Dict[str, Any]:
        """Evaluate an action and return a result dict:

        {
          'decision': 'allow'|'review'|'block',
          'reason': 'text',
          'rule': { ... } | None
        }

        Rules are evaluated in order; first match wins.
        
        Supports:
        1. Explicit structured rules with field matching, predicates, priority
        2. Legacy checks for backwards compatibility
        3. Capability enforcement (if capabilities module available)
        """
        # Capability enforcement runs before rule matching.
        # If the agent's profile lacks required capabilities, block immediately.
        cap_engine = CapabilityEngine(self.capability_profile)
        if not cap_engine.check_capabilities(action):
            missing = cap_engine.get_missing_capabilities(action)
            return {
                'decision': 'block',
                'reason': f'missing_capability:{",".join(missing)}',
                'rule': None,
            }

        # Try explicit rules (first match wins)
        rules = self.policies.get('rules', []) or []
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            if self._match_rule(rule, action):
                decision = rule.get('decision')
                reason = rule.get('reason', 'matched_rule')

                # Check per-rule capability requirements if present
                required_caps = rule.get('capabilities', [])
                if required_caps:
                    for cap in required_caps:
                        if not cap_engine.profile.has_capability(cap):
                            return {
                                'decision': 'block',
                                'reason': f'missing_capability:{cap}',
                                'rule': rule,
                            }

                return {
                    'decision': decision,
                    'reason': reason,
                    'rule': rule,
                }

        # Legacy/default checks preserved for backwards compatibility
        typ = action.get('type')
        legacy = self.policies.get('legacy_settings', {})

        # File actions
        if typ == 'file':
            path = action.get('path', '')
            for s in legacy.get('block_sensitive_files', []):
                if s in path:
                    return {'decision': 'block', 'reason': f'sensitive_path_match:{s}', 'rule': None}
            if action.get('subtype') == 'delete':
                if 'delete_file' in legacy.get('require_approval', []):
                    return {'decision': 'review', 'reason': 'delete_requires_approval', 'rule': None}
            return {'decision': 'block', 'reason': 'default_deny', 'rule': None}

        # Network actions
        if typ == 'network':
            target = action.get('target', '')
            for d in legacy.get('blocked_domains', []):
                if d in target:
                    return {'decision': 'block', 'reason': f'blocked_domain:{d}', 'rule': None}
            return {'decision': 'block', 'reason': 'default_deny', 'rule': None}

        # Process execution
        if typ == 'process':
            cmd = action.get('cmd', '')
            if 'rm -rf' in cmd or 'shutdown' in cmd:
                return {'decision': 'block', 'reason': 'dangerous_command', 'rule': None}
            return {'decision': 'block', 'reason': 'default_deny', 'rule': None}

        # Default deny for unknown action types
        return {'decision': 'block', 'reason': 'default_deny', 'rule': None}

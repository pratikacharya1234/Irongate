"""AgentShield - Deterministic runtime security for AI agents.

AgentShield is a policy-based runtime enforcement layer that monitors and
controls how AI agents interact with the operating system.

Usage:

    from agentshield import shield, protect_agent

    # Direct API
    action_allowed = shield.evaluate_action({
        'type': 'file',
        'path': '/etc/passwd',
        'subtype': 'read'
    })

    # Protected agent decorator
    @protect_agent
    def run_my_agent():
        # All file/network/process calls are enforced by policy
        with open('data.csv') as f:
            return f.read()

    # Or context manager
    with shield.protect():
        agent.run(query)

See README.md and SECURITY_MODEL.md for detailed documentation.
"""
__version__ = "0.1.0"

from .interceptor import RuntimeInterceptor
from .policy import PolicyEngine
from .storage import LocalStorage
from .notifier import Notifier
from .models import (
    normalize_action, Decision, EvaluationResult, CallerContext,
    FileAction, NetworkAction, ProcessAction, ToolAction, CredentialAction,
)
from .capabilities import CapabilityEngine, CapabilityProfile, PROFILE_SANDBOXED, PROFILE_READ_ONLY, PROFILE_TRUSTED
from .approvals import ApprovalQueue, normalize_approval_dto
from .audit_hooks import install_audit_hooks, deactivate_audit_hooks, is_available as audit_hooks_available
from .limitation_detector import install_limitation_detector

# Global runtime instance
storage = LocalStorage()
policy = PolicyEngine(storage=storage)
notifier = Notifier(storage=storage)
shield = RuntimeInterceptor(policy=policy, storage=storage, notifier=notifier)

# Install limitation detector to warn about known limitations when agents use them
limitation_detector = install_limitation_detector()


def protect_agent(agent):
    """Protect an agent (callable) by running it inside the shield.protect()

    If `agent` is a callable, returns a wrapped callable that when invoked
    runs the original inside the protected runtime (monkeypatched).
    If `agent` is not callable, returns it unchanged.
    """
    from functools import wraps

    if callable(agent):
        @wraps(agent)
        def _wrapped(*args, **kwargs):
            with shield.protect():
                return agent(*args, **kwargs)

        return _wrapped

    return agent


__all__ = [
    '__version__',
    'shield',
    'protect_agent',
    'storage',
    'policy',
    'notifier',
    'limitation_detector',
    'normalize_action',
    'Decision',
    'EvaluationResult',
    'CallerContext',
    'FileAction',
    'NetworkAction',
    'ProcessAction',
    'ToolAction',
    'CredentialAction',
    'CapabilityEngine',
    'CapabilityProfile',
    'PROFILE_SANDBOXED',
    'PROFILE_READ_ONLY',
    'PROFILE_TRUSTED',
    'ApprovalQueue',
    'normalize_approval_dto',
    'install_audit_hooks',
    'deactivate_audit_hooks',
    'audit_hooks_available',
]

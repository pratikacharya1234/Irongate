"""Detect remaining known limitations and warn when they're encountered.

This module monitors for known bypass vectors and limitation usage patterns,
logging warnings when agents attempt to use unprotected APIs or mechanisms.

Known limitations detected:
- C extensions (ctypes, cffi) bypass all Python-level enforcement
- Pre-imported function references bypass monkeypatching
- os.exec*, os.spawn*, os.popen not monkeypatched (covered by audit hooks)
- Audit log not encrypted at rest
- Hash chaining detects but does not prevent tampering
- --isolate does not provide OS-level sandboxing
"""

import sys
import logging
from typing import Any, Set, Callable
import importlib.abc
import importlib.machinery

logger = logging.getLogger("agentshield.limitations")


# APIs NOT intercepted by monkeypatching (covered by audit hooks or not at all)
NOT_INTERCEPTED_APIS = {
    'os.exec': 'os.exec* variants — covered by audit hooks, not monkeypatched',
    'os.spawn': 'os.spawn* variants — covered by audit hooks, not monkeypatched',
    'os.popen': 'os.popen — not intercepted',
}

# C extensions that bypass all enforcement
C_EXTENSION_MODULES = {
    'ctypes': 'ctypes allows arbitrary C function calls — bypasses all enforcement',
    'cffi': 'cffi allows C FFI — bypasses all enforcement',
}

# Dangerous patterns
DANGEROUS_PATTERNS = {
    'builtins.open': 'Pre-imported open reference bypasses monkeypatch',
    'os.remove': 'Pre-imported os.remove bypasses monkeypatch',
    'requests.get': 'Pre-imported requests.get bypasses monkeypatch',
}


class LimitationWarner:
    """Monitor for and warn about known limitations and bypass vectors."""

    def __init__(self):
        self.warned_apis: Set[str] = set()
        self.warned_c_extensions: Set[str] = set()
        self.warned_patterns: Set[str] = set()

    def check_import(self, module_name: str) -> None:
        """Check if an imported module represents a known limitation.

        Args:
            module_name: Name of the module being imported
        """
        # Check for unintercepted APIs
        if module_name in NOT_INTERCEPTED_APIS:
            if module_name not in self.warned_apis:
                msg = f"LIMITATION: {module_name} — {NOT_INTERCEPTED_APIS[module_name]}"
                logger.warning(msg)
                self.warned_apis.add(module_name)

        # Check for C extensions
        if module_name in C_EXTENSION_MODULES:
            if module_name not in self.warned_c_extensions:
                msg = f"BYPASS RISK: {module_name} — {C_EXTENSION_MODULES[module_name]}"
                logger.warning(msg)
                self.warned_c_extensions.add(module_name)

    def check_attribute_access(self, obj: Any, attr: str) -> None:
        """Check if code is accessing dangerous pre-imported references.

        Args:
            obj: Object being accessed
            attr: Attribute name
        """
        # Check for builtins module access
        if hasattr(obj, '__name__') and obj.__name__ == 'builtins':
            if attr == 'open':
                pattern = f"builtins.{attr}"
                if pattern not in self.warned_patterns:
                    msg = (f"LIMITATION: Direct builtins.{attr} access may bypass "
                           "monkeypatch if saved before shield.protect()")
                    logger.warning(msg)
                    self.warned_patterns.add(pattern)

    def log_limitation_summary(self) -> None:
        """Log a summary of all detected limitations."""
        if self.warned_apis or self.warned_c_extensions or self.warned_patterns:
            logger.warning(
                "SUMMARY: Agent attempted to use known limitation APIs. "
                "These are not fully intercepted by AgentShield. Verify policy is "
                "sufficient for your security requirements."
            )


class ImportWarningHook:
    """Hook into sys.meta_path to detect module imports and warn about limitations."""

    def __init__(self, warner: LimitationWarner):
        self.warner = warner
        self.original_find_module = None

    def find_module(self, fullname: str, path: Any = None) -> None:
        """Called when a module is imported. Check for known limitations.

        Args:
            fullname: Full name of the module being imported
            path: Module search path
        """
        # Extract top-level module name
        top_level = fullname.split('.')[0]
        self.warner.check_import(top_level)
        return None  # Return None to let normal import continue


def install_limitation_detector() -> LimitationWarner:
    """Install import hook to detect limitation usage.

    Returns:
        LimitationWarner instance for manual checks
    """
    warner = LimitationWarner()
    hook = ImportWarningHook(warner)

    # Install at beginning of meta_path to be called first
    sys.meta_path.insert(0, hook)

    logger.debug("Limitation detector installed")
    return warner


def warn_about_audit_log_limitations() -> None:
    """Warn about audit log limitations."""
    msg = (
        "AUDIT LOG LIMITATIONS:\n"
        "  - Audit log is NOT encrypted at rest\n"
        "  - Hash chaining DETECTS tampering but does NOT prevent it\n"
        "  - For compliance, back up logs to immutable external system (syslog, etc.)\n"
        "  - File system access by attacker can modify sqlite database\n"
        "  Use storage.verify_chain() to detect modifications"
    )
    logger.warning(msg)


def warn_about_isolate_mode_limitations() -> None:
    """Warn about --isolate mode limitations."""
    msg = (
        "--isolate MODE LIMITATIONS:\n"
        "  - Does NOT provide OS-level sandboxing\n"
        "  - Does NOT protect against system-level attacks\n"
        "  - For stronger isolation, use containers or VMs\n"
        "  - Child process inherits all parent capabilities\n"
        "  - Useful for process-level separation, not security boundary"
    )
    logger.warning(msg)


def warn_about_enforcement_model() -> None:
    """Warn about the enforcement model limitations."""
    msg = (
        "ENFORCEMENT MODEL LIMITATIONS:\n"
        "  - No AI/ML-based detection — enforcement is purely rule-based\n"
        "  - Policy-based only — no behavioral analysis or anomaly detection\n"
        "  - Designed for semi-trusted agents, not adversarial code\n"
        "  - Local runtime only — no cloud, distributed trust, or enterprise features\n"
        "  - For untrusted code, combine with OS-level isolation (containers, seccomp)"
    )
    logger.warning(msg)


def warn_about_scope() -> None:
    """Warn about the scope limitations of v0.1.0."""
    msg = (
        "v0.1.0 SCOPE LIMITATIONS:\n"
        "  - LOCAL RUNTIME ONLY — not for cloud deployments\n"
        "  - NOT suitable for adversarial agents\n"
        "  - NOT a substitute for OS-level sandboxing (containers, VMs, seccomp)\n"
        "  - NOT suitable for distributed or multi-tenant scenarios\n"
        "  - NOT a compliance or audit tool\n"
        "  See SECURITY.md and THREAT_MODEL.md for detailed analysis"
    )
    logger.warning(msg)

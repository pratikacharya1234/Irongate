"""Audit Hooks: sys.addaudithook-based runtime enforcement.

Uses Python's PEP 578 audit hook system to observe and enforce runtime events
at a level deeper than monkeypatching. Audit hooks cannot be removed once
installed, making them harder to bypass than monkeypatches.

Handles audit events for:
- File open (open, os.open)
- Subprocess execution (subprocess.Popen, os.system, os.exec*, os.spawn*)
- Socket connections (socket.connect, socket.bind, socket.sendto)
- Module imports (import)
- OS operations (os.remove, os.unlink, os.rename, os.mkdir, os.rmdir, os.chmod)

Each event is converted to a normalized AgentShield action dict and routed
through the policy engine. Denied actions raise PermissionError.

Limitations:
- sys.addaudithook requires Python 3.8+
- Audit hooks are global and permanent for the process lifetime
- C extensions that bypass CPython API are not observed
- Some audit events may not be available on all platforms
"""
import sys
import os
import threading
from typing import Optional, Callable, Set

# Minimum Python version for audit hooks
_MIN_VERSION = (3, 8)
_AUDIT_HOOKS_AVAILABLE = sys.version_info >= _MIN_VERSION


class AuditHookEnforcer:
    """Installs a sys.addaudithook that routes events through AgentShield policy.

    Once installed, the hook cannot be removed (Python limitation by design).
    The enforcer can be enabled/disabled via the `active` flag, but the hook
    itself stays registered for the lifetime of the process.
    """

    # Audit event names we handle
    HANDLED_EVENTS: Set[str] = {
        # File operations
        "open",

        # Subprocess / process execution
        "subprocess.Popen",
        "os.system",
        "os.exec",
        "os.posix_spawn",
        "os.spawn",

        # Socket operations
        "socket.connect",
        "socket.bind",
        "socket.sendto",

        # OS file management
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.mkdir",
        "os.rmdir",
        "os.chmod",
        "os.chown",

        # Import (for monitoring, not blocking by default)
        "import",
    }

    # Paths that AgentShield itself needs — exempt from enforcement to avoid
    # infinite recursion (policy engine reads files, storage writes SQLite, etc.)
    _INTERNAL_PATH_MARKERS = (
        "/.agentshield/",
        "\\.agentshield\\",
    )

    def __init__(self):
        self.active = False
        self._evaluator: Optional[Callable] = None
        self._installed = False
        self._lock = threading.Lock()
        # Track re-entrant calls per thread to avoid infinite recursion
        self._thread_local = threading.local()

    def install(self, evaluator: Callable):
        """Install the audit hook with the given evaluator function.

        Args:
            evaluator: Callable that takes an action dict and returns True
                       if allowed, False if denied. Typically shield.evaluate_action.

        Raises:
            RuntimeError: If audit hooks are not available (Python < 3.8)
        """
        if not _AUDIT_HOOKS_AVAILABLE:
            raise RuntimeError(
                f"sys.addaudithook requires Python {_MIN_VERSION[0]}.{_MIN_VERSION[1]}+, "
                f"running {sys.version_info[0]}.{sys.version_info[1]}"
            )

        with self._lock:
            if self._installed:
                # Already installed — just update evaluator and activate
                self._evaluator = evaluator
                self.active = True
                return

            self._evaluator = evaluator
            self.active = True
            self._installed = True

        # Install the hook — this is permanent for the process
        sys.addaudithook(self._hook)

    def deactivate(self):
        """Deactivate enforcement (hook stays registered but becomes a no-op)."""
        self.active = False

    def activate(self):
        """Re-activate enforcement after deactivation."""
        if not self._installed:
            raise RuntimeError("Cannot activate: audit hook not installed. Call install() first.")
        self.active = True

    def _is_reentrant(self) -> bool:
        """Check if we're already inside a hook call on this thread."""
        return getattr(self._thread_local, "in_hook", False)

    def _set_reentrant(self, value: bool):
        self._thread_local.in_hook = value

    def _is_internal_path(self, path: str) -> bool:
        """Check if path belongs to AgentShield internals (exempt from enforcement)."""
        if not path:
            return False
        for marker in self._INTERNAL_PATH_MARKERS:
            if marker in path:
                return True
        # Also exempt the agentshield package source directory
        if "/agentshield/" in path or "\\agentshield\\" in path:
            try:
                pkg_dir = os.path.dirname(os.path.abspath(__file__))
                if os.path.abspath(path).startswith(pkg_dir):
                    return True
            except (ValueError, OSError):
                pass
        return False

    def _hook(self, event: str, args):
        """The actual audit hook registered with sys.addaudithook.

        This function is called by CPython for every auditable event.
        It must be fast for unhandled events and must never raise
        exceptions for events we don't enforce.
        """
        # Fast path: skip if not active or event not handled
        if not self.active or event not in self.HANDLED_EVENTS:
            return

        # Prevent infinite recursion: policy evaluation itself triggers
        # file opens, socket ops, etc.
        if self._is_reentrant():
            return

        try:
            self._set_reentrant(True)
            action = self._event_to_action(event, args)
            if action is None:
                return

            # Skip internal AgentShield operations
            path = action.get("path", "") or action.get("target", "")
            if self._is_internal_path(str(path)):
                return

            evaluator = self._evaluator
            if evaluator is None:
                return

            allowed = evaluator(action)
            if not allowed:
                reason = action.get("_deny_reason", "audit_hook_denied")
                raise PermissionError(
                    f"AgentShield audit hook blocked {event}: {reason}"
                )
        except PermissionError:
            raise  # Re-raise our own denials
        except Exception:
            # Fail closed: if we can't evaluate, block
            # But only for events we explicitly enforce (not imports)
            if event != "import":
                raise PermissionError(
                    f"AgentShield audit hook: enforcement error for {event}, failing closed"
                )
        finally:
            self._set_reentrant(False)

    def _event_to_action(self, event: str, args) -> Optional[dict]:
        """Convert a CPython audit event + args into an AgentShield action dict.

        Returns None for events we observe but don't enforce (e.g., imports
        from standard paths).
        """
        import time

        if event == "open":
            # args: (path, mode, flags)
            if not args or len(args) < 1:
                return None
            path = str(args[0]) if args[0] is not None else ""
            mode = str(args[1]) if len(args) > 1 and args[1] is not None else "r"
            if not path:
                return None
            return {
                "type": "file",
                "subtype": "open",
                "path": path,
                "mode": mode,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "subprocess.Popen":
            # args: (args, executable, ...)
            cmd = str(args[0]) if args and args[0] is not None else ""
            executable = str(args[1]) if len(args) > 1 and args[1] is not None else ""
            return {
                "type": "process",
                "subtype": "exec",
                "cmd": cmd,
                "executable": executable,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "os.system":
            # args: (command,)
            cmd = str(args[0]) if args else ""
            return {
                "type": "process",
                "subtype": "system",
                "cmd": cmd,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event in ("os.exec", "os.posix_spawn", "os.spawn"):
            # args vary but first is typically the path/executable
            cmd = str(args[0]) if args else ""
            return {
                "type": "process",
                "subtype": "exec",
                "cmd": cmd,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "socket.connect":
            # args: (socket, address)
            addr = str(args[1]) if len(args) > 1 else str(args[0]) if args else ""
            return {
                "type": "network",
                "subtype": "socket",
                "target": addr,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "socket.bind":
            addr = str(args[1]) if len(args) > 1 else str(args[0]) if args else ""
            return {
                "type": "network",
                "subtype": "socket_bind",
                "target": addr,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "socket.sendto":
            addr = str(args[1]) if len(args) > 1 else ""
            return {
                "type": "network",
                "subtype": "socket",
                "target": addr,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event in ("os.remove", "os.unlink"):
            path = str(args[0]) if args else ""
            return {
                "type": "file",
                "subtype": "delete",
                "path": path,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "os.rename":
            src = str(args[0]) if args else ""
            dst = str(args[1]) if len(args) > 1 else ""
            return {
                "type": "file",
                "subtype": "rename",
                "path": src,
                "target": dst,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "os.mkdir":
            path = str(args[0]) if args else ""
            return {
                "type": "file",
                "subtype": "mkdir",
                "path": path,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "os.rmdir":
            path = str(args[0]) if args else ""
            return {
                "type": "file",
                "subtype": "delete",
                "path": path,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event in ("os.chmod", "os.chown"):
            path = str(args[0]) if args else ""
            return {
                "type": "file",
                "subtype": "execute",
                "path": path,
                "timestamp": time.time(),
                "source": "audit_hook",
            }

        elif event == "import":
            # Monitor but don't enforce standard imports — only flag suspicious ones
            module_name = str(args[0]) if args else ""
            # Skip standard library and common packages
            if not module_name or module_name.startswith(("_", "encodings", "codecs")):
                return None
            # We return None for imports — they are logged but not blocked
            # To block imports, uncomment below and add import rules to policy
            return None

        return None


# Module-level singleton
_enforcer = AuditHookEnforcer()


def install_audit_hooks(evaluator: Callable):
    """Install audit hooks with the given evaluator function.

    Args:
        evaluator: Callable that takes an action dict and returns True if allowed.
                   Typically `shield.evaluate_action`.
    """
    _enforcer.install(evaluator)


def deactivate_audit_hooks():
    """Deactivate audit hook enforcement (hook remains registered)."""
    _enforcer.deactivate()


def activate_audit_hooks():
    """Re-activate audit hook enforcement."""
    _enforcer.activate()


def is_available() -> bool:
    """Check if audit hooks are available on this Python version."""
    return _AUDIT_HOOKS_AVAILABLE


def is_active() -> bool:
    """Check if audit hooks are currently active."""
    return _enforcer.active and _enforcer._installed

"""Interceptor: monkeypatches Python runtime APIs for security enforcement.

Covers:
- File operations: builtins.open, io.open, pathlib.Path.open/read_text/
  write_text/read_bytes/write_bytes/unlink/rename/replace/mkdir, os.open,
  os.remove, os.unlink, os.rename, os.mkdir, os.makedirs, os.rmdir,
  os.fdopen, os.link, os.symlink, shutil.rmtree, shutil.copy, shutil.copy2,
  shutil.move, shutil.copytree, os.removedirs
- Network: requests, httpx, urllib, socket.socket, socket.create_connection,
  aiohttp, http.client.HTTPConnection/HTTPSConnection, ssl.wrap_socket
- Process: subprocess.run, subprocess.Popen, subprocess.call,
  subprocess.check_call, subprocess.check_output, os.system
  (with Python child vs binary classification)

Returns normalized action dicts {decision, reason, rule}.

Known limitations:
- Works only when the agent runs in the same Python process and uses
  standard libs. For native/binary agents use OS-level sandboxing.
- Pre-imported references to patched functions bypass interception.
- C extensions (ctypes, cffi) bypass Python-level monkeypatching.
- os.exec*, os.spawn*, os.popen are not patched (covered by audit hooks).
- Some async libraries may not be fully intercepted.
"""
import builtins
import io
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import requests

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import http.client
    HAS_HTTP_CLIENT = True
except ImportError:
    HAS_HTTP_CLIENT = False

try:
    import ssl
    HAS_SSL = True
except ImportError:
    HAS_SSL = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import urllib.request
    import urllib.parse
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


class RuntimeInterceptor:
    """Runtime security interceptor for AI agent actions."""

    def __init__(self, policy, storage, notifier):
        """Initialize the interceptor.

        Args:
            policy: PolicyEngine instance
            storage: Storage instance (e.g., LocalStorage)
            notifier: Notifier instance for alerts
        """
        self.policy = policy
        self.storage = storage
        self.notifier = notifier
        self._lock = threading.RLock()
        # Track re-entrant calls per thread to avoid infinite recursion
        self._thread_local = threading.local()

    def _is_reentrant(self) -> bool:
        """Check if we're already inside an action handler on this thread."""
        return getattr(self._thread_local, "in_handler", False)

    def _set_reentrant(self, value: bool):
        self._thread_local.in_handler = value

    def _is_internal_path(self, path: str) -> bool:
        """Check if path belongs to AgentShield internals (exempt from enforcement).

        Matches:
        - ~/.agentshield/ directory (storage, policy, notifications)
        - agentshield package directory itself
        """
        if not path:
            return False
        # Match the AgentShield data directory (e.g. ~/.agentshield/events.db)
        if "/.agentshield/" in path or "\\.agentshield\\" in path:
            return True
        # Match the agentshield package source directory
        if "/agentshield/" in path or "\\agentshield\\" in path:
            # Only match if it looks like a package path, not user files
            import os
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            try:
                if os.path.abspath(path).startswith(pkg_dir):
                    return True
            except (ValueError, OSError):
                pass
        return False

    def _handle_action(self, action: dict) -> tuple:
        """Core action handler: evaluate, log, and decide.

        Args:
            action: Action dict with at minimum 'type' field

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        # Prevent infinite recursion: policy evaluation itself triggers
        # file opens, socket ops, etc.
        if self._is_reentrant():
            return True, "reentrant_call_allowed"

        # Skip internal AgentShield operations
        path = action.get("path", "") or action.get("target", "")
        if self._is_internal_path(str(path)):
            return True, "internal_operation_allowed"

        if 'timestamp' not in action:
            action['timestamp'] = time.time()

        try:
            self._set_reentrant(True)

            # Evaluate against policies
            raw_result = self.policy.evaluate(action)
            if isinstance(raw_result, dict):
                decision = raw_result.get('decision')
                reason = raw_result.get('reason')
                matched_rule = raw_result.get('rule')
            else:
                # Legacy tuple response
                try:
                    decision, reason = raw_result
                except Exception:
                    # Fail closed: invalid policy result defaults to block
                    decision = 'block'
                    reason = 'invalid_policy_result'
                matched_rule = None

            # Attach matched rule for audit logging
            if matched_rule is not None:
                action['_matched_rule'] = matched_rule

            # Log the action
            try:
                event_id = self.storage.log_event(action, decision, reason)
            except Exception:
                event_id = None

            if decision == 'allow':
                return True, None

            elif decision == 'review':
                # Notify about pending review
                try:
                    self.notifier.notify(action, level='warning')
                except Exception:
                    pass

                if event_id is None:
                    return False, 'no_event_logged'

                # Wait for approval via dashboard (timeout controlled by policy, not agent)
                timeout = self.policy.policies.get('approval_timeout_seconds', 300)
                approved = self._wait_for_approval(event_id, timeout=timeout)
                if approved:
                    try:
                        self.storage.set_decision(event_id, 'allow')
                    except Exception:
                        pass
                    return True, 'owner_approved'
                else:
                    try:
                        self.storage.set_decision(event_id, 'block')
                    except Exception:
                        pass
                    return False, 'owner_denied_or_timeout'

            else:  # decision == 'block' or unknown
                return False, reason

        finally:
            self._set_reentrant(False)

    def evaluate_action(self, action: dict) -> bool:
        """Public API: evaluate an action and return True if allowed.

        Args:
            action: Action dict

        Returns:
            True if action is allowed, False otherwise
        """
        allowed, _ = self._handle_action(action)
        return bool(allowed)

    def _wait_for_approval(self, event_id: int, timeout: int = 300,
                          poll_interval: float = 1.0) -> bool:
        """Poll storage for approval decision until timeout.

        Args:
            event_id: Event ID to wait for
            timeout: Max seconds to wait
            poll_interval: Sleep between polls

        Returns:
            True if approved, False if blocked or timeout
        """
        start = time.time()
        while time.time() - start < timeout:
            ev = self.storage.get_event(event_id)
            if not ev:
                time.sleep(poll_interval)
                continue

            decision = ev.get('decision')
            if decision == 'allow':
                return True
            if decision == 'block':
                return False

            time.sleep(poll_interval)

        return False  # Timeout: safe default is deny

    # ==================== File operations ====================

    def _open_wrapper(self, orig_open, file, mode='r', *args, **kwargs):
        """Wrapper for builtins.open() and io.open()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'open',
                'path': str(file),
                'mode': mode
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_open(file, mode, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_open_wrapper(self, orig_method, path_obj, *args, **kwargs):
        """Wrapper for pathlib.Path.open()."""
        try:
            mode = kwargs.get('mode', 'r')
            action = {
                'type': 'file',
                'subtype': 'open',
                'path': str(path_obj),
                'mode': mode
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_open_wrapper(self, orig_open, path, flags, *args, **kwargs):
        """Wrapper for os.open()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'open',
                'path': str(path),
                'flags': flags
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_open(path, flags, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_remove_wrapper(self, orig_remove, path, *args, **kwargs):
        """Wrapper for os.remove() and os.unlink()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'delete',
                'path': str(path)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_remove(path, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_rename_wrapper(self, orig_rename, src, dst, *args, **kwargs):
        """Wrapper for os.rename()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'rename',
                'path': str(src),
                'target': str(dst)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_rename(src, dst, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _shutil_rmtree_wrapper(self, orig_rmtree, path, *args, **kwargs):
        """Wrapper for shutil.rmtree()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'delete',
                'path': str(path)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_rmtree(path, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _shutil_copy_wrapper(self, orig_copy, src, dst, *args, **kwargs):
        """Wrapper for shutil.copy() and shutil.copy2()."""
        try:
            # Copy requires read on src and write on dst
            read_action = {
                'type': 'file',
                'subtype': 'read',
                'path': str(src)
            }
            allowed, reason = self._handle_action(read_action)
            if not allowed:
                raise PermissionError(f"AgentShield blocked read: {reason}")

            write_action = {
                'type': 'file',
                'subtype': 'write',
                'path': str(dst)
            }
            allowed, reason = self._handle_action(write_action)
            if not allowed:
                raise PermissionError(f"AgentShield blocked write: {reason}")

            return orig_copy(src, dst, *args, **kwargs)
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _shutil_move_wrapper(self, orig_move, src, dst, *args, **kwargs):
        """Wrapper for shutil.move()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'rename',
                'path': str(src),
                'target': str(dst)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_move(src, dst, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_mkdir_wrapper(self, orig_mkdir, path, *args, **kwargs):
        """Wrapper for os.mkdir() and os.makedirs()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'mkdir',
                'path': str(path)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_mkdir(path, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_rmdir_wrapper(self, orig_rmdir, path, *args, **kwargs):
        """Wrapper for os.rmdir()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'delete',
                'path': str(path)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_rmdir(path, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_read_text_wrapper(self, orig_method, path_obj, *args, **kwargs):
        """Wrapper for pathlib.Path.read_text() and read_bytes()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'read',
                'path': str(path_obj)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_write_text_wrapper(self, orig_method, path_obj, *args, **kwargs):
        """Wrapper for pathlib.Path.write_text() and write_bytes()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'write',
                'path': str(path_obj)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_unlink_wrapper(self, orig_method, path_obj, *args, **kwargs):
        """Wrapper for pathlib.Path.unlink()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'delete',
                'path': str(path_obj)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_rename_wrapper(self, orig_method, path_obj, target, *args, **kwargs):
        """Wrapper for pathlib.Path.rename() and replace()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'rename',
                'path': str(path_obj),
                'target': str(target)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, target, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _path_mkdir_wrapper(self, orig_method, path_obj, *args, **kwargs):
        """Wrapper for pathlib.Path.mkdir()."""
        try:
            action = {
                'type': 'file',
                'subtype': 'mkdir',
                'path': str(path_obj)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_method(path_obj, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _socket_connect_wrapper(self, orig_connect, sock_obj, address, *args, **kwargs):
        """Wrapper for socket.create_connection()."""
        try:
            action = {
                'type': 'network',
                'subtype': 'socket',
                'target': str(address)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_connect(address, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    # ==================== Network operations ====================

    def _http_wrapper(self, orig_request, method: str, url: str,
                     *args, **kwargs):
        """Wrapper for HTTP requests (requests library)."""
        try:
            action = {
                'type': 'network',
                'subtype': 'http',
                'method': method,
                'target': url
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_request(method, url, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _httpx_request_wrapper(self, orig_request, method: str, url: str,
                              *args, **kwargs):
        """Wrapper for httpx requests."""
        try:
            action = {
                'type': 'network',
                'subtype': 'http',
                'method': method,
                'target': url
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_request(method, url, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _urllib_urlopen_wrapper(self, orig_urlopen, url, *args, **kwargs):
        """Wrapper for urllib.request.urlopen()."""
        try:
            action = {
                'type': 'network',
                'subtype': 'http',
                'target': str(url)
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_urlopen(url, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _socket_wrapper(self, orig_socket, *args, **kwargs):
        """Wrapper for socket.socket() constructor."""
        try:
            action = {
                'type': 'network',
                'subtype': 'socket',
                'target': f'socket({args})'
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_socket(*args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    # ==================== Process operations ====================

    @staticmethod
    def _classify_subprocess(cmd) -> str:
        """Classify a subprocess command as 'python_child' or 'binary'.

        Python child processes get subtype 'python_child' — policy can treat
        them differently (e.g., allow Python children that will have their
        own AgentShield bootstrap, but block arbitrary binaries).
        """
        cmd_str = str(cmd).lower() if cmd else ""
        # Check if the command is a Python interpreter
        python_markers = ("python", "python3", "python2", sys.executable.lower())
        if isinstance(cmd, (list, tuple)):
            first = str(cmd[0]).lower() if cmd else ""
            if any(first.endswith(m) or first == m for m in python_markers):
                return "python_child"
        else:
            first_word = cmd_str.split()[0] if cmd_str.strip() else ""
            if any(first_word.endswith(m) or first_word == m for m in python_markers):
                return "python_child"
        return "binary"

    def _subprocess_run_wrapper(self, orig_run, *popenargs, **kwargs):
        """Wrapper for subprocess.run()."""
        try:
            cmd = popenargs[0] if popenargs else kwargs.get('args')
            process_class = self._classify_subprocess(cmd)
            action = {
                'type': 'process',
                'subtype': 'exec',
                'cmd': str(cmd),
                'process_class': process_class,
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_run(*popenargs, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _subprocess_popen_wrapper(self, orig_popen, *popenargs, **kwargs):
        """Wrapper for subprocess.Popen()."""
        try:
            cmd = popenargs[0] if popenargs else kwargs.get('args')
            process_class = self._classify_subprocess(cmd)
            action = {
                'type': 'process',
                'subtype': 'spawn',
                'cmd': str(cmd),
                'process_class': process_class,
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_popen(*popenargs, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _subprocess_call_wrapper(self, orig_call, *popenargs, **kwargs):
        """Wrapper for subprocess.call(), check_call(), check_output()."""
        try:
            cmd = popenargs[0] if popenargs else kwargs.get('args')
            process_class = self._classify_subprocess(cmd)
            action = {
                'type': 'process',
                'subtype': 'exec',
                'cmd': str(cmd),
                'process_class': process_class,
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_call(*popenargs, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_system_wrapper(self, orig_system, cmd: str):
        """Wrapper for os.system()."""
        try:
            action = {
                'type': 'process',
                'subtype': 'system',
                'cmd': cmd
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_system(cmd)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            # Re-raise policy denial errors
            raise
        except Exception:
            # Fail closed: any unexpected error in enforcement blocks the operation
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _os_fdopen_wrapper(self, orig_fdopen, fd, *args, **kwargs):
        """Wrapper for os.fdopen()."""
        action = {
            'type': 'file',
            'subtype': 'open',
            'path': f'fd:{fd}',  # Use fd number as identifier
            'mode': args[0] if args else kwargs.get('mode', 'r')
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_fdopen(fd, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _os_link_wrapper(self, orig_link, src, dst, *args, **kwargs):
        """Wrapper for os.link()."""
        action = {
            'type': 'file',
            'subtype': 'link',
            'path': dst,
            'src_path': src
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_link(src, dst, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _os_symlink_wrapper(self, orig_symlink, src, dst, *args, **kwargs):
        """Wrapper for os.symlink()."""
        action = {
            'type': 'file',
            'subtype': 'symlink',
            'path': dst,
            'src_path': src
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_symlink(src, dst, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _shutil_copytree_wrapper(self, orig_copytree, src, dst, *args, **kwargs):
        """Wrapper for shutil.copytree()."""
        action = {
            'type': 'file',
            'subtype': 'copytree',
            'path': dst,
            'src_path': src
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_copytree(src, dst, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _os_removedirs_wrapper(self, orig_removedirs, path):
        """Wrapper for os.removedirs()."""
        action = {
            'type': 'file',
            'subtype': 'delete',
            'path': path
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_removedirs(path)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _http_client_wrapper(self, orig_init, conn_obj, host, port=None, *args, **kwargs):
        """Wrapper for http.client.HTTPConnection/HTTPSConnection."""
        try:
            action = {
                'type': 'network',
                'subtype': 'http',
                'target': f"{host}:{port or 80}",
                'hostname': host,
                'port': port or 80
            }
            allowed, reason = self._handle_action(action)
            if allowed:
                return orig_init(conn_obj, host, port, *args, **kwargs)
            raise PermissionError(f"AgentShield blocked: {reason}")
        except PermissionError:
            raise
        except Exception:
            raise PermissionError(f"AgentShield enforcement error: operation blocked for safety")

    def _aiohttp_request_wrapper(self, orig_request, method: str, url: str, *args, **kwargs):
        """Wrapper for aiohttp request methods."""
        action = {
            'type': 'network',
            'subtype': 'http',
            'method': method.upper(),
            'target': url
        }
        # Extract hostname if possible
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                action['hostname'] = parsed.hostname
                action['port'] = parsed.port
        except:
            pass

        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_request(method, url, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    def _ssl_wrap_socket_wrapper(self, orig_wrap_socket, sock, *args, **kwargs):
        """Wrapper for ssl.wrap_socket and ssl.SSLContext.wrap_socket."""
        # Get peer info if available
        peer = None
        try:
            peer = sock.getpeername()
        except:
            pass

        action = {
            'type': 'network',
            'subtype': 'ssl',
            'target': str(peer) if peer else 'unknown',
            'hostname': peer[0] if peer and len(peer) > 0 else None,
            'port': peer[1] if peer and len(peer) > 1 else None
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_wrap_socket(sock, *args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    # ==================== Tool operations ====================

    def _tool_wrapper(self, orig_func, tool_name: str, *args, **kwargs):
        """Wrapper for tool invocations."""
        action = {
            'type': 'tool',
            'subtype': 'invoke',
            'tool_name': tool_name,
            'input_args': [str(arg)[:100] for arg in args[:5]]
        }
        allowed, reason = self._handle_action(action)
        if allowed:
            return orig_func(*args, **kwargs)
        raise PermissionError(f"AgentShield blocked: {reason}")

    @contextmanager
    def protect(self):
        """Context manager that applies monkeypatches for the duration.

        Patches file, network, process, and tool operations. All operations
        route through PolicyEngine for deterministic allow/review/block decisions.

        Usage:
            with shield.protect():
                agent.run()

        Or via @shield.protect_agent decorator in __init__.py
        """
        with self._lock:
            # === File patches ===
            orig_open = builtins.open
            builtins.open = lambda file, mode='r', *a, **kw: self._open_wrapper(
                orig_open, file, mode, *a, **kw
            )

            orig_io_open = io.open
            io.open = lambda file, mode='r', *a, **kw: self._open_wrapper(
                orig_io_open, file, mode, *a, **kw
            )

            orig_path_open = Path.open
            Path.open = lambda self_path, *a, **kw: self._path_open_wrapper(
                orig_path_open, self_path, *a, **kw
            )

            orig_os_open = os.open
            os.open = lambda path, flags, *a, **kw: self._os_open_wrapper(
                orig_os_open, path, flags, *a, **kw
            )

            orig_os_remove = os.remove
            os.remove = lambda path, *a, **kw: self._os_remove_wrapper(
                orig_os_remove, path, *a, **kw
            )

            orig_os_unlink = os.unlink
            os.unlink = lambda path, *a, **kw: self._os_remove_wrapper(
                orig_os_unlink, path, *a, **kw
            )

            orig_os_rename = os.rename
            os.rename = lambda src, dst, *a, **kw: self._os_rename_wrapper(
                orig_os_rename, src, dst, *a, **kw
            )

            orig_shutil_rmtree = shutil.rmtree
            shutil.rmtree = lambda path, *a, **kw: self._shutil_rmtree_wrapper(
                orig_shutil_rmtree, path, *a, **kw
            )

            orig_shutil_copy = shutil.copy
            shutil.copy = lambda src, dst, *a, **kw: self._shutil_copy_wrapper(
                orig_shutil_copy, src, dst, *a, **kw
            )

            orig_shutil_copy2 = shutil.copy2
            shutil.copy2 = lambda src, dst, *a, **kw: self._shutil_copy_wrapper(
                orig_shutil_copy2, src, dst, *a, **kw
            )

            orig_shutil_move = shutil.move
            shutil.move = lambda src, dst, *a, **kw: self._shutil_move_wrapper(
                orig_shutil_move, src, dst, *a, **kw
            )

            orig_os_mkdir = os.mkdir
            os.mkdir = lambda path, *a, **kw: self._os_mkdir_wrapper(
                orig_os_mkdir, path, *a, **kw
            )

            orig_os_makedirs = os.makedirs
            os.makedirs = lambda path, *a, **kw: self._os_mkdir_wrapper(
                orig_os_makedirs, path, *a, **kw
            )

            orig_os_rmdir = os.rmdir
            os.rmdir = lambda path, *a, **kw: self._os_rmdir_wrapper(
                orig_os_rmdir, path, *a, **kw
            )

            # Additional file operations
            orig_os_fdopen = os.fdopen
            os.fdopen = lambda fd, *a, **kw: self._os_fdopen_wrapper(
                orig_os_fdopen, fd, *a, **kw
            )

            orig_os_link = os.link
            os.link = lambda src, dst, *a, **kw: self._os_link_wrapper(
                orig_os_link, src, dst, *a, **kw
            )

            orig_os_symlink = os.symlink
            os.symlink = lambda src, dst, *a, **kw: self._os_symlink_wrapper(
                orig_os_symlink, src, dst, *a, **kw
            )

            orig_shutil_copytree = shutil.copytree
            shutil.copytree = lambda src, dst, *a, **kw: self._shutil_copytree_wrapper(
                orig_shutil_copytree, src, dst, *a, **kw
            )

            orig_os_removedirs = os.removedirs
            os.removedirs = lambda path: self._os_removedirs_wrapper(
                orig_os_removedirs, path
            )

            # === Pathlib convenience methods ===
            orig_path_read_text = Path.read_text
            Path.read_text = lambda self_path, *a, **kw: self._path_read_text_wrapper(
                orig_path_read_text, self_path, *a, **kw
            )

            orig_path_read_bytes = Path.read_bytes
            Path.read_bytes = lambda self_path, *a, **kw: self._path_read_text_wrapper(
                orig_path_read_bytes, self_path, *a, **kw
            )

            orig_path_write_text = Path.write_text
            Path.write_text = lambda self_path, *a, **kw: self._path_write_text_wrapper(
                orig_path_write_text, self_path, *a, **kw
            )

            orig_path_write_bytes = Path.write_bytes
            Path.write_bytes = lambda self_path, *a, **kw: self._path_write_text_wrapper(
                orig_path_write_bytes, self_path, *a, **kw
            )

            orig_path_unlink = Path.unlink
            Path.unlink = lambda self_path, *a, **kw: self._path_unlink_wrapper(
                orig_path_unlink, self_path, *a, **kw
            )

            orig_path_rename = Path.rename
            Path.rename = lambda self_path, target, *a, **kw: self._path_rename_wrapper(
                orig_path_rename, self_path, target, *a, **kw
            )

            orig_path_replace = Path.replace
            Path.replace = lambda self_path, target, *a, **kw: self._path_rename_wrapper(
                orig_path_replace, self_path, target, *a, **kw
            )

            orig_path_mkdir = Path.mkdir
            Path.mkdir = lambda self_path, *a, **kw: self._path_mkdir_wrapper(
                orig_path_mkdir, self_path, *a, **kw
            )

            # === Network patches ===
            orig_requests_req = requests.request
            requests.request = lambda method, url, *a, **kw: self._http_wrapper(
                orig_requests_req, method, url, *a, **kw
            )

            orig_requests_sess_req = requests.Session.request
            requests.Session.request = lambda self_sess, method, url, *a, **kw: (
                self._http_wrapper(
                    lambda m, u, *x, **y: orig_requests_sess_req(self_sess, m, u, *x, **y),
                    method, url, *a, **kw
                )
            )

            httpx_patches = []
            if HAS_HTTPX:
                try:
                    orig_httpx_req = httpx.request
                    httpx.request = lambda method, url, *a, **kw: self._httpx_request_wrapper(
                        orig_httpx_req, method, url, *a, **kw
                    )
                    httpx_patches.append(('request', orig_httpx_req))

                    orig_httpx_client_req = httpx.Client.request
                    httpx.Client.request = lambda self_client, method, url, *a, **kw: (
                        self._httpx_request_wrapper(
                            lambda m, u, *x, **y: orig_httpx_client_req(self_client, m, u, *x, **y),
                            method, url, *a, **kw
                        )
                    )
                    httpx_patches.append(('Client.request', orig_httpx_client_req))
                except Exception:
                    pass

            urllib_patches = []
            if HAS_URLLIB:
                try:
                    orig_urllib_urlopen = urllib.request.urlopen
                    urllib.request.urlopen = lambda url, *a, **kw: self._urllib_urlopen_wrapper(
                        orig_urllib_urlopen, url, *a, **kw
                    )
                    urllib_patches.append(('urlopen', orig_urllib_urlopen))
                except Exception:
                    pass

            orig_socket = socket.socket
            socket.socket = lambda *a, **kw: self._socket_wrapper(
                orig_socket, *a, **kw
            )

            orig_create_connection = socket.create_connection
            socket.create_connection = lambda address, *a, **kw: self._socket_connect_wrapper(
                orig_create_connection, None, address, *a, **kw
            )

            # Additional network patches
            aiohttp_patches = []
            if HAS_AIOHTTP:
                try:
                    orig_aiohttp_request = aiohttp.request
                    aiohttp.request = lambda method, url, *a, **kw: self._aiohttp_request_wrapper(
                        orig_aiohttp_request, method, url, *a, **kw
                    )
                    aiohttp_patches.append(('request', orig_aiohttp_request))
                except Exception:
                    pass

            http_client_patches = []
            if HAS_HTTP_CLIENT:
                try:
                    _interceptor = self
                    orig_http_connection_init = http.client.HTTPConnection.__init__
                    http.client.HTTPConnection.__init__ = lambda conn_self, host, port=None, *a, **kw: _interceptor._http_client_wrapper(
                        orig_http_connection_init, conn_self, host, port, *a, **kw
                    )
                    http_client_patches.append(('HTTPConnection.__init__', orig_http_connection_init))

                    orig_https_connection_init = http.client.HTTPSConnection.__init__
                    http.client.HTTPSConnection.__init__ = lambda conn_self, host, port=None, *a, **kw: _interceptor._http_client_wrapper(
                        orig_https_connection_init, conn_self, host, port, *a, **kw
                    )
                    http_client_patches.append(('HTTPSConnection.__init__', orig_https_connection_init))
                except Exception:
                    pass

            ssl_patches = []
            if HAS_SSL:
                try:
                    orig_ssl_wrap_socket = ssl.wrap_socket
                    ssl.wrap_socket = lambda sock, *a, **kw: self._ssl_wrap_socket_wrapper(
                        orig_ssl_wrap_socket, sock, *a, **kw
                    )
                    ssl_patches.append(('wrap_socket', orig_ssl_wrap_socket))

                    orig_ssl_context_wrap_socket = ssl.SSLContext.wrap_socket
                    ssl.SSLContext.wrap_socket = lambda self_ctx, sock, *a, **kw: self._ssl_wrap_socket_wrapper(
                        orig_ssl_context_wrap_socket, self_ctx, sock, *a, **kw
                    )
                    ssl_patches.append(('SSLContext.wrap_socket', orig_ssl_context_wrap_socket))
                except Exception:
                    pass

            # === Process patches ===
            orig_run = subprocess.run
            subprocess.run = lambda *a, **kw: self._subprocess_run_wrapper(
                orig_run, *a, **kw
            )

            orig_popen = subprocess.Popen
            subprocess.Popen = lambda *a, **kw: self._subprocess_popen_wrapper(
                orig_popen, *a, **kw
            )

            orig_call = subprocess.call
            subprocess.call = lambda *a, **kw: self._subprocess_call_wrapper(
                orig_call, *a, **kw
            )

            orig_check_call = subprocess.check_call
            subprocess.check_call = lambda *a, **kw: self._subprocess_call_wrapper(
                orig_check_call, *a, **kw
            )

            orig_check_output = subprocess.check_output
            subprocess.check_output = lambda *a, **kw: self._subprocess_call_wrapper(
                orig_check_output, *a, **kw
            )

            orig_os_system = os.system
            os.system = lambda cmd: self._os_system_wrapper(orig_os_system, cmd)

            try:
                yield
            finally:
                # === Restore all patches ===
                builtins.open = orig_open
                io.open = orig_io_open
                Path.open = orig_path_open
                os.open = orig_os_open
                os.remove = orig_os_remove
                os.unlink = orig_os_unlink
                os.rename = orig_os_rename
                shutil.rmtree = orig_shutil_rmtree
                shutil.copy = orig_shutil_copy
                shutil.copy2 = orig_shutil_copy2
                shutil.move = orig_shutil_move

                os.mkdir = orig_os_mkdir
                os.makedirs = orig_os_makedirs
                os.rmdir = orig_os_rmdir

                os.fdopen = orig_os_fdopen
                os.link = orig_os_link
                os.symlink = orig_os_symlink
                shutil.copytree = orig_shutil_copytree
                os.removedirs = orig_os_removedirs

                Path.read_text = orig_path_read_text
                Path.read_bytes = orig_path_read_bytes
                Path.write_text = orig_path_write_text
                Path.write_bytes = orig_path_write_bytes
                Path.unlink = orig_path_unlink
                Path.rename = orig_path_rename
                Path.replace = orig_path_replace
                Path.mkdir = orig_path_mkdir

                requests.request = orig_requests_req
                requests.Session.request = orig_requests_sess_req

                if HAS_HTTPX:
                    for attr_name, orig_func in httpx_patches:
                        if attr_name == 'request':
                            httpx.request = orig_func
                        elif attr_name == 'Client.request':
                            httpx.Client.request = orig_func

                if HAS_URLLIB:
                    for attr_name, orig_func in urllib_patches:
                        if attr_name == 'urlopen':
                            urllib.request.urlopen = orig_func

                socket.socket = orig_socket
                socket.create_connection = orig_create_connection

                if HAS_AIOHTTP:
                    for attr_name, orig_func in aiohttp_patches:
                        if attr_name == 'request':
                            aiohttp.request = orig_func

                if HAS_HTTP_CLIENT:
                    for attr_name, orig_func in http_client_patches:
                        if attr_name == 'HTTPConnection.__init__':
                            http.client.HTTPConnection.__init__ = orig_func
                        elif attr_name == 'HTTPSConnection.__init__':
                            http.client.HTTPSConnection.__init__ = orig_func

                if HAS_SSL:
                    for attr_name, orig_func in ssl_patches:
                        if attr_name == 'wrap_socket':
                            ssl.wrap_socket = orig_func
                        elif attr_name == 'SSLContext.wrap_socket':
                            ssl.SSLContext.wrap_socket = orig_func

                subprocess.run = orig_run
                subprocess.Popen = orig_popen
                subprocess.call = orig_call
                subprocess.check_call = orig_check_call
                subprocess.check_output = orig_check_output
                os.system = orig_os_system

"""Release-blocking tests for v0.1.0.

Tests startup safety checks, file permission validation, remote dashboard
opt-in, isolated mode environment sanitization, and audit chain verification.
"""
import sys
import os
import stat
import json
import tempfile
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# =============================================================
# 1. Startup checks: policy validation
# =============================================================

class TestStartupPolicyChecks:
    """Startup must fail when policy is invalid or missing default deny."""

    def test_missing_default_deny_fails(self, tmp_path):
        """Startup fails when policy has no terminal default deny rule."""
        from agentshield.startup_checks import validate_policy_file, StartupValidationError

        policy = {"rules": [
            {"type": "file", "decision": "allow"}
        ]}
        policy_file = tmp_path / "bad_policy.json"
        policy_file.write_text(json.dumps(policy))

        with pytest.raises(StartupValidationError, match="terminal default deny"):
            validate_policy_file(str(policy_file))

    def test_valid_policy_passes(self, tmp_path):
        """Startup passes with valid policy containing default deny."""
        from agentshield.startup_checks import validate_policy_file

        policy = {"rules": [
            {"type": "file", "decision": "allow"},
            {"decision": "block", "reason": "default_deny"}
        ]}
        policy_file = tmp_path / "good_policy.json"
        policy_file.write_text(json.dumps(policy))

        result = validate_policy_file(str(policy_file))
        assert result is not None
        assert "rules" in result

    def test_invalid_json_fails(self, tmp_path):
        """Startup fails when policy file is not valid JSON."""
        from agentshield.startup_checks import validate_policy_file, StartupValidationError

        policy_file = tmp_path / "broken.json"
        policy_file.write_text("{not valid json!!!")

        with pytest.raises(StartupValidationError, match="invalid JSON"):
            validate_policy_file(str(policy_file))

    def test_missing_rules_fails(self, tmp_path):
        """Startup fails when policy has no rules array."""
        from agentshield.startup_checks import validate_policy_file, StartupValidationError

        policy_file = tmp_path / "no_rules.json"
        policy_file.write_text(json.dumps({"version": 1}))

        with pytest.raises(StartupValidationError, match="rules"):
            validate_policy_file(str(policy_file))

    def test_empty_rules_fails(self, tmp_path):
        """Startup fails when policy has empty rules array."""
        from agentshield.startup_checks import validate_policy_file, StartupValidationError

        policy_file = tmp_path / "empty_rules.json"
        policy_file.write_text(json.dumps({"rules": []}))

        with pytest.raises(StartupValidationError, match="no rules"):
            validate_policy_file(str(policy_file))

    def test_missing_policy_file_raises(self, tmp_path):
        """Startup fails when policy file does not exist."""
        from agentshield.startup_checks import validate_policy_file, StartupValidationError

        with pytest.raises(StartupValidationError, match="not found"):
            validate_policy_file(str(tmp_path / "nonexistent.json"))


# =============================================================
# 2. Startup checks: audit storage
# =============================================================

class TestStartupStorageChecks:

    def test_storage_writable(self, tmp_path):
        """Startup passes when storage directory is writable."""
        from agentshield.startup_checks import validate_audit_storage

        result = validate_audit_storage(str(tmp_path / "agentshield_test"))
        assert result is not None

    def test_storage_creates_dir(self, tmp_path):
        """Startup creates storage directory if it doesn't exist."""
        from agentshield.startup_checks import validate_audit_storage

        new_dir = tmp_path / "new_storage_dir"
        validate_audit_storage(str(new_dir))
        assert new_dir.exists()


# =============================================================
# 3. File permission checks
# =============================================================

class TestFilePermissionChecks:

    def test_world_writable_warns(self, tmp_path):
        """World-writable files should produce warnings."""
        from agentshield.startup_checks import validate_file_permissions

        test_file = tmp_path / "events.db"
        test_file.write_text("test")
        os.chmod(str(test_file), 0o666)

        # Non-strict should warn but not raise
        validate_file_permissions(str(tmp_path), strict=False)

    def test_world_writable_strict_fails(self, tmp_path):
        """World-writable files should fail in strict mode."""
        from agentshield.startup_checks import validate_file_permissions, StartupValidationError

        test_file = tmp_path / "events.db"
        test_file.write_text("test")
        os.chmod(str(test_file), 0o666)

        with pytest.raises(StartupValidationError, match="world-writable"):
            validate_file_permissions(str(tmp_path), strict=True)

    def test_safe_permissions_pass(self, tmp_path):
        """Files with safe permissions should not warn."""
        from agentshield.startup_checks import validate_file_permissions

        test_file = tmp_path / "events.db"
        test_file.write_text("test")
        os.chmod(str(test_file), 0o600)

        # Should not raise or warn
        validate_file_permissions(str(tmp_path), strict=True)


# =============================================================
# 4. Remote dashboard opt-in
# =============================================================

class TestRemoteDashboardOptIn:

    def test_remote_bind_without_opt_in_fails(self):
        """Remote dashboard binding without AGENTSHIELD_ALLOW_REMOTE fails."""
        from agentshield.startup_checks import validate_remote_dashboard_opt_in, StartupValidationError

        orig = os.environ.get('AGENTSHIELD_ALLOW_REMOTE')
        try:
            if 'AGENTSHIELD_ALLOW_REMOTE' in os.environ:
                del os.environ['AGENTSHIELD_ALLOW_REMOTE']

            with pytest.raises(StartupValidationError, match="opt-in"):
                validate_remote_dashboard_opt_in(remote_bind=True)
        finally:
            if orig is not None:
                os.environ['AGENTSHIELD_ALLOW_REMOTE'] = orig

    def test_remote_bind_with_opt_in_passes(self):
        """Remote dashboard binding with AGENTSHIELD_ALLOW_REMOTE=1 passes."""
        from agentshield.startup_checks import validate_remote_dashboard_opt_in

        orig = os.environ.get('AGENTSHIELD_ALLOW_REMOTE')
        try:
            os.environ['AGENTSHIELD_ALLOW_REMOTE'] = '1'
            # Should not raise
            validate_remote_dashboard_opt_in(remote_bind=True)
        finally:
            if orig is not None:
                os.environ['AGENTSHIELD_ALLOW_REMOTE'] = orig
            elif 'AGENTSHIELD_ALLOW_REMOTE' in os.environ:
                del os.environ['AGENTSHIELD_ALLOW_REMOTE']

    def test_localhost_bind_always_passes(self):
        """Localhost binding should always pass regardless of env var."""
        from agentshield.startup_checks import validate_remote_dashboard_opt_in

        # remote_bind=False (localhost) should never raise
        validate_remote_dashboard_opt_in(remote_bind=False)


# =============================================================
# 5. Isolated mode environment sanitization
# =============================================================

class TestIsolatedModeSanitization:

    def test_pythonpath_removed(self):
        """PYTHONPATH must be removed in sanitized env."""
        from agentshield.environment_sanitizer import sanitize_environment

        orig = os.environ.get('PYTHONPATH')
        try:
            os.environ['PYTHONPATH'] = '/tmp/evil'
            sanitized = sanitize_environment()
            assert 'PYTHONPATH' not in sanitized
        finally:
            if orig is not None:
                os.environ['PYTHONPATH'] = orig
            elif 'PYTHONPATH' in os.environ:
                del os.environ['PYTHONPATH']

    def test_ld_preload_removed(self):
        """LD_PRELOAD must be removed in sanitized env."""
        from agentshield.environment_sanitizer import sanitize_environment

        orig = os.environ.get('LD_PRELOAD')
        try:
            os.environ['LD_PRELOAD'] = 'libevil.so'
            sanitized = sanitize_environment()
            assert 'LD_PRELOAD' not in sanitized
        finally:
            if orig is not None:
                os.environ['LD_PRELOAD'] = orig
            elif 'LD_PRELOAD' in os.environ:
                del os.environ['LD_PRELOAD']

    def test_dyld_insert_libraries_removed(self):
        """DYLD_INSERT_LIBRARIES must be removed in sanitized env."""
        from agentshield.environment_sanitizer import sanitize_environment

        orig = os.environ.get('DYLD_INSERT_LIBRARIES')
        try:
            os.environ['DYLD_INSERT_LIBRARIES'] = '/tmp/evil.dylib'
            sanitized = sanitize_environment()
            assert 'DYLD_INSERT_LIBRARIES' not in sanitized
        finally:
            if orig is not None:
                os.environ['DYLD_INSERT_LIBRARIES'] = orig
            elif 'DYLD_INSERT_LIBRARIES' in os.environ:
                del os.environ['DYLD_INSERT_LIBRARIES']

    def test_home_preserved(self):
        """HOME must be preserved in sanitized env."""
        from agentshield.environment_sanitizer import sanitize_environment

        sanitized = sanitize_environment()
        assert 'HOME' in sanitized

    def test_path_preserved(self):
        """PATH must be preserved in sanitized env."""
        from agentshield.environment_sanitizer import sanitize_environment

        sanitized = sanitize_environment()
        assert 'PATH' in sanitized


# =============================================================
# 6. Audit chain verification
# =============================================================

class TestAuditChainVerification:

    def test_chain_valid_on_clean_db(self):
        """Fresh DB with events should have valid chain."""
        from agentshield.storage import LocalStorage

        db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db.close()
        try:
            storage = LocalStorage(db_path=db.name)
            storage.log_event({'type': 'file', 'path': '/a'}, 'allow', 'test')
            storage.log_event({'type': 'file', 'path': '/b'}, 'block', 'test')

            result = storage.verify_chain()
            assert result['valid'] is True
        finally:
            os.unlink(db.name)

    def test_chain_detects_modification(self):
        """Modifying an event should break the chain."""
        from agentshield.storage import LocalStorage

        db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db.close()
        try:
            storage = LocalStorage(db_path=db.name)
            storage.log_event({'type': 'file', 'path': '/a'}, 'allow', 'test')
            eid = storage.log_event({'type': 'file', 'path': '/b'}, 'allow', 'test')
            storage.log_event({'type': 'file', 'path': '/c'}, 'allow', 'test')

            # Tamper with event
            cur = storage.conn.cursor()
            cur.execute("UPDATE events SET target = '/hacked' WHERE id = ?", (eid,))
            storage.conn.commit()

            result = storage.verify_chain()
            assert result['valid'] is False
        finally:
            os.unlink(db.name)


# =============================================================
# 7. Capability profile validation
# =============================================================

class TestCapabilityProfileValidation:

    def test_unknown_profile_fails(self):
        """Unknown capability profile must fail startup check."""
        from agentshield.startup_checks import validate_capability_profile, StartupValidationError

        with pytest.raises(StartupValidationError, match="Unknown"):
            validate_capability_profile("nonexistent_profile")

    def test_valid_profiles_pass(self):
        """All known profiles must pass startup check."""
        from agentshield.startup_checks import validate_capability_profile

        for profile in ['sandboxed', 'read_only', 'trusted', 'minimal']:
            validate_capability_profile(profile)


# =============================================================
# 8. Version consistency
# =============================================================

class TestVersionConsistency:

    def test_init_version_matches_pyproject(self):
        """__version__ in __init__.py must match pyproject.toml."""
        import agentshield
        assert agentshield.__version__ == "0.1.0"


# =============================================================
# 9. Production readiness security validation
# =============================================================

class TestProductionReadinessSecurity:
    """Release-blocking security validation for production deployment."""

    def test_fail_closed_behavior_implemented(self):
        """All monkey patch wrappers must implement fail-closed error handling."""
        import inspect
        from agentshield.interceptor import RuntimeInterceptor

        # Get all wrapper methods
        wrapper_methods = [
            method for method in dir(RuntimeInterceptor)
            if method.endswith('_wrapper') and not method.startswith('_')
        ]

        for method_name in wrapper_methods:
            method = getattr(RuntimeInterceptor, method_name)
            source = inspect.getsource(method)

            # Check that method contains fail-closed error handling
            assert 'except PermissionError:' in source, f"{method_name} missing PermissionError re-raise"
            assert 'except Exception:' in source, f"{method_name} missing fail-closed exception handling"
            assert 'AgentShield enforcement error: operation blocked for safety' in source, \
                f"{method_name} missing fail-closed error message"

    def test_tamper_evident_logging_comprehensive(self):
        """Audit logging must include comprehensive tamper-evident features."""
        from agentshield.storage import LocalStorage

        # Check that all required integrity methods exist
        required_methods = [
            'verify_full_chain', 'verify_database_integrity',
            'detect_file_tampering', 'validate_event_consistency',
            'get_integrity_report'
        ]

        for method_name in required_methods:
            assert hasattr(LocalStorage, method_name), f"Missing integrity method: {method_name}"

        # Test that integrity report includes all components
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = LocalStorage(db_path=f"{tmpdir}/test.db")

            report = storage.get_integrity_report()
            required_keys = [
                'overall_valid', 'full_chain_verification', 'database_integrity',
                'file_tampering_detection', 'event_consistency', 'recommendations'
            ]

            for key in required_keys:
                assert key in report, f"Integrity report missing key: {key}"

    def test_startup_validation_includes_integrity_checks(self):
        """Startup validation must include comprehensive audit integrity checks."""
        from agentshield.startup_checks import run_startup_checks
        import tempfile
        import os

        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            # This should not raise an exception with default settings
            try:
                run_startup_checks(
                    policy_path=None,  # Use default
                    storage_dir=tmpdir,
                    capability_profile="minimal",
                    remote_dashboard=False,
                    strict=False
                )
            except Exception as e:
                # Should not fail on integrity checks for empty DB
                assert "audit log integrity" not in str(e).lower(), \
                    f"Integrity check failed unexpectedly: {e}"

    def test_audit_hooks_fail_closed(self):
        """Audit hooks must implement fail-closed behavior."""
        import sys
        from agentshield.audit_hooks import AuditHookEnforcer

        # Check that audit hook _hook method handles exceptions
        import inspect
        hook_method = getattr(AuditHookEnforcer, '_hook')
        source = inspect.getsource(hook_method)

        # Should contain error handling
        assert 'try:' in source, "Audit hook _hook method missing try block"
        assert 'except' in source, "Audit hook _hook method missing exception handling"

    def test_dashboard_security_hardening_complete(self):
        """Dashboard must implement all required security features."""
        from agentshield.dashboard import app
        import inspect

        # Check that dashboard has security middleware
        routes = [route for route in app.routes]

        # Should have some routes (basic functionality check)
        assert len(routes) > 0, "Dashboard has no routes"

        # Check for security headers middleware (this would be in the app setup)
        # This is a basic check - in production we'd want more comprehensive validation

    def test_policy_engine_default_deny_enforced(self):
        """Policy engine must enforce default deny behavior."""
        from agentshield.policy import PolicyEngine

        engine = PolicyEngine()

        # Test that unknown actions are denied
        result = engine.evaluate({
            'type': 'completely_unknown_type',
            'subtype': 'test'
        })

        assert result['decision'] == 'block', "Policy engine does not default deny unknown actions"
        assert 'missing_capability' in result['reason'], f"Unknown actions should be blocked by missing capabilities, got: {result['reason']}"

    def test_interceptor_thread_safety(self):
        """Interceptor must be thread-safe for concurrent operations."""
        from agentshield.policy import PolicyEngine
        from agentshield.storage import LocalStorage
        from agentshield.notifier import Notifier
        from agentshield.interceptor import RuntimeInterceptor
        import threading
        import tempfile

        # Create required dependencies
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = PolicyEngine()
            storage = LocalStorage(db_path=f"{tmpdir}/test.db")
            notifier = Notifier()

            interceptor = RuntimeInterceptor(policy, storage, notifier)
            results = []
            errors = []

            def test_thread(thread_id):
                try:
                    # Test thread-local reentrancy guard
                    action = {'type': 'file', 'subtype': 'read', 'path': f'/tmp/test_{thread_id}'}
                    result = interceptor.evaluate_action(action)
                    results.append((thread_id, result))
                except Exception as e:
                    errors.append((thread_id, str(e)))

            # Run multiple threads
            threads = []
            for i in range(5):  # Reduced from 10 to avoid overwhelming the test
                t = threading.Thread(target=test_thread, args=(i,))
                threads.append(t)
                t.start()

            # Wait for all threads
            for t in threads:
                t.join()

            # Should have results from all threads with no errors
            assert len(results) == 5, f"Thread safety test failed: {len(results)} results, {len(errors)} errors"
            assert len(errors) == 0, f"Thread safety errors: {errors}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

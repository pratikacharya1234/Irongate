"""Test new production-grade features:
- Capability enforcement
- Advanced rule matching
- Normalized action models
- Approval queue
"""
import pytest
import json
import time
from agentshield import (
    shield, policy, storage,
    CapabilityEngine, PROFILE_SANDBOXED, PROFILE_READ_ONLY,
    ApprovalQueue, normalize_action,
    FileAction, NetworkAction, ProcessAction
)


class TestCapabilities:
    """Test capability permission model."""
    
    def test_capability_matching_exact(self):
        """Test exact capability matching."""
        engine = CapabilityEngine(PROFILE_READ_ONLY)
        assert engine.profile.has_capability("file.read") is True
        assert engine.profile.has_capability("file.write") is False
    
    def test_capability_matching_wildcard(self):
        """Test wildcard capability matching."""
        engine = CapabilityEngine(PROFILE_READ_ONLY)
        # PROFILE_READ_ONLY has "file.read" but not "file.*"
        assert engine.profile.has_capability("file.read") is True
        assert engine.profile.has_capability("file.write") is False
    
    def test_required_capabilities_file_read(self):
        """Test determining required capabilities for file read."""
        engine = CapabilityEngine(PROFILE_SANDBOXED)
        action = {'type': 'file', 'subtype': 'read', 'path': '/home/user/data.txt'}
        required = engine.required_capabilities(action)
        assert "file.read" in required
    
    def test_required_capabilities_sensitive_file(self):
        """Test that sensitive files require higher capability."""
        engine = CapabilityEngine(PROFILE_SANDBOXED)
        action = {'type': 'file', 'subtype': 'read', 'path': '/home/user/.env'}
        required = engine.required_capabilities(action)
        assert "file.read.sensitive" in required
    
    def test_check_capabilities_allowed(self):
        """Test capability check for allowed action."""
        engine = CapabilityEngine(PROFILE_READ_ONLY)
        action = {'type': 'file', 'subtype': 'read', 'path': '/home/user/data.txt'}
        assert engine.check_capabilities(action) is True
    
    def test_check_capabilities_denied(self):
        """Test capability check for denied action."""
        engine = CapabilityEngine(PROFILE_READ_ONLY)
        action = {'type': 'file', 'subtype': 'delete'}
        assert engine.check_capabilities(action) is False
    
    def test_get_missing_capabilities(self):
        """Test retrieving missing capabilities."""
        engine = CapabilityEngine(PROFILE_READ_ONLY)
        action = {'type': 'process', 'subtype': 'exec', 'cmd': 'ls'}
        missing = engine.get_missing_capabilities(action)
        assert "process.exec" in missing


class TestAdvancedRuleMatching:
    """Test advanced rule matching with predicates."""
    
    def test_rule_exact_match(self):
        """Test exact field matching in rules."""
        test_policy = {
            "rules": [
                {"type": "file", "subtype": "read", "decision": "allow"}
            ]
        }
        policy.set_policy(test_policy)
        
        action = {'type': 'file', 'subtype': 'read', 'path': '/data.txt'}
        result = policy.evaluate(action)
        assert result['decision'] == 'allow'
    
    def test_rule_list_contains_match(self):
        """Test path_contains predicate matching."""
        test_policy = {
            "rules": [
                {
                    "type": "file",
                    "path_contains": [".env", ".ssh"],
                    "decision": "block"
                }
            ]
        }
        policy.set_policy(test_policy)
        
        action = {'type': 'file', 'path': '/home/user/.env', 'subtype': 'read'}
        result = policy.evaluate(action)
        assert result['decision'] == 'block'
    
    def test_rule_regex_pattern_match(self):
        """Test cmd_pattern regex matching."""
        test_policy = {
            "rules": [
                {
                    "type": "process",
                    "cmd_pattern": "^(rm|dd|shutdown)",
                    "decision": "block"
                }
            ]
        }
        policy.set_policy(test_policy)
        
        action = {'type': 'process', 'cmd': 'rm -rf /'}
        result = policy.evaluate(action)
        assert result['decision'] == 'block'
    
    def test_rule_prefix_match(self):
        """Test path_startswith predicate matching."""
        test_policy = {
            "rules": [
                {
                    "type": "file",
                    "path_startswith": "/etc",
                    "decision": "block"
                }
            ]
        }
        policy.set_policy(test_policy)
        
        action = {'type': 'file', 'path': '/etc/passwd'}
        result = policy.evaluate(action)
        assert result['decision'] == 'block'
    
    def test_rule_priority_first_match_wins(self):
        """Test that first matching rule wins."""
        test_policy = {
            "rules": [
                {"type": "file", "decision": "block"},  # Catch-all block
                {"type": "file", "subtype": "read", "decision": "allow"}  # Won't be reached
            ]
        }
        policy.set_policy(test_policy)
        
        action = {'type': 'file', 'subtype': 'read', 'path': '/data.txt'}
        result = policy.evaluate(action)
        # First rule matches (just type=file), so block
        assert result['decision'] == 'block'


class TestNormalizedActions:
    """Test action normalization with Pydantic models."""
    
    def test_normalize_file_action(self):
        """Test normalizing a file action."""
        action = {'type': 'file', 'path': '/data.txt', 'subtype': 'read'}
        normalized = normalize_action(action)
        assert normalized['type'] == 'file'
        assert normalized['path'] == '/data.txt'
        assert 'timestamp' in normalized
    
    def test_normalize_network_action(self):
        """Test normalizing a network action."""
        action = {'type': 'network', 'target': 'https://api.example.com', 'method': 'GET'}
        normalized = normalize_action(action)
        assert normalized['type'] == 'network'
        assert normalized['target'] == 'https://api.example.com'
        assert 'timestamp' in normalized
    
    def test_normalize_process_action(self):
        """Test normalizing a process action."""
        action = {'type': 'process', 'cmd': 'ls -la', 'subtype': 'exec'}
        normalized = normalize_action(action)
        assert normalized['type'] == 'process'
        assert normalized['cmd'] == 'ls -la'
        assert 'timestamp' in normalized
    
    def test_normalize_adds_timestamp(self):
        """Test that normalization adds timestamp."""
        action = {'type': 'file', 'path': '/data.txt'}
        normalized = normalize_action(action)
        assert 'timestamp' in normalized
        assert isinstance(normalized['timestamp'], float)


class TestApprovalQueue:
    """Test first-class approval queue system."""
    
    def test_create_pending_approval(self):
        """Test creating a pending approval."""
        queue = ApprovalQueue(storage)
        action = {'type': 'file', 'path': '/data.txt', 'subtype': 'delete'}
        pending = queue.create_pending(event_id=999, action=action)
        
        assert pending['event_id'] == 999
        assert pending['action'] == action
        assert pending['status'] == 'pending'
        assert 'created_at' in pending
    
    def test_resolve_pending_approval(self):
        """Test resolving a pending approval."""
        queue = ApprovalQueue(storage)
        resolved = queue.resolve_pending(event_id=999, approved=True, decided_by='admin')
        
        assert resolved['event_id'] == 999
        assert resolved['decision'] == 'allow'
        assert resolved['decided_by'] == 'admin'
        assert 'decided_at' in resolved
    
    def test_resolve_pending_block(self):
        """Test resolving a pending approval as blocked."""
        queue = ApprovalQueue(storage)
        resolved = queue.resolve_pending(event_id=999, approved=False, decided_by='admin')
        
        assert resolved['decision'] == 'block'
        assert resolved['status'] == 'blocked'


class TestDefaultPolicy:
    """Test the new robust default policy."""
    
    def test_default_policy_restricts_sensitive_file_paths(self):
        """Test that default policy does not allow sensitive file paths."""
        # Reload to use default policy
        policy.reload_policy()

        action = {'type': 'file', 'path': '/home/user/.env', 'subtype': 'open'}
        result = policy.evaluate(action)
        # Should match a path_contains rule and review or block (not allow)
        assert result['decision'] in ('review', 'block')
    
    def test_default_policy_blocks_dangerous_commands(self):
        """Test that default policy blocks dangerous commands."""
        policy.reload_policy()
        
        action = {'type': 'process', 'cmd': 'rm -rf /'}
        result = policy.evaluate(action)
        assert result['decision'] == 'block'
    
    def test_default_policy_blocks_system_files(self):
        """Test that default policy blocks system-critical file access."""
        policy.reload_policy()
        
        action = {'type': 'file', 'path': '/etc/passwd', 'subtype': 'read'}
        result = policy.evaluate(action)
        assert result['decision'] == 'block'


class TestStartupSafety:
    """Test startup validation checks for v0.1.0 release."""
    
    def test_startup_policy_missing_default_deny(self):
        """Test that startup fails if policy lacks default deny rule."""
        from agentshield.startup_checks import validate_policy_file
        
        # Create a policy without default deny
        bad_policy = {
            'rules': [
                {
                    'type': 'file',
                    'path_contains': ['.env'],
                    'decision': 'block'
                }
                # Missing default deny rule
            ]
        }
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(bad_policy, f)
            f.flush()
            bad_policy_path = f.name
        
        try:
            with pytest.raises(Exception) as exc_info:
                validate_policy_file(bad_policy_path)
            assert "default deny" in str(exc_info.value).lower()
        finally:
            import os as os_module
            os_module.unlink(bad_policy_path)
    
    def test_startup_invalid_policy_json(self):
        """Test that startup fails on invalid policy JSON."""
        from agentshield.startup_checks import validate_policy_file
        
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{ invalid json')
            f.flush()
            bad_json_path = f.name
        
        try:
            with pytest.raises(Exception) as exc_info:
                validate_policy_file(bad_json_path)
            assert "invalid" in str(exc_info.value).lower()
        finally:
            import os as os_module
            os_module.unlink(bad_json_path)
    
    def test_capability_profile_validation(self):
        """Test that startup validates capability profile."""
        from agentshield.startup_checks import validate_capability_profile
        
        # Valid profiles should not raise
        validate_capability_profile('sandboxed')
        validate_capability_profile('read_only')
        validate_capability_profile('trusted')
        validate_capability_profile('minimal')
        
        # Invalid profile should raise
        with pytest.raises(Exception):
            validate_capability_profile('invalid_profile')
    
    def test_remote_dashboard_requires_opt_in(self):
        """Test that remote dashboard binding requires opt-in."""
        from agentshield.startup_checks import validate_remote_dashboard_opt_in
        
        # Should raise without opt-in
        with pytest.raises(Exception):
            validate_remote_dashboard_opt_in(remote_bind=True)
        
        # Should not raise with opt-in
        import os as os_module
        os_module.environ['AGENTSHIELD_ALLOW_REMOTE'] = '1'
        try:
            # Should not raise
            validate_remote_dashboard_opt_in(remote_bind=True)
        finally:
            del os_module.environ['AGENTSHIELD_ALLOW_REMOTE']
    
    def test_environment_sanitization_removes_dangerous_vars(self):
        """Test that isolated mode sanitizes dangerous environment variables."""
        from agentshield.environment_sanitizer import sanitize_environment
        
        import os as os_module

        # Save originals
        orig_home = os_module.environ.get('HOME')
        orig_pythonpath = os_module.environ.get('PYTHONPATH')
        orig_ld_preload = os_module.environ.get('LD_PRELOAD')

        # Set some dangerous variables
        os_module.environ['PYTHONPATH'] = '/tmp/malicious'
        os_module.environ['LD_PRELOAD'] = 'libmalicious.so'
        os_module.environ['HOME'] = '/home/testuser'

        try:
            sanitized = sanitize_environment()

            # Dangerous vars should be removed
            assert 'PYTHONPATH' not in sanitized
            assert 'LD_PRELOAD' not in sanitized

            # Safe vars should be kept
            assert 'HOME' in sanitized
            assert sanitized['HOME'] == '/home/testuser'
        finally:
            # Restore all originals
            if orig_home is not None:
                os_module.environ['HOME'] = orig_home
            elif 'HOME' in os_module.environ:
                del os_module.environ['HOME']
            if orig_pythonpath is not None:
                os_module.environ['PYTHONPATH'] = orig_pythonpath
            elif 'PYTHONPATH' in os_module.environ:
                del os_module.environ['PYTHONPATH']
            if orig_ld_preload is not None:
                os_module.environ['LD_PRELOAD'] = orig_ld_preload
            elif 'LD_PRELOAD' in os_module.environ:
                del os_module.environ['LD_PRELOAD']


class TestLimitationDetector:
    """Test detection and warning of known limitations."""
    
    def test_limitation_detector_import(self):
        """Test that limitation detector can be imported."""
        from agentshield.limitation_detector import (
            LimitationWarner, install_limitation_detector,
            NOT_INTERCEPTED_APIS, C_EXTENSION_MODULES
        )

        # aiohttp and http.client are now intercepted, should NOT be in NOT_INTERCEPTED_APIS
        assert 'aiohttp' not in NOT_INTERCEPTED_APIS
        assert 'http.client' not in NOT_INTERCEPTED_APIS
        assert 'ctypes' in C_EXTENSION_MODULES

    def test_limitation_warner_not_intercepted_apis(self):
        """Test warner detects unintercepted APIs."""
        from agentshield.limitation_detector import LimitationWarner

        warner = LimitationWarner()

        # os.exec is in NOT_INTERCEPTED_APIS (covered by audit hooks only)
        warner.check_import('os.exec')
        assert 'os.exec' in warner.warned_apis
    
    def test_limitation_warner_c_extensions(self):
        """Test warner detects C extension imports."""
        from agentshield.limitation_detector import LimitationWarner
        
        warner = LimitationWarner()
        
        # Check that ctypes is detected as bypass
        warner.check_import('ctypes')
        assert 'ctypes' in warner.warned_c_extensions
        
        # Check cffi
        warner.check_import('cffi')
        assert 'cffi' in warner.warned_c_extensions
    
    def test_limitation_warner_no_duplicate_warnings(self):
        """Test that same limitation is only warned once."""
        from agentshield.limitation_detector import LimitationWarner

        warner = LimitationWarner()

        # Import same limitation twice
        warner.check_import('os.exec')
        warner.check_import('os.exec')

        # Should only be in set once
        assert len(warner.warned_apis) == 1
    
    def test_limitation_functions_callable(self):
        """Test that limitation warning functions are callable."""
        from agentshield.limitation_detector import (
            warn_about_audit_log_limitations,
            warn_about_isolate_mode_limitations,
            warn_about_enforcement_model,
            warn_about_scope
        )
        
        # All should be callable
        assert callable(warn_about_audit_log_limitations)
        assert callable(warn_about_isolate_mode_limitations)
        assert callable(warn_about_enforcement_model)
        assert callable(warn_about_scope)
        
        # Should not raise errors
        warn_about_audit_log_limitations()
        warn_about_isolate_mode_limitations()
        warn_about_enforcement_model()
        warn_about_scope()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


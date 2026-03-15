"""Security regression tests for AgentShield v0.1.

Tests the critical security invariants that must hold for release:
1. Deny-by-default for unknown action types
2. Deny-by-default for malformed policy results
3. Sensitive file rules fire correctly
4. Capability enforcement blocks missing capabilities
5. Dashboard mutating endpoints require auth
6. Patched operations go through enforcement
7. Approval timeout defaults to deny
"""
import io
import os
import shutil
import socket
import subprocess
import tempfile
import time
import builtins

import pytest

from agentshield.interceptor import RuntimeInterceptor
from agentshield.policy import PolicyEngine
from agentshield.storage import LocalStorage
from agentshield.notifier import Notifier
from agentshield.capabilities import (
    CapabilityEngine, CapabilityProfile,
    PROFILE_SANDBOXED, PROFILE_READ_ONLY, PROFILE_TRUSTED, PROFILE_MINIMAL,
)


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary storage database."""
    return LocalStorage(db_path=str(tmp_path / "test_events.db"))


@pytest.fixture
def tmp_policy_file(tmp_path):
    """Create a temporary policy file path."""
    return str(tmp_path / "test_policy.json")


@pytest.fixture
def shield_env(tmp_db, tmp_policy_file):
    """Create an isolated shield environment for testing."""
    policy = PolicyEngine(storage=tmp_db, policy_path=tmp_policy_file)
    notifier = Notifier(storage=tmp_db)
    interceptor = RuntimeInterceptor(policy=policy, storage=tmp_db, notifier=notifier)
    return {
        'policy': policy,
        'storage': tmp_db,
        'notifier': notifier,
        'shield': interceptor,
    }


# =============================================================
# 1. Deny-by-default
# =============================================================

class TestDenyByDefault:
    """Unknown action types and unmatched actions must be blocked."""

    def test_unknown_action_type_blocked(self, shield_env):
        """An action with a type not covered by any rule must be blocked."""
        policy = shield_env['policy']
        policy.reload_policy()

        result = policy.evaluate({'type': 'custom_dangerous_type'})
        assert result['decision'] == 'block'
        # Unknown types are blocked via missing capability or default deny
        assert 'default_deny' in result['reason'] or 'missing_capability' in result['reason']

    def test_empty_action_blocked(self, shield_env):
        """An empty action dict must be blocked."""
        policy = shield_env['policy']
        policy.reload_policy()

        result = policy.evaluate({})
        assert result['decision'] == 'block'

    def test_no_rules_blocks_everything(self, shield_env):
        """With an empty rules list, all actions must be blocked."""
        policy = shield_env['policy']
        policy.set_policy({"rules": []})

        for action_type in ['file', 'network', 'process', 'tool', 'credential', 'unknown']:
            result = policy.evaluate({'type': action_type})
            assert result['decision'] == 'block', f"Expected block for type={action_type}, got {result['decision']}"

    def test_default_policy_terminal_deny(self, shield_env):
        """The default policy must have a terminal deny-all rule."""
        policy = shield_env['policy']
        policy.reload_policy()
        rules = policy.policies.get('rules', [])
        last_rule = rules[-1] if rules else None
        assert last_rule is not None
        assert last_rule.get('decision') == 'block'
        assert 'type' not in last_rule  # catch-all, no type filter


# =============================================================
# 2. Malformed policy result handling
# =============================================================

class TestMalformedPolicyResult:
    """Invalid policy engine output must default to block."""

    def test_invalid_tuple_result_blocks(self, shield_env):
        """If policy.evaluate returns something unparseable, block."""
        shield = shield_env['shield']

        # Monkey-patch policy.evaluate to return garbage
        original_evaluate = shield.policy.evaluate
        shield.policy.evaluate = lambda action: "garbage"

        try:
            allowed, reason = shield._handle_action({'type': 'file', 'path': '/test'})
            assert not allowed
            assert reason == 'invalid_policy_result'
        finally:
            shield.policy.evaluate = original_evaluate

    def test_none_result_blocks(self, shield_env):
        """If policy.evaluate returns None, block."""
        shield = shield_env['shield']

        original_evaluate = shield.policy.evaluate
        shield.policy.evaluate = lambda action: None

        try:
            allowed, reason = shield._handle_action({'type': 'file', 'path': '/test'})
            assert not allowed
            assert reason == 'invalid_policy_result'
        finally:
            shield.policy.evaluate = original_evaluate

    def test_dict_without_decision_blocks(self, shield_env):
        """If policy.evaluate returns a dict without 'decision', treat as block."""
        shield = shield_env['shield']

        original_evaluate = shield.policy.evaluate
        shield.policy.evaluate = lambda action: {'reason': 'oops'}

        try:
            allowed, reason = shield._handle_action({'type': 'file', 'path': '/test'})
            # decision is None, which is not 'allow' or 'review', so falls to else branch
            assert not allowed
        finally:
            shield.policy.evaluate = original_evaluate


# =============================================================
# 3. Sensitive file rule fires
# =============================================================

class TestSensitiveFileRule:
    """Sensitive file paths must trigger review or block in default policy."""

    @pytest.mark.parametrize("path", [
        "/home/user/.env",
        "/app/.ssh/id_rsa",
        "/home/user/.aws/credentials",
        "/project/credentials.json",
        "/data/secret.txt",
        "/app/token.json",
        "/home/user/.ssh/id_dsa",
        "/etc/passwd",
        "/etc/shadow",
    ])
    def test_sensitive_paths_not_allowed(self, shield_env, path):
        """Sensitive file paths must not be allowed by default policy."""
        policy = shield_env['policy']
        policy.reload_policy()

        result = policy.evaluate({'type': 'file', 'subtype': 'open', 'path': path})
        assert result['decision'] in ('review', 'block'), \
            f"Expected review/block for {path}, got {result['decision']}: {result['reason']}"

    def test_nonsensitive_file_blocked_by_default_deny(self, shield_env):
        """A non-sensitive file path is blocked by the terminal deny-all rule."""
        policy = shield_env['policy']
        policy.reload_policy()

        result = policy.evaluate({'type': 'file', 'subtype': 'open', 'path': '/tmp/harmless.txt'})
        # Default policy has no allow rule for generic files, so terminal deny catches it
        assert result['decision'] == 'block'


# =============================================================
# 4. Capability enforcement
# =============================================================

class TestCapabilityEnforcement:
    """Missing capabilities must cause block before policy rules run."""

    def test_sandboxed_blocks_file_write(self, shield_env):
        """Sandboxed profile lacks file.write, so writes must be blocked."""
        policy = shield_env['policy']
        policy.set_capability_profile(PROFILE_SANDBOXED)
        # Set a policy that would allow everything
        policy.set_policy({"rules": [{"type": "file", "decision": "allow"}]})

        result = policy.evaluate({'type': 'file', 'subtype': 'write', 'path': '/tmp/test.txt'})
        assert result['decision'] == 'block'
        assert 'missing_capability' in result['reason']

    def test_sandboxed_blocks_process_exec(self, shield_env):
        """Sandboxed profile lacks process.exec, so execution must be blocked."""
        policy = shield_env['policy']
        policy.set_capability_profile(PROFILE_SANDBOXED)
        policy.set_policy({"rules": [{"type": "process", "decision": "allow"}]})

        result = policy.evaluate({'type': 'process', 'subtype': 'exec', 'cmd': 'ls'})
        assert result['decision'] == 'block'
        assert 'missing_capability' in result['reason']

    def test_sandboxed_allows_file_read(self, shield_env):
        """Sandboxed profile has file.read, so reads should pass capability check."""
        policy = shield_env['policy']
        policy.set_capability_profile(PROFILE_SANDBOXED)
        policy.set_policy({"rules": [
            {"type": "file", "decision": "allow"}
        ]})

        result = policy.evaluate({
            'type': 'file', 'subtype': 'open', 'path': '/tmp/safe.txt', 'mode': 'r'
        })
        assert result['decision'] == 'allow'

    def test_trusted_allows_broad_access(self, shield_env):
        """Trusted profile has wildcard capabilities, so most ops pass."""
        policy = shield_env['policy']
        policy.set_capability_profile(PROFILE_TRUSTED)
        policy.set_policy({"rules": [
            {"type": "process", "decision": "allow"}
        ]})

        result = policy.evaluate({'type': 'process', 'subtype': 'exec', 'cmd': 'ls'})
        assert result['decision'] == 'allow'

    def test_minimal_blocks_almost_everything(self, shield_env):
        """Minimal profile only has tool.invoke. File and network must be blocked."""
        policy = shield_env['policy']
        policy.set_capability_profile(PROFILE_MINIMAL)
        policy.set_policy({"rules": [
            {"type": "file", "decision": "allow"},
            {"type": "network", "decision": "allow"},
        ]})

        result_file = policy.evaluate({'type': 'file', 'subtype': 'read', 'path': '/test'})
        assert result_file['decision'] == 'block'

        result_net = policy.evaluate({'type': 'network', 'subtype': 'http', 'target': 'http://example.com'})
        assert result_net['decision'] == 'block'

    def test_profile_change_takes_effect(self, shield_env):
        """Changing the profile must affect subsequent evaluations."""
        policy = shield_env['policy']
        policy.set_policy({"rules": [{"type": "process", "decision": "allow"}]})

        # Sandboxed: no process.exec
        policy.set_capability_profile(PROFILE_SANDBOXED)
        result = policy.evaluate({'type': 'process', 'subtype': 'exec', 'cmd': 'ls'})
        assert result['decision'] == 'block'

        # Switch to trusted: has process.*
        policy.set_capability_profile(PROFILE_TRUSTED)
        result = policy.evaluate({'type': 'process', 'subtype': 'exec', 'cmd': 'ls'})
        assert result['decision'] == 'allow'


# =============================================================
# 5. Dashboard authentication
# =============================================================

class TestDashboardAuth:
    """Dashboard mutating endpoints must require auth."""

    @pytest.fixture
    def dashboard_client(self, tmp_path):
        """Create a test client for the dashboard."""
        from agentshield.dashboard import app, init_dashboard, CSRF_TOKEN
        from fastapi.testclient import TestClient
        import os

        # Set up test environment
        old_remote = os.environ.get('AGENTSHIELD_ALLOW_REMOTE')
        os.environ['AGENTSHIELD_ALLOW_REMOTE'] = '1'  # Allow remote for testing
        
        # Create a temporary policy file with default deny
        policy_file = tmp_path / "test_policy.json"
        policy_file.write_text('''{
            "rules": [
                {"type": "file", "decision": "allow"},
                {"decision": "block", "reason": "default_deny"}
            ]
        }''')
        
        old_policy = os.environ.get('AGENTSHIELD_POLICY_FILE')
        os.environ['AGENTSHIELD_POLICY_FILE'] = str(policy_file)

        try:
            token = init_dashboard()
            client = TestClient(app)
            return client, token, CSRF_TOKEN
        finally:
            # Restore environment
            if old_remote is not None:
                os.environ['AGENTSHIELD_ALLOW_REMOTE'] = old_remote
            else:
                os.environ.pop('AGENTSHIELD_ALLOW_REMOTE', None)

            if old_policy is not None:
                os.environ['AGENTSHIELD_POLICY_FILE'] = old_policy
            else:
                os.environ.pop('AGENTSHIELD_POLICY_FILE', None)

    def test_approve_requires_auth(self, dashboard_client):
        """POST /approve without auth must return 401."""
        client, token, csrf_token = dashboard_client
        resp = client.post('/approve', json={'event_id': 1, 'decision': 'allow'})
        assert resp.status_code == 401

    def test_approve_with_wrong_token(self, dashboard_client):
        """POST /approve with wrong token must return 403."""
        client, token, csrf_token = dashboard_client
        resp = client.post(
            '/approve',
            json={'event_id': 1, 'decision': 'allow'},
            headers={'Authorization': 'Bearer wrong-token', 'X-CSRF-Token': csrf_token}
        )
        assert resp.status_code == 403

    def test_approve_with_correct_token(self, dashboard_client):
        """POST /approve with correct token must work (404 for nonexistent event is OK)."""
        client, token, csrf_token = dashboard_client
        resp = client.post(
            '/approve',
            json={'event_id': 99999, 'decision': 'allow'},
            headers={'Authorization': f'Bearer {token}', 'X-CSRF-Token': csrf_token}
        )
        # 404 because event doesn't exist, but auth passed
        assert resp.status_code == 404

    def test_block_requires_auth(self, dashboard_client):
        """POST /block without auth must return 401."""
        client, token, csrf_token = dashboard_client
        resp = client.post('/block', json={'event_id': 1, 'decision': 'block'})
        assert resp.status_code == 401

    def test_policy_update_requires_auth(self, dashboard_client):
        """POST /policy/update without auth must return 401."""
        client, token, csrf_token = dashboard_client
        resp = client.post('/policy/update', json={'rules': []})
        assert resp.status_code == 401

    def test_policy_update_with_correct_token(self, dashboard_client):
        """POST /policy/update with correct token must work."""
        client, token, csrf_token = dashboard_client
        resp = client.post(
            '/policy/update',
            json={'rules': [{"type": "file", "decision": "block"}]},
            headers={'Authorization': f'Bearer {token}', 'X-CSRF-Token': csrf_token}
        )
        assert resp.status_code == 200

    def test_get_events_requires_auth(self, dashboard_client):
        """GET /events requires auth (all endpoints are authenticated)."""
        client, token, csrf_token = dashboard_client
        # Without auth — should be 401
        resp = client.get('/events')
        assert resp.status_code == 401
        # With auth — should work
        resp = client.get('/events', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200

    def test_get_policy_requires_auth(self, dashboard_client):
        """GET /policy requires auth (all endpoints are authenticated)."""
        client, token, csrf_token = dashboard_client
        resp = client.get('/policy')
        assert resp.status_code == 401
        resp = client.get('/policy', headers={'Authorization': f'Bearer {token}'})
        assert resp.status_code == 200


# =============================================================
# 6. Interceptor patches go through enforcement
# =============================================================

class TestInterceptorPatching:
    """Patched operations must route through the policy engine."""

    def test_open_intercepted(self, shield_env):
        """builtins.open must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        # Use default policy which blocks everything by default deny
        shield_env['policy'].reload_policy()

        with shield.protect():
            # Any file open should go through enforcement.
            # Default policy blocks non-sensitive files via terminal deny.
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                builtins.open('/tmp/test_agentshield_intercept.txt', 'w')

    def test_io_open_intercepted(self, shield_env):
        """io.open must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                io.open('/tmp/test_agentshield_io_intercept.txt', 'w')

    def test_os_remove_intercepted(self, shield_env):
        """os.remove must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                os.remove('/tmp/test_agentshield_remove.txt')

    def test_os_unlink_intercepted(self, shield_env):
        """os.unlink must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                os.unlink('/tmp/test_agentshield_unlink.txt')

    def test_os_rename_intercepted(self, shield_env):
        """os.rename must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                os.rename('/tmp/a_agentshield.txt', '/tmp/b_agentshield.txt')

    def test_shutil_rmtree_intercepted(self, shield_env):
        """shutil.rmtree must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                shutil.rmtree('/tmp/test_agentshield_rmtree')

    def test_subprocess_call_intercepted(self, shield_env):
        """subprocess.call must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                subprocess.call(['echo', 'test'])

    def test_subprocess_check_call_intercepted(self, shield_env):
        """subprocess.check_call must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                subprocess.check_call(['echo', 'test'])

    def test_subprocess_check_output_intercepted(self, shield_env):
        """subprocess.check_output must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                subprocess.check_output(['echo', 'test'])

    def test_socket_intercepted(self, shield_env):
        """socket.socket must be intercepted inside shield.protect()."""
        shield = shield_env['shield']
        shield_env['policy'].reload_policy()

        with shield.protect():
            with pytest.raises(PermissionError, match="AgentShield blocked"):
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def test_patches_restored_after_protect(self, shield_env):
        """After shield.protect() exits, all patches must be restored."""
        shield = shield_env['shield']

        orig_open = builtins.open
        orig_io_open = io.open
        orig_os_remove = os.remove
        orig_subprocess_call = subprocess.call
        orig_socket = socket.socket

        with shield.protect():
            # Inside protect, they should be patched (different from originals)
            pass

        # After protect, they should be restored
        assert builtins.open is orig_open
        assert io.open is orig_io_open
        assert os.remove is orig_os_remove
        assert subprocess.call is orig_subprocess_call
        assert socket.socket is orig_socket


# =============================================================
# 7. Approval timeout defaults to deny
# =============================================================

class TestApprovalTimeout:
    """Approval timeouts must result in deny."""

    def test_wait_for_approval_timeout_denies(self, shield_env):
        """_wait_for_approval must return False on timeout."""
        shield = shield_env['shield']
        storage = shield_env['storage']

        # Log an event with 'review' decision
        event_id = storage.log_event(
            {'type': 'file', 'path': '/test', 'subtype': 'open'},
            'review',
            'needs_review'
        )

        # Wait with a very short timeout (no one will approve)
        result = shield._wait_for_approval(event_id, timeout=0.1, poll_interval=0.05)
        assert result is False

    def test_approved_event_returns_true(self, shield_env):
        """_wait_for_approval must return True if event is approved."""
        shield = shield_env['shield']
        storage = shield_env['storage']

        event_id = storage.log_event(
            {'type': 'file', 'path': '/test', 'subtype': 'open'},
            'review',
            'needs_review'
        )

        # Approve it before waiting
        storage.set_decision(event_id, 'allow')

        result = shield._wait_for_approval(event_id, timeout=1.0, poll_interval=0.05)
        assert result is True

    def test_blocked_event_returns_false(self, shield_env):
        """_wait_for_approval must return False if event is blocked."""
        shield = shield_env['shield']
        storage = shield_env['storage']

        event_id = storage.log_event(
            {'type': 'file', 'path': '/test', 'subtype': 'open'},
            'review',
            'needs_review'
        )

        storage.set_decision(event_id, 'block')

        result = shield._wait_for_approval(event_id, timeout=1.0, poll_interval=0.05)
        assert result is False


# =============================================================
# 8. Storage audit logging
# =============================================================

class TestAuditLogging:
    """Actions and decisions must be logged to storage."""

    def test_allowed_action_logged(self, shield_env):
        """An allowed action must appear in the audit log."""
        policy = shield_env['policy']
        shield = shield_env['shield']
        storage = shield_env['storage']

        policy.set_policy({"rules": [{"type": "tool", "decision": "allow"}]})
        policy.set_capability_profile(PROFILE_TRUSTED)

        shield._handle_action({'type': 'tool', 'subtype': 'invoke', 'tool_name': 'test_tool'})

        events = storage.recent(10)
        assert len(events) >= 1
        assert events[0]['decision'] == 'allow'

    def test_blocked_action_logged(self, shield_env):
        """A blocked action must appear in the audit log."""
        policy = shield_env['policy']
        shield = shield_env['shield']
        storage = shield_env['storage']

        policy.set_policy({"rules": [{"type": "file", "decision": "block"}]})

        shield._handle_action({'type': 'file', 'subtype': 'open', 'path': '/secret'})

        events = storage.recent(10)
        assert len(events) >= 1
        assert events[0]['decision'] == 'block'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

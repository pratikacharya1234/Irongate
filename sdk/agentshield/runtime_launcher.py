"""Runtime Launcher: Execute scripts/agents within the protected runtime.

Provides a simplified interface to execute arbitrary Python scripts or agent code
with AgentShield enforcement enabled. All file, network, process, and tool operations
are intercepted and enforced according to the active policy.

Usage:
    from agentshield.runtime_launcher import launch_protected_script
    
    launch_protected_script(
        script_path='agent_script.py',
        agent_name='my_agent',
        capability_profile='sandboxed',
        policy_file=None  # Use default
    )
"""
import sys
import runpy
import argparse
import subprocess
import os
import json
from pathlib import Path
from typing import Optional

from . import shield, policy, storage
from .capabilities import (
    CapabilityEngine, PROFILE_SANDBOXED, PROFILE_READ_ONLY,
    PROFILE_TRUSTED, PROFILE_MINIMAL, CapabilityProfile
)
from .audit_hooks import install_audit_hooks, is_available as audit_hooks_available
from .startup_checks import run_startup_checks, StartupValidationError
from .environment_sanitizer import sanitize_environment


# Predefined profiles accessible by name
PROFILES_BY_NAME = {
    'sandboxed': PROFILE_SANDBOXED,
    'read_only': PROFILE_READ_ONLY,
    'trusted': PROFILE_TRUSTED,
    'minimal': PROFILE_MINIMAL,
}


def load_capability_profile(profile_name_or_obj) -> CapabilityProfile:
    """Load a capability profile by name or return the object directly.
    
    Args:
        profile_name_or_obj: Profile name string or CapabilityProfile instance
        
    Returns:
        CapabilityProfile instance
    """
    if isinstance(profile_name_or_obj, CapabilityProfile):
        return profile_name_or_obj
    
    if isinstance(profile_name_or_obj, str):
        if profile_name_or_obj in PROFILES_BY_NAME:
            return PROFILES_BY_NAME[profile_name_or_obj]
        raise ValueError(f"Unknown profile: {profile_name_or_obj}. Available: {list(PROFILES_BY_NAME.keys())}")
    
    raise TypeError(f"Profile must be string or CapabilityProfile, got {type(profile_name_or_obj)}")


def launch_protected_script(
    script_path: str,
    agent_name: Optional[str] = None,
    capability_profile: str = 'sandboxed',
    policy_file: Optional[str] = None,
    log_events: bool = True,
    isolate: bool = False
) -> int:
    """Execute a Python script within the protected AgentShield runtime.

    All file, network, process, and tool operations are intercepted and enforced
    according to the active policy and capability profile.

    Args:
        script_path: Path to Python script to execute
        agent_name: Name of the agent (for audit logging)
        capability_profile: Capability profile name ('sandboxed', 'read_only', 'trusted', 'minimal')
        policy_file: Optional path to policy file (uses default if None)
        log_events: Whether to log all events to storage (default True)
        isolate: If True, run agent in a child Python process for OS-level isolation

    Returns:
        Exit code from the script (0 on success, 1+ on error)

    Raises:
        FileNotFoundError: If script doesn't exist
        ValueError: If profile name is unknown
    """
    # Validate script exists
    script_file = Path(script_path)
    if not script_file.exists():
        print(f"Error: Script not found: {script_path}", file=sys.stderr)
        return 1
    
    if not script_file.is_file():
        print(f"Error: Not a file: {script_path}", file=sys.stderr)
        return 1
    
    # Load policy if specified
    if policy_file:
        policy_path = Path(policy_file)
        if policy_path.exists():
            try:
                with open(policy_path, 'r') as f:
                    import json
                    custom_policy = json.load(f)
                    policy.set_policy(custom_policy)
            except Exception as e:
                print(f"Error loading policy file: {e}", file=sys.stderr)
                return 1
    
    # Load capability profile
    try:
        profile = load_capability_profile(capability_profile)
    except (ValueError, TypeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    # Apply the selected capability profile to the policy engine
    policy.set_capability_profile(profile)

    # Run startup safety checks (fail closed)
    try:
        run_startup_checks(
            policy_file=policy_file,
            capability_profile=capability_profile,
        )
    except StartupValidationError as e:
        print(f"[AgentShield] STARTUP CHECK FAILED:\n{e}", file=sys.stderr)
        return 1

    # Store agent context for logging
    agent_context = {
        'agent_name': agent_name or 'unknown',
        'profile': profile.name,
        'script': str(script_file.absolute())
    }

    # Execute script within protected runtime
    try:
        print(f"[AgentShield] Launching agent: {agent_context['agent_name']}")
        print(f"[AgentShield] Profile: {agent_context['profile']}")
        print(f"[AgentShield] Script: {agent_context['script']}")

        # Install audit hooks BEFORE agent code runs (if available)
        if audit_hooks_available():
            install_audit_hooks(shield.evaluate_action)
            print(f"[AgentShield] Audit hooks: enabled (sys.addaudithook)")
        else:
            print(f"[AgentShield] Audit hooks: unavailable (Python < 3.8)")

        print(f"[AgentShield] Monkeypatch interception: enabled")
        print(f"[AgentShield] All operations will be enforced according to policy")
        print()

        if isolate:
            # Child-process isolation: run agent in a separate Python interpreter
            return _launch_isolated(
                script_file, agent_context, profile, policy_file
            )

        # In-process execution with monkeypatch + audit hook enforcement
        with shield.protect():
            script_abs = str(script_file.absolute())
            try:
                exit_code = runpy.run_path(script_abs, run_name='__main__')
                return 0
            except SystemExit as e:
                return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except PermissionError as e:
                print(f"[AgentShield] Blocked: {e}", file=sys.stderr)
                return 1
            except Exception as e:
                print(f"[AgentShield] Script execution failed: {e}", file=sys.stderr)
                if '--verbose' in sys.argv or '-v' in sys.argv:
                    import traceback
                    traceback.print_exc()
                return 1

    except Exception as e:
        print(f"[AgentShield] Runtime error: {e}", file=sys.stderr)
        return 1

    finally:
        if log_events:
            try:
                events = storage.recent(limit=1000)
                blocked_count = sum(1 for e in events if e.get('decision') == 'block')
                reviewed_count = sum(1 for e in events if e.get('decision') == 'review')
                if blocked_count > 0 or reviewed_count > 0:
                    print()
                    print(f"[AgentShield] Execution summary:")
                    print(f"  - Blocked operations: {blocked_count}")
                    print(f"  - Reviewed operations: {reviewed_count}")
                    print(f"  - Total events logged: {len(events)}")
            except Exception:
                pass


def _launch_isolated(
    script_file: Path,
    agent_context: dict,
    profile: 'CapabilityProfile',
    policy_file: Optional[str] = None,
) -> int:
    """Launch agent script in a child Python process with AgentShield bootstrap.

    The child process imports agentshield, installs audit hooks and monkeypatches,
    then executes the agent script. This provides process-level isolation: if the
    agent crashes, the parent is unaffected. The child inherits the parent's
    AgentShield policy and capability profile via environment variables.

    Args:
        script_file: Path to the agent script
        agent_context: Dict with agent_name, profile, script
        profile: CapabilityProfile to enforce
        policy_file: Optional path to custom policy file

    Returns:
        Exit code from the child process
    """
    print(f"[AgentShield] Isolation mode: child process")

    # Sanitize environment: remove dangerous loader vars (PYTHONPATH, LD_PRELOAD, etc.)
    child_env = sanitize_environment()
    child_env["AGENTSHIELD_PROFILE"] = profile.name
    child_env["AGENTSHIELD_AGENT_NAME"] = agent_context.get("agent_name", "unknown")
    child_env["AGENTSHIELD_ENFORCE"] = "1"
    if policy_file:
        child_env["AGENTSHIELD_POLICY_FILE"] = str(policy_file)

    # Build the bootstrap command: import agentshield, set up enforcement,
    # then run the target script
    script_abs = str(script_file.absolute())
    bootstrap_code = _generate_bootstrap_code(script_abs)

    try:
        # Use the same Python interpreter as the parent
        result = subprocess.run(
            [sys.executable, "-c", bootstrap_code],
            env=child_env,
            close_fds=True,
            timeout=3600,  # 1 hour max
        )
        return result.returncode
    except subprocess.TimeoutExpired:
        print(f"[AgentShield] Child process timed out after 3600s", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[AgentShield] Failed to launch isolated process: {e}", file=sys.stderr)
        return 1


def _generate_bootstrap_code(script_path: str) -> str:
    """Generate Python bootstrap code that the child process executes.

    This code:
    1. Imports agentshield
    2. Reads configuration from environment variables
    3. Installs audit hooks (before agent code)
    4. Applies monkeypatch interception
    5. Runs the agent script via runpy.run_path
    """
    # Escape the script path for embedding in Python source
    escaped_path = script_path.replace("\\", "\\\\").replace("'", "\\'")

    return f"""
import sys
import os
import runpy

# Import AgentShield and set up enforcement
from agentshield import shield, policy, storage
from agentshield.runtime_launcher import load_capability_profile
from agentshield.audit_hooks import install_audit_hooks, is_available

# Read configuration from environment
profile_name = os.environ.get("AGENTSHIELD_PROFILE", "sandboxed")
agent_name = os.environ.get("AGENTSHIELD_AGENT_NAME", "unknown")
policy_file = os.environ.get("AGENTSHIELD_POLICY_FILE")

# Apply capability profile
profile = load_capability_profile(profile_name)
policy.set_capability_profile(profile)

# Load custom policy if specified
if policy_file and os.path.exists(policy_file):
    import json
    with open(policy_file, 'r') as f:
        custom_policy = json.load(f)
        policy.set_policy(custom_policy)

# Install audit hooks BEFORE agent code runs
if is_available():
    install_audit_hooks(shield.evaluate_action)

# Run agent script under monkeypatch protection
try:
    with shield.protect():
        runpy.run_path('{escaped_path}', run_name='__main__')
except SystemExit as e:
    sys.exit(e.code if isinstance(e.code, int) else (0 if e.code is None else 1))
except PermissionError as e:
    print(f"[AgentShield] Blocked: {{e}}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"[AgentShield] Script failed: {{e}}", file=sys.stderr)
    sys.exit(1)
"""


def main():
    """CLI entrypoint for agentshield run command."""
    parser = argparse.ArgumentParser(
        description='Execute a Python script within the protected AgentShield runtime',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  agentshield run script.py
  agentshield run script.py --agent-name my_agent
  agentshield run script.py --profile read_only
  agentshield run script.py --policy custom_policy.json --verbose
        """
    )
    
    parser.add_argument(
        'script',
        help='Path to Python script to execute'
    )
    
    parser.add_argument(
        '--agent-name',
        default=None,
        help='Name of the agent (for audit logging, default: script basename)'
    )
    
    parser.add_argument(
        '--profile',
        default='sandboxed',
        choices=list(PROFILES_BY_NAME.keys()),
        help='Capability profile to use (default: sandboxed)'
    )
    
    parser.add_argument(
        '--policy',
        default=None,
        help='Path to custom policy file (default: ~/.agentshield/policies.json)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output and full exception tracing'
    )

    parser.add_argument(
        '--isolate',
        action='store_true',
        help='Run agent in a child Python process for process-level isolation'
    )

    args = parser.parse_args()

    # Use script basename as default agent name
    if not args.agent_name:
        args.agent_name = Path(args.script).stem

    # Launch the script
    exit_code = launch_protected_script(
        script_path=args.script,
        agent_name=args.agent_name,
        capability_profile=args.profile,
        policy_file=args.policy,
        log_events=True,
        isolate=args.isolate
    )
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()

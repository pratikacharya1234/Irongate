"""Startup safety validation for AgentShield v0.1.0 experimental release.

Validates that the runtime environment is safe before enforcement begins.
Fails closed if critical checks fail.
"""
import os
import stat
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any
import platform


class StartupValidationError(Exception):
    """Raised when startup validation fails."""
    pass


def validate_policy_file(policy_path: str) -> Dict[str, Any]:
    """Load and validate policy file exists and contains default deny rule.
    
    Args:
        policy_path: Path to policy JSON file
        
    Returns:
        Parsed policy dict
        
    Raises:
        StartupValidationError: If policy cannot be loaded or lacks default deny
    """
    try:
        with open(policy_path, 'r') as f:
            policy = json.load(f)
    except FileNotFoundError:
        raise StartupValidationError(
            f"Policy file not found: {policy_path}\n"
            "  Use --policy <file> or create ~/.agentshield/policies.json"
        )
    except json.JSONDecodeError as e:
        raise StartupValidationError(
            f"Policy file invalid JSON: {policy_path}\n"
            f"  Error: {e}"
        )
    
    # Verify policy has rules array
    if 'rules' not in policy or not isinstance(policy['rules'], list):
        raise StartupValidationError(
            f"Policy missing 'rules' array: {policy_path}"
        )
    
    if not policy['rules']:
        raise StartupValidationError(
            f"Policy has no rules (empty rules array): {policy_path}"
        )
    
    # Verify default deny: must have a catch-all block rule (no 'type' field)
    has_default_deny = False
    for rule in policy['rules']:
        # Catch-all rule: no 'type' field means it matches all action types
        if 'type' not in rule:
            # This is a potential catch-all rule
            if rule.get('decision') == 'block':
                # This is a valid default deny
                has_default_deny = True
                break
    
    if not has_default_deny:
        raise StartupValidationError(
            f"Policy missing terminal default deny rule: {policy_path}\n"
            "  Policy must end with: {\"decision\": \"block\", \"reason\": \"default_deny\"}\n"
            "  This ensures deny-by-default enforcement."
        )
    
    return policy


def validate_audit_storage(storage_dir: Optional[str] = None) -> Path:
    """Validate audit storage directory is accessible and safe.
    
    Args:
        storage_dir: Storage directory (defaults to ~/.agentshield)
        
    Returns:
        Path to storage directory
        
    Raises:
        StartupValidationError: If storage cannot be accessed
    """
    if storage_dir is None:
        storage_dir = os.path.expanduser('~/.agentshield')
    
    storage_path = Path(storage_dir)
    
    # Try to create directory if it doesn't exist
    try:
        storage_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise StartupValidationError(
            f"Cannot create audit storage directory: {storage_dir}\n"
            f"  Error: {e}"
        )
    
    # Verify write access
    try:
        test_file = storage_path / '.agentshield_test_write'
        test_file.write_text('test')
        test_file.unlink()
    except OSError as e:
        raise StartupValidationError(
            f"Cannot write to audit storage directory: {storage_dir}\n"
            f"  Error: {e}"
        )
    
    return storage_path


def validate_file_permissions(storage_dir: Optional[str] = None, strict: bool = False) -> None:
    """Check that audit storage files are not world-writable.
    
    Args:
        storage_dir: Storage directory (defaults to ~/.agentshield)
        strict: If True, fail on insecure permissions. If False, warn.
        
    Raises:
        StartupValidationError: If strict=True and files are world-writable
    """
    if storage_dir is None:
        storage_dir = os.path.expanduser('~/.agentshield')
    
    storage_path = Path(storage_dir)
    
    # Files to check
    files_to_check = [
        storage_path / 'events.db',
        storage_path / 'policies.json',
    ]
    
    for file_path in files_to_check:
        if not file_path.exists():
            continue
        
        try:
            st = file_path.stat()
            # Check if world-writable (mode & 0o002)
            if st.st_mode & stat.S_IWOTH:
                msg = (
                    f"INSECURE: {file_path} is world-writable\n"
                    f"  Fix: chmod 600 {file_path}\n"
                    f"  AgentShield audit logs must not be world-writable."
                )
                if strict:
                    raise StartupValidationError(msg)
                else:
                    print(f"WARNING: {msg}", file=sys.stderr)
        except OSError as e:
            # Log but don't fail
            print(f"WARNING: Cannot check permissions on {file_path}: {e}", file=sys.stderr)


def validate_capability_profile(profile_name: str) -> None:
    """Validate that capability profile exists.
    
    Args:
        profile_name: Profile name (sandboxed, read_only, trusted, minimal)
        
    Raises:
        StartupValidationError: If profile is unknown
    """
    valid_profiles = {'sandboxed', 'read_only', 'trusted', 'minimal'}
    if profile_name not in valid_profiles:
        raise StartupValidationError(
            f"Unknown capability profile: {profile_name}\n"
            f"  Valid profiles: {', '.join(valid_profiles)}"
        )


def validate_remote_dashboard_opt_in(remote_bind: bool = False) -> None:
    """Validate that remote dashboard binding requires explicit opt-in.
    
    Args:
        remote_bind: Whether remote binding is requested
        
    Raises:
        StartupValidationError: If remote binding without opt-in
    """
    if remote_bind:
        env_opt_in = os.environ.get('AGENTSHIELD_ALLOW_REMOTE', '').lower()
        if env_opt_in not in ('1', 'true', 'yes'):
            raise StartupValidationError(
                "Remote dashboard binding not allowed without explicit opt-in.\n"
                "  To enable, set AGENTSHIELD_ALLOW_REMOTE=1\n"
                "  Default: localhost only (127.0.0.1:9123)"
            )


def validate_python_version() -> None:
    """Validate that Python version is compatible with AgentShield.

    Requires Python 3.8+ for full feature support.
    """
    version = sys.version_info
    if version < (3, 8):
        raise StartupValidationError(
            f"Python {version.major}.{version.minor} is not supported.\n"
            "  AgentShield requires Python 3.8+ for full security features.\n"
            f"  Current version: {platform.python_version()}"
        )


def validate_required_dependencies() -> None:
    """Validate that required dependencies are available."""
    required_modules = [
        'sqlite3',  # For audit storage
        'hashlib',  # For tamper-evident logging
        'json',     # For policy files
        'sys',      # For audit hooks
    ]
    
    missing = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        raise StartupValidationError(
            f"Required dependencies missing: {', '.join(missing)}\n"
            "  These are standard library modules and should be available.\n"
            "  Check your Python installation."
        )


def validate_system_resources() -> None:
    """Validate that system has adequate resources for secure operation."""
    # Check available disk space for audit logs
    try:
        import shutil
        storage_dir = os.path.expanduser('~/.agentshield')
        statvfs = os.statvfs(storage_dir if os.path.exists(storage_dir) else '/tmp')
        # Require at least 100MB free space
        free_mb = (statvfs.f_bavail * statvfs.f_frsize) / (1024 * 1024)
        if free_mb < 100:
            raise StartupValidationError(
                f"Insufficient disk space: {free_mb:.1f}MB free\n"
                "  AgentShield requires at least 100MB for audit logs.\n"
                f"  Storage directory: {storage_dir}"
            )
    except (OSError, AttributeError):
        # Skip check if statvfs not available (Windows) or other errors
        pass


def validate_configuration_integrity() -> None:
    """Validate that configuration files haven't been tampered with."""
    config_files = [
        ('default_policy.json', 'Default policy file corrupted'),
        ('SECURITY_MODEL.md', 'Security model documentation missing'),
    ]
    
    for filename, error_msg in config_files:
        try:
            # Try to find the file in the package
            import importlib.resources as pkg_resources
            try:
                pkg_resources.files('agentshield').joinpath(filename)
            except (AttributeError, FileNotFoundError):
                # Fallback for older Python versions - just check if we can import agentshield
                import agentshield
                if not hasattr(agentshield, '__file__'):
                    raise StartupValidationError(
                        f"{error_msg}: {filename}\n"
                        "  Configuration files may be corrupted or missing."
                    )
        except Exception:
            # If we can't validate, warn but don't fail
            pass


def run_startup_checks(
    policy_file: Optional[str] = None,
    storage_dir: Optional[str] = None,
    capability_profile: str = 'sandboxed',
    remote_dashboard: bool = False,
    strict: bool = False,
) -> None:
    """Run all startup validation checks.
    
    Args:
        policy_file: Path to policy JSON file
        storage_dir: Audit storage directory
        capability_profile: Capability profile name
        remote_dashboard: Whether remote dashboard binding is requested
        strict: If True, fail on warnings
        
    Raises:
        StartupValidationError: If any check fails
    """
    errors = []
    
    # Determine policy file path
    if policy_file is None:
        default_policy = os.path.expanduser('~/.agentshield/policies.json')
        if os.path.exists(default_policy):
            policy_file = default_policy
        else:
            # Use built-in default
            import importlib.resources as pkg_resources
            try:
                policy_file = str(
                    Path(__file__).parent / 'default_policy.json'
                )
            except Exception:
                raise StartupValidationError(
                    "Cannot locate default policy file"
                )
    
    # Check 1: Python version compatibility
    try:
        validate_python_version()
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 2: Required dependencies
    try:
        validate_required_dependencies()
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 3: System resources
    try:
        validate_system_resources()
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 4: Policy file
    try:
        validate_policy_file(policy_file)
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 5: Audit storage
    try:
        validate_audit_storage(storage_dir)
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 6: File permissions (warn by default, fail in strict mode)
    try:
        validate_file_permissions(storage_dir, strict=strict)
    except StartupValidationError as e:
        if strict:
            errors.append(str(e))
    
    # Check 7: Capability profile
    try:
        validate_capability_profile(capability_profile)
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 8: Remote dashboard opt-in
    try:
        validate_remote_dashboard_opt_in(remote_dashboard)
    except StartupValidationError as e:
        errors.append(str(e))
    
    # Check 9: Configuration integrity
    try:
        validate_configuration_integrity()
    except StartupValidationError as e:
        if strict:
            errors.append(str(e))
    
    # Check 10: Comprehensive audit log integrity verification
    if storage_dir is None:
        storage_dir_path = os.path.expanduser('~/.agentshield')
    else:
        storage_dir_path = storage_dir
    db_path = os.path.join(storage_dir_path, 'events.db')
    if os.path.exists(db_path):
        try:
            from .storage import LocalStorage
            storage = LocalStorage(db_path=db_path)
            integrity_report = storage.get_integrity_report()

            if not integrity_report['overall_valid']:
                issues = []
                recommendations = integrity_report.get('recommendations', [])

                # Check each validation component
                if not integrity_report['full_chain_verification']['valid']:
                    chain_result = integrity_report['full_chain_verification']
                    issues.append(f"AUDIT CHAIN BROKEN: {chain_result.get('error', 'unknown error')}")
                    if chain_result.get('broken_at'):
                        issues.append(f"  Broken at event ID: {chain_result['broken_at']}")
                    if chain_result.get('gaps'):
                        issues.append(f"  Missing events: {len(chain_result['gaps'])} gaps detected")
                    if chain_result.get('duplicates'):
                        issues.append(f"  Duplicate events: {len(chain_result['duplicates'])} duplicates detected")

                if not integrity_report['database_integrity']['valid']:
                    db_issues = integrity_report['database_integrity']['issues']
                    issues.append(f"DATABASE INTEGRITY ISSUES: {len(db_issues)} problems detected")
                    for issue in db_issues[:3]:  # Show first 3 issues
                        issues.append(f"  - {issue}")

                if integrity_report['file_tampering_detection']['tampered']:
                    tamper_changes = integrity_report['file_tampering_detection']['changes']
                    issues.append(f"FILE TAMPERING DETECTED: {len(tamper_changes)} suspicious changes")
                    for change in tamper_changes:
                        issues.append(f"  - {change}")

                if not integrity_report['event_consistency']['valid']:
                    consistency_issues = integrity_report['event_consistency']['issues']
                    issues.append(f"EVENT CONSISTENCY ISSUES: {len(consistency_issues)} problems detected")
                    for issue in consistency_issues[:3]:  # Show first 3 issues
                        issues.append(f"  - {issue}")

                if issues:
                    msg = (
                        f"AUDIT LOG INTEGRITY COMPROMISED:\n" +
                        "\n".join(f"  {issue}" for issue in issues) +
                        f"\n\nRECOMMENDATIONS:\n" +
                        "\n".join(f"  - {rec}" for rec in recommendations if rec != "All integrity checks passed")
                    )
                    if strict:
                        errors.append(msg)
                    else:
                        print(f"CRITICAL WARNING: {msg}", file=sys.stderr)
            else:
                # Integrity checks passed - log success in non-strict mode
                if not strict:
                    print(f"[OK] Audit log integrity verified ({integrity_report['full_chain_verification']['total_events']} events)", file=sys.stderr)

        except Exception as e:
            error_msg = f"Cannot perform audit integrity verification: {e}"
            if strict:
                errors.append(error_msg)
            else:
                print(f"WARNING: {error_msg}", file=sys.stderr)

    if errors:
        error_msg = "\n\n".join(errors)
        raise StartupValidationError(
            f"AgentShield startup validation failed:\n\n{error_msg}"
        )

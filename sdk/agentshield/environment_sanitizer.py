"""Environment sanitization for isolated mode (--isolate flag).

When running an agent in a child process, sanitize inherited environment
variables to prevent loaders and injection attacks.
"""
import os
import copy
from typing import Dict


# Environment variables that could be used for injection/loading
DANGEROUS_ENV_VARS = {
    'PYTHONPATH',  # Adds directories to sys.path before standard library
    'PYTHONHOME',  # Alternative Python home
    'PYTHONPROXYFILE',  # Python proxy
    'PYTHONUTF8',  # May affect encoding parsing
    'LD_PRELOAD',  # Load shared libraries (Linux/Unix)
    'LD_LIBRARY_PATH',  # Shared library search path
    'LD_AUDIT',  # Audit library
    'LD_DEBUG',  # Debug output
    'DYLD_INSERT_LIBRARIES',  # Load libraries (macOS)
    'DYLD_LIBRARY_PATH',  # Library search (macOS)
    'DYLD_FRAMEWORK_PATH',  # Framework search (macOS)
    'DYLD_ROOT_PATH',  # Root path (macOS)
}

# Environment variables needed for runtime
REQUIRED_ENV_VARS = {
    'HOME',  # Home directory
    'USER',  # Current user
    'PATH',  # Command search path (keep, but may want to restrict)
    'LANG',  # Locale
    'LC_ALL',  # Locale
    'TZ',  # Timezone
    'SHELL',  # Default shell
    'TERM',  # Terminal type
}


def sanitize_environment() -> Dict[str, str]:
    """Create a sanitized environment for child process.
    
    Removes dangerous variables that could be used for injection or loading.
    Keeps essential variables for basic functionality.
    
    Returns:
        Sanitized environment dict
    """
    current_env = os.environ.copy()
    sanitized = {}
    
    # Copy only non-dangerous variables
    for key, value in current_env.items():
        if key in DANGEROUS_ENV_VARS:
            # Skip dangerous variables
            continue
        
        # Skip common python-specific variables
        if key.startswith('PYTHON'):
            continue
        
        # Skip runtime-specific variables that may be set by parent
        if key.startswith('LD_') or key.startswith('DYLD_'):
            continue
        
        # Copy safe variables
        sanitized[key] = value
    
    # Ensure required variables are present
    for key in REQUIRED_ENV_VARS:
        if key not in sanitized and key in current_env:
            sanitized[key] = current_env[key]
    
    return sanitized


def get_sanitized_env_for_subprocess() -> Dict[str, str]:
    """Get environment for subprocess.Popen/run in isolated mode.
    
    Returns:
        Sanitized environment dict suitable for child process
    """
    return sanitize_environment()


def close_inherited_file_descriptors(min_fd: int = 3) -> None:
    """Close inherited file descriptors above the standard three.
    
    This prevents the child process from inheriting open file handles
    that may grant unintended access.
    
    Args:
        min_fd: Minimum FD to close (default 3, keeps stdin/stdout/stderr)
        
    Note:
        This is best-effort; some platforms may not support it.
    """
    import subprocess
    
    # Note: subprocess.Popen(close_fds=True) is the standard approach
    # This function is for explicit cleanup if needed
    try:
        import resource
        # Get max open file descriptors
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        for fd in range(min_fd, soft):
            try:
                os.close(fd)
            except OSError:
                # Already closed
                pass
    except ImportError:
        # resource module not available, skip
        pass

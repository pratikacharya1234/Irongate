# Security Policy — Optimus v0.1.0

## Scope

Optimus v0.1.0 is an **experimental local runtime** for deterministic enforcement of Python AI agent behavior. The scope of this release is strictly the local deterministic runtime:

- Policy-based interception of file, network, process, and tool operations
- Audit hooks and monkeypatch-based enforcement
- Local SQLite audit log with hash chaining
- Local FastAPI dashboard for approval workflows
- Capability profiles and access control

**Out of scope:**
- Enterprise platform features
- Distributed trust networks
- Cloud integration
- Compliance frameworks
- Backend services
- ML/AI-based detection or anomaly analysis

## Known Limitations

Optimus is **not a substitute for OS-level sandboxing**. The following are **not protected**:

- Native C extensions, `ctypes`, or `cffi` syscalls
- Code saved references to Python APIs before `shield.protect()` is called
- `aiohttp` or other non-intercepted libraries
- Binary executables or native code
- Processes running outside the Python interpreter

**Optimus automatically detects and warns when agents use known limitation APIs.** The limitation detector:

- Logs warnings when `ctypes`, `cffi`, `aiohttp`, `http.client`, and other unintercepted modules are imported
- Detects pre-imported function references that bypass monkeypatching
- Provides summary warnings about audit log, isolation, and scope limitations
- Available via: `from optimus.limitation_detector import LimitationWarner`

Run the limitation demo to see how these work:

```bash
python examples/safe_agent.py
```

See [SECURITY_MODEL.md](SECURITY_MODEL.md) and [THREAT_MODEL.md](THREAT_MODEL.md) for detailed analysis.

## Supported Version

Only **v0.1.0** is supported. This is an experimental release.

## Reporting Security Issues

If you discover a security issue in the local runtime enforcement, please report it directly to:

**Email**: `pratikacharya468@gmail.com` (subject: "Optimus Security Report")

**Please do not:**
- Open a public GitHub issue
- Disclose the issue publicly before we have time to address it

Include:
- Description of the issue
- Steps to reproduce (local runtime only)
- Impact assessment

## Enforcement Boundaries

Optimus enforces policy at the **Python API layer** using:

1. **Audit hooks** (`sys.addaudithook`) — PEP 578
2. **Monkeypatching** — replacing standard library functions

Both approaches have **documented bypass boundaries**:

- Audit hooks observe most operations but cannot intercept before the hook is installed
- Monkeypatches can be bypassed if code saves a reference to the original function before patching
- Native code and C extensions are outside the enforcement boundary

## What "Deny by Default" Means

Every action must be **explicitly allowed** by policy or it is blocked. Unknown action types are blocked. This includes:

- Unknown file operations
- Unknown network protocols
- Unknown process types
- Unknown tool classes

## Audit Chain Integrity

The local SQLite audit log uses **hash chaining** for tamper evidence, but is **not cryptographically verified**. Hash chaining is sufficient to detect modification but does not prove who created the chain.

For compliance, audit logs should be backed up to an immutable external system (syslog, centralized logging, etc.).

## Local Dashboard Security

The local dashboard:
- Binds to `127.0.0.1:9123` by default (localhost only)
- Requires an authentication token for all endpoints
- Token is printed to console at startup
- Token is stored in memory, not on disk
- Tokens expire or are reset when the dashboard restarts

Remote binding (to `0.0.0.0`) requires explicit opt-in via `OPTIMUS_ALLOW_REMOTE=1` environment variable.

## Python Versions

- Audit hooks require **Python 3.8+** (PEP 578 added in 3.8)
- Tested on Python 3.10, 3.11, 3.12, 3.13

## No Guarantees Beyond the Enforcement Boundary

Optimus **makes no claims beyond the documented enforcement boundary**. It is a deterministic policy engine, not a sandbox, not a security boundary for untrusted code, and not a replacement for OS-level isolation.

Use with containers (`--isolate` mode), seccomp, AppArmor, or SELinux for deeper isolation.

## Contact

Maintainer: Pratik Acharya (`pratikacharya468@gmail.com`)

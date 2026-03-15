# IronGate

**Experimental v0.1.0** | Local deterministic runtime security for Python AI agents.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org)

IronGate is a local, in-process policy enforcement layer for Python-based AI agents. It intercepts file, network, process, and tool operations at the Python API level and applies deterministic allow/review/block decisions based on a JSON policy file.

## Experimental Release Warning

This is an **experimental release** for evaluation and feedback. Important limitations:

- Deterministic, deny-by-default enforcement -- no AI/ML inside IronGate
- Local runtime only -- all enforcement in-process or in a child process
- Known bypass boundaries documented in [SECURITY_MODEL.md](SECURITY_MODEL.md)
- **Not a substitute for OS-level sandboxing** -- use containers or seccomp for untrusted code
- Hash-chained audit log for tamper evidence, not cryptographic proof

## What it does

- **Intercepts** standard Python APIs via two enforcement layers:
  - **Audit hooks** (`sys.addaudithook`): Observes file open, subprocess, socket, OS operations at the CPython level. Harder to bypass than monkeypatching. Cannot be removed once installed.
  - **Monkeypatch interception**: Replaces standard library functions with policy-enforcing wrappers.
- **Evaluates** each operation against a JSON policy (first-match-wins rule engine)
- **Enforces** allow, review (human-in-the-loop via local dashboard), or block decisions
- **Logs** all operations to a local SQLite audit trail with hash chaining for tamper evidence
- **Defaults to deny** -- unknown action types and unmatched operations are blocked

### Intercepted APIs

**File**: `builtins.open`, `io.open`, `os.open`, `os.fdopen`, `os.remove`, `os.unlink`, `os.rename`, `os.link`, `os.symlink`, `os.mkdir`, `os.makedirs`, `os.rmdir`, `os.removedirs`, `shutil.rmtree`, `shutil.copy`, `shutil.copy2`, `shutil.move`, `shutil.copytree`, `pathlib.Path.open/read_text/write_text/read_bytes/write_bytes/unlink/rename/replace/mkdir`

**Network**: `requests.*`, `httpx.*`, `urllib.*`, `aiohttp.*`, `http.client.HTTPConnection/HTTPSConnection`, `ssl.wrap_socket/SSLContext.wrap_socket`, `socket.socket`, `socket.create_connection`

**Process**: `subprocess.run/Popen/call/check_call/check_output`, `os.system` (with Python child vs binary classification). Audit hooks also cover `os.exec*`, `os.spawn*`.

## What it does NOT do

- It does not sandbox native code, C extensions, or `ctypes`/`cffi` calls
- It does not use machine learning, AI-based detection, or heuristics
- It does not provide network-level firewalling or OS-level syscall interposition
- It does not prevent an agent from saving a reference to `builtins.open` before `shield.protect()` is entered
- It is not a cloud service -- everything runs locally in your process

See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the full list of known limitations and bypass boundaries.

## Install

```bash
cd sdk
pip install -e .
```

Requires Python 3.8+ (audit hooks require 3.8+).

## Quick start

### Protect a script

```bash
irongate run my_agent.py
```

All file, network, process, and tool operations inside `my_agent.py` will be intercepted and enforced.

### Options

```bash
irongate run my_agent.py --profile sandboxed    # default -- restrictive capabilities
irongate run my_agent.py --profile read_only    # read files + HTTP only
irongate run my_agent.py --profile trusted      # broad capabilities
irongate run my_agent.py --policy custom.json   # custom policy file
irongate run my_agent.py --isolate              # run in child process
irongate run my_agent.py -v                     # verbose output
```

### Child-process isolation

```bash
irongate run my_agent.py --isolate
```

Runs the agent in a separate Python interpreter with its own IronGate bootstrap. If the agent crashes, the parent is unaffected. The child process inherits the policy and capability profile via environment variables.

### Use as a library

```python
from agentshield import shield, protect_agent

# Context manager
with shield.protect():
    agent.run(query)

# Decorator
@protect_agent
def run_my_agent():
    with open('data.csv') as f:
        return f.read()
```

### Start the local dashboard

```bash
irongate dashboard
```

The dashboard starts on `http://127.0.0.1:9123` and prints an auth token to the console. **All endpoints** require this token as `Authorization: Bearer <token>`.

Remote binding requires explicit opt-in via the `IRONGATE_ALLOW_REMOTE=1` environment variable.

## Policy format

Policies are JSON files with a `rules` array. Rules are evaluated in order; first match wins. The default policy ends with a deny-all fallback.

```json
{
  "rules": [
    {
      "type": "file",
      "path_contains": [".env", ".ssh/", "id_rsa"],
      "decision": "review",
      "reason": "Sensitive file access requires approval"
    },
    {
      "type": "process",
      "cmd_contains": ["rm -rf", "shutdown"],
      "decision": "block",
      "reason": "Dangerous commands blocked"
    },
    {
      "decision": "block",
      "reason": "default_deny"
    }
  ]
}
```

Supported match predicates:
- Exact match: `"type": "file"` matches `action.type == "file"`
- Substring list: `"path_contains": [".env", ".ssh"]` matches if path contains any
- Regex: `"cmd_pattern": "^sudo"` matches if cmd matches the regex
- Prefix: `"path_startswith": "/sensitive"`

Custom policies can be placed at `~/.irongate/policies.json` or passed via `--policy`.

## Capability profiles

Profiles restrict what classes of operations an agent can perform, enforced before policy rules:

| Profile | Capabilities |
|---------|-------------|
| `sandboxed` (default) | file.read, network.dns, process.env_access, tool.invoke |
| `read_only` | file.read, network.dns, network.http, process.env_access, tool.invoke |
| `trusted` | file.*, network.*, process.*, tool.*, credential.read |
| `minimal` | tool.invoke only |

If an action requires a capability the profile doesn't grant, it is blocked before policy evaluation. Unknown action types require an impossible capability and are always blocked.

## Architecture

```
Agent code
    |
    v
sys.addaudithook (audit hook layer -- permanent, hard to bypass)
    |
    v
RuntimeInterceptor (monkeypatch layer -- secondary enforcement)
    |
    v
PolicyEngine (capability check + rule matching)
    |
    |-- allow --> proceed
    |-- review --> log + wait for dashboard approval
    +-- block --> raise PermissionError
    |
    v
LocalStorage (SQLite + WAL mode + hash-chained audit log)
```

All components run in-process (or in a child process with `--isolate`). No external services required.

## Project structure

```
sdk/
  agentshield/
    __init__.py          # Global runtime instance
    audit_hooks.py       # sys.addaudithook enforcement (PEP 578)
    interceptor.py       # Monkeypatch-based interception
    policy.py            # Rule engine + capability enforcement
    capabilities.py      # Capability profiles and checks
    storage.py           # SQLite event storage (WAL + hash chaining)
    dashboard.py         # Local FastAPI dashboard (all endpoints authenticated)
    cli.py               # CLI entrypoint
    runtime_launcher.py  # Script execution (in-process or child-process isolation)
    startup_checks.py    # Startup safety validation (fail closed)
    environment_sanitizer.py  # Environment sanitization for --isolate mode
    models.py            # Pydantic action models
    approvals.py         # Approval queue management
    notifier.py          # Local notification log
    default_policy.json  # Default deny-by-default policy
    integrations/        # LangChain and generic wrappers
  tests/
  pyproject.toml
```

## Testing

```bash
cd sdk
pip install -e ".[dev]"
pytest -v
```

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.

## License

MIT License -- see [LICENSE](LICENSE).

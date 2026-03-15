# Optimus Security Model

Version: 0.1.0 (experimental local runtime only)

## Overview

Optimus is a deterministic, in-process runtime enforcement layer for Python-based AI agents. It uses two complementary enforcement mechanisms:

1. **Audit hooks** (`sys.addaudithook`, PEP 578): Observes CPython runtime events at a level deeper than monkeypatching. Once installed, audit hooks cannot be removed.
2. **Monkeypatch interception**: Replaces standard Python functions with policy-enforcing wrappers for precise control and richer action context.

Both layers route actions through the same PolicyEngine for deterministic allow/review/block decisions.

## Enforcement mechanisms

### Audit hooks (primary)

Installed via `sys.addaudithook` before agent code executes. Handles:
- `open` — file open operations
- `subprocess.Popen` — subprocess creation
- `os.system` — system command execution
- `os.exec`, `os.posix_spawn`, `os.spawn` — process execution families
- `socket.connect`, `socket.bind`, `socket.sendto` — network connections
- `os.remove`, `os.unlink`, `os.rename`, `os.mkdir`, `os.rmdir` — file management
- `os.chmod`, `os.chown` — permission changes

Audit hooks are:
- **Permanent**: Cannot be removed once installed (Python design)
- **Harder to bypass**: Triggered by CPython internally, not by Python-level function calls
- **Fail-closed**: If evaluation errors occur, the operation is blocked

### Monkeypatch interception (secondary)

Active during `shield.protect()` context. Provides richer action context and covers APIs not reached by audit hooks.

#### File operations intercepted

| API | Action type |
| --- | --- |
| `builtins.open()` | file/open |
| `io.open()` | file/open |
| `pathlib.Path.open()` | file/open |
| `pathlib.Path.read_text()` | file/read |
| `pathlib.Path.read_bytes()` | file/read |
| `pathlib.Path.write_text()` | file/write |
| `pathlib.Path.write_bytes()` | file/write |
| `pathlib.Path.unlink()` | file/delete |
| `pathlib.Path.rename()` | file/rename |
| `pathlib.Path.replace()` | file/rename |
| `pathlib.Path.mkdir()` | file/mkdir |
| `os.open()` | file/open |
| `os.remove()` | file/delete |
| `os.unlink()` | file/delete |
| `os.rename()` | file/rename |
| `os.mkdir()` | file/mkdir |
| `os.makedirs()` | file/mkdir |
| `os.rmdir()` | file/delete |
| `shutil.rmtree()` | file/delete |
| `shutil.copy()` | file/read + file/write |
| `shutil.copy2()` | file/read + file/write |
| `shutil.move()` | file/rename |

#### Network operations intercepted

| API | Action type |
| --- | --- |
| `requests.request()` | network/http |
| `requests.Session.request()` | network/http |
| `httpx.request()` | network/http |
| `httpx.Client.request()` | network/http |
| `urllib.request.urlopen()` | network/http |
| `socket.socket()` | network/socket |
| `socket.create_connection()` | network/socket |

#### Process operations intercepted

| API | Action type | Classification |
| --- | --- | --- |
| `subprocess.run()` | process/exec | Python child or binary |
| `subprocess.Popen()` | process/spawn | Python child or binary |
| `subprocess.call()` | process/exec | Python child or binary |
| `subprocess.check_call()` | process/exec | Python child or binary |
| `subprocess.check_output()` | process/exec | Python child or binary |
| `os.system()` | process/system | — |

Subprocess commands are classified as `python_child` or `binary` based on the executable. Policy rules can use the `process_class` field to allow Python child processes (which will have their own Optimus bootstrap in `--isolate` mode) while blocking arbitrary binaries.

## What is NOT intercepted

### Not intercepted by either layer

- Direct use of `ctypes`/`cffi` for native code execution
- Compiled C extensions that bypass Python APIs
- `os.fork()` (creates new process not covered by audit hooks)
- Some async libraries may have incomplete interception

### Fundamental bypass vectors

These cannot be fully fixed by in-process enforcement:

1. **Pre-imported references**: If agent code saves `orig = builtins.open` before `shield.protect()` is entered, the reference bypasses monkeypatch interception. Audit hooks still observe the operation.
2. **C extensions**: Operations via `ctypes`, `cffi`, or compiled C extension modules bypass both audit hooks and monkeypatching.
3. **importlib**: Using `importlib.import_module()` to get fresh module references can yield unpatched versions. Audit hooks still observe the underlying operations.
4. **Shared process state**: The global `shield` object and its policy/storage are mutable module-level variables. Agent code in the same process can theoretically import and modify them. Use `--isolate` to mitigate.
5. **Child process escape**: Subprocess calls that are allowed will spawn processes without Optimus enforcement (unless `--isolate` mode is used with Python children that bootstrap Optimus).

## Default deny behavior

- If no policy rule matches an action, the decision is **block** with reason `default_deny`
- If the policy engine returns an invalid or malformed result, the decision is **block**
- If an approval times out, the decision is **block**
- If an audit hook cannot evaluate an action, the operation is **blocked** (fail closed)
- Unknown action types require an impossible capability and are always **blocked**
- Unknown file subtypes default to requiring `file.write` capability
- The default policy includes a terminal catch-all `{"decision": "block", "reason": "default_deny"}` rule

## Capability enforcement

Capabilities are checked before policy rules. The PolicyEngine uses a CapabilityEngine with the active profile. If the agent's profile lacks a required capability, the action is blocked regardless of policy rules.

Unknown action types are assigned an impossible capability (`unknown.<type>`) that no profile grants, ensuring deny-by-default for unrecognized operations.

## Audit trail

All intercepted operations are logged to `~/.optimus/events.db` (SQLite) with:

- **WAL mode**: Enables safe concurrent reads during writes
- **Thread-safe writes**: All writes are serialized via threading.Lock
- **Hash chaining**: Each event includes a SHA-256 hash of its contents plus the previous event's hash, creating a tamper-evident chain. Use `storage.verify_chain()` to detect modifications or deletions.

Each event records: timestamp, agent name, action type/subtype, target, decision, reason, raw action dict, matched rule, previous hash, event hash.

Dashboard actions (approve, block, policy changes) are also audit-logged as `type=dashboard` events.

The audit log is not encrypted at rest.

## Dashboard authentication

The local dashboard generates a random bearer token at startup. **All endpoints** require this token in the `Authorization: Bearer <token>` header — both read and write operations.

Remote binding (non-localhost) requires explicit opt-in via `OPTIMUS_ALLOW_REMOTE=1` environment variable. Without this, the dashboard only binds to `127.0.0.1`.

## Child-process isolation

The `--isolate` flag runs the agent in a separate Python interpreter:

1. Configuration (profile, policy) is passed via environment variables
2. The child process bootstraps Optimus (audit hooks + monkeypatches) before executing agent code
3. If the agent crashes, the parent process is unaffected
4. The child process has its own module namespace, preventing shared-state attacks

This does not provide OS-level sandboxing. For stronger containment, combine with containers or VMs.

## Threat model scope

Optimus is designed to enforce security policies on **cooperative or semi-trusted agents running standard Python code**. It is not designed to contain a fully adversarial agent that is actively trying to escape.

For stronger containment of untrusted code, use OS-level isolation (containers, VMs, WASM sandboxes, seccomp/AppArmor) in addition to Optimus's policy enforcement.

# Optimus Threat Model

Version: 0.1.0 (experimental local runtime only)

## Scope

Optimus is a local, in-process policy enforcement layer for Python AI agents. This threat model describes what attacks it can and cannot defend against.

## What Optimus defends against

### 1. Accidental or policy-violating file access

An agent that attempts to read `.env`, `.ssh/id_rsa`, `credentials.json`, or other sensitive files through standard Python APIs will be intercepted via both audit hooks and monkeypatches. The default policy sends these to review or blocks them. Coverage includes `open()`, `Path.read_text()`, `shutil.copy()`, and other file APIs.

### 2. Unintended network requests

HTTP requests via `requests`, `httpx`, `urllib`, `socket.socket`, or `socket.create_connection` to payment APIs, external webhooks, or blocked domains are intercepted. Audit hooks additionally observe `socket.connect`, `socket.bind`, and `socket.sendto` events.

### 3. Dangerous command execution

Commands containing `rm -rf`, `shutdown`, `dd if=/dev`, or other destructive patterns are blocked when executed through `subprocess.*`, `os.system()`, or (via audit hooks) `os.exec*` and `os.spawn*`. Subprocess commands are classified as `python_child` or `binary` — policy can distinguish between them.

### 4. Uncontrolled tool invocations

Tool calls routed through Optimus's wrappers (LangChain integration, generic wrapper) are subject to policy evaluation. Destructive tool names can be flagged for review or blocked.

### 5. Unknown operation types

Any operation type not covered by explicit policy rules is blocked by default. Unknown action types require an impossible capability that no profile grants (deny-by-default).

### 6. Audit log tampering (partially mitigated)

The audit log now uses SHA-256 hash chaining. Each event includes a hash of the previous event, forming a tamper-evident chain. While an attacker with file access can still modify the database, the `verify_chain()` function will detect modifications, deletions, or insertions.

## What Optimus does NOT defend against

### 1. Native code execution

C extensions, `ctypes.CDLL`, `cffi`, and any compiled code bypass both audit hooks and monkeypatching. Optimus cannot intercept operations that do not go through CPython's auditing infrastructure.

### 2. Pre-imported function references

If agent code executes `orig_open = builtins.open` before `shield.protect()` is entered, the saved reference points to the unpatched function. Audit hooks still observe the underlying `open` event, providing partial mitigation.

### 3. APIs not currently covered

See SECURITY_MODEL.md for the full list. Most standard library APIs are now intercepted. Remaining gaps: `os.fork`, `os.exec*`/`os.spawn*` (covered by audit hooks, not monkeypatched), and `os.popen`.

### 4. Adversarial agents actively trying to escape

An agent that knows it is running inside Optimus and deliberately attempts to bypass it (via C extensions, pre-imported references, or other vectors) can succeed. Optimus is designed for policy enforcement on cooperative or semi-trusted agents, not for containment of fully adversarial code.

### 5. Content-based attacks

Optimus does not inspect the content of files being read or written, HTTP request/response bodies, or command output. It makes decisions based on the operation metadata (path, URL, command string), not on data content.

### 6. Multi-process attacks (partially mitigated)

If an agent spawns a child process (through an allowed subprocess call), the child process is a new Python interpreter. In `--isolate` mode, Python child processes bootstrap Optimus automatically. Arbitrary binary child processes remain unmonitored. Without `--isolate`, all child processes are unmonitored.

### 7. Timing attacks on approval flow

The approval flow polls SQLite for decision changes. An attacker with local file access could modify the SQLite database directly. Hash chaining detects post-hoc tampering but does not prevent real-time manipulation during the approval window.

## Recommended deployment

For stronger security:

1. Run Optimus inside a container or VM to provide OS-level isolation
2. Use read-only file system mounts for sensitive paths
3. Apply network policies (iptables, security groups) in addition to Optimus
4. Review the audit log regularly and verify the hash chain
5. Use the `sandboxed` or `minimal` capability profile unless broader access is explicitly needed
6. Keep the dashboard bound to localhost (default) and protect the auth token
7. Use `--isolate` mode for stronger process-level separation
8. Run `storage.verify_chain()` periodically to detect audit log tampering

## Risk summary

| Risk | Severity | Status |
| --- | --- | --- |
| Agent uses uncovered API | High | Reduced — most APIs now covered, audit hooks catch more |
| Agent pre-imports function reference | Medium | Partially mitigated — audit hooks still observe |
| C extension bypass | High | Architectural limitation |
| Audit log tampered | Medium | Partially mitigated — hash chaining detects tampering |
| Dashboard exposed to network | Low | Auth on all endpoints, remote requires explicit opt-in |
| SQLite contention under concurrency | Low | WAL mode + thread-safe writes |
| Policy file corruption | Medium | Silent fallback to defaults then deny |
| Child process escape | Medium | Partially mitigated with --isolate mode |

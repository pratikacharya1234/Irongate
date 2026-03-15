# Changelog

All notable changes to Optimus are documented here.

## [0.1.0] - 2026-03-14

### Added

**Core Runtime Enforcement:**
- Deny-by-default policy engine with JSON rule matching
- First-match-wins rule evaluation with support for regex, substring, and exact match predicates
- Capability profiles: `sandboxed`, `read_only`, `trusted`, `minimal`
- Audit hooks (PEP 578) for CPython-level operation observation
- Monkeypatch interception layer for Python standard library APIs

**Intercepted Operations:**
- File operations: open, read, write, delete, rename, mkdir, rmdir, copy, move
- Network operations: HTTP/HTTPS requests, DNS queries, socket connections
- Process operations: subprocess execution, OS command calls
- Tool operations: LangChain Tool invocation and generic function wrapping
- Credential detection: patterns for API keys, tokens, SSH keys

**Audit and Logging:**
- Local SQLite audit log with write-ahead logging (WAL)
- Hash-chained event log for tamper evidence
- Event context: agent name, operation type, resource, decision, timestamp
- Approval queue for human-in-the-loop sensitive operations

**Local Dashboard:**
- FastAPI-based web interface on `http://127.0.0.1:9123`
- Authentication token required for all endpoints
- Real-time event stream
- Approval workflow UI
- Policy tester and validation

**Child-Process Isolation:**
- `--isolate` mode runs agent in separate Python interpreter
- Sanitized environment: removes `PYTHONPATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, and other dangerous loader variables
- Closes inherited file descriptors (`close_fds=True`)
- Environment variable inheritance for policy and profile
- Deterministic child process startup
- Exit code passthrough

**Startup Safety Checks:**

- Policy file validation: must be valid JSON with a terminal default deny rule
- Audit storage validation: directory must be writable
- File permission checks: warns on world-writable `events.db` or `policies.json`, fails in strict mode
- Capability profile validation: rejects unknown profiles
- Remote dashboard opt-in: binding to non-localhost requires `OPTIMUS_ALLOW_REMOTE=1`
- Audit chain verification: detects tampered events on startup

**Subprocess Classification:**
- Subprocess commands classified as `python_child` or `binary`
- Policy can distinguish Python child processes from arbitrary binaries

**Policy and Profiles:**
- Default deny-by-default policy with production rules
- Custom policy file support (JSON format)
- Environment-based policy override
- Capability profile selection via CLI or API

**Command-Line Interface:**
- `optimus run <script>` — execute script with enforcement
- `optimus dashboard` — start local dashboard
- Profile selection: `--profile {sandboxed|read_only|trusted|minimal}`
- Custom policy: `--policy <file>`
- Isolated mode: `--isolate`
- Verbose output: `-v`

**Library Integration:**
- Python decorator: `@protect_agent`
- Context manager: `with shield.protect():`
- LangChain Tool wrapping
- Generic function wrapping

### Known Limitations

- **Not a sandbox**: Native code, C extensions, `ctypes`, `cffi` are outside enforcement boundary
- **Python API layer only**: No protection for binary executables or non-Python code
- **Audit chain not cryptographic**: Hash chaining detects tampering but requires external immutable log for compliance
- **No ML/AI inside**: Enforcement is purely rule-based, no probabilistic detection
- **Monkeypatch vulnerability**: Code can save references to original functions before patching
- **Not a substitute for OS sandboxing**: Use containers, seccomp, or AppArmor for untrusted code

### Experimental Status

This is an **experimental release** for evaluation and feedback. The enforcement model has known gaps documented in [SECURITY_MODEL.md](SECURITY_MODEL.md) and [THREAT_MODEL.md](THREAT_MODEL.md). Do not rely on this as your sole security boundary in production.

### Local Runtime Only

This release focuses exclusively on the local deterministic runtime. Enterprise platform features, distributed trust networks, cloud integration, and compliance frameworks are out of scope.

---

## Future Releases (Not Committed)

Possible future enhancements (no timeline):

- Rate limiting per capability
- Encrypted credential masking in logs
- SELinux/AppArmor integration
- Distributed approval (multi-signature)
- Policy versioning and rollback
- Hardware attestation
- Capability time windows (schedule-based)

"""CLI entrypoint for AgentShield.

Usage:
    agentshield run <script.py> [--agent-name NAME] [--profile PROFILE] [--policy FILE]
    agentshield dashboard [--host HOST] [--port PORT]
"""
import sys
from pathlib import Path

from agentshield.runtime_launcher import launch_protected_script, PROFILES_BY_NAME


def show_help():
    """Display help information."""
    print("AgentShield - Deterministic runtime security for AI agents")
    print("")
    print("Usage:")
    print("  agentshield run <script.py> [options]")
    print("  agentshield dashboard [options]")
    print("")
    print("Run options:")
    print("  --agent-name NAME       Agent name for audit logging (default: script basename)")
    print("  --profile PROFILE       Capability profile: sandboxed, read_only, trusted, minimal")
    print("                          (default: sandboxed)")
    print("  --policy FILE          Custom policy file (default: ~/.agentshield/policies.json)")
    print("  --isolate              Run agent in child process (process-level isolation)")
    print("  -v, --verbose          Enable verbose output")
    print("")
    print("Dashboard options:")
    print("  --host HOST            Host to bind to (default: 127.0.0.1)")
    print("  --port PORT            Port to bind to (default: 9123)")
    print("")
    print("Examples:")
    print("  agentshield run my_agent.py")
    print("  agentshield run my_agent.py --agent-name test_agent")
    print("  agentshield run my_agent.py --profile read_only")
    print("  agentshield run my_agent.py --policy custom.json --verbose")
    print("  agentshield dashboard --port 8080")
    print("")


def main():
    """Main CLI entrypoint."""
    if len(sys.argv) < 2:
        show_help()
        sys.exit(0)

    command = sys.argv[1]

    if command in ('--help', '-h', 'help'):
        show_help()
        sys.exit(0)

    if command == "run":
        if len(sys.argv) < 3:
            print("Error: agentshield run requires a script path")
            print("Usage: agentshield run <script.py> [options]")
            print("")
            print("Use 'agentshield run --help' for more information")
            sys.exit(1)

        script_path = sys.argv[2]
        
        # Parse optional arguments
        agent_name = None
        profile = 'sandboxed'
        policy_file = None
        verbose = False
        isolate = False

        i = 3
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg == '--agent-name' and i + 1 < len(sys.argv):
                agent_name = sys.argv[i + 1]
                i += 2
            elif arg == '--profile' and i + 1 < len(sys.argv):
                profile = sys.argv[i + 1]
                i += 2
            elif arg == '--policy' and i + 1 < len(sys.argv):
                policy_file = sys.argv[i + 1]
                i += 2
            elif arg in ('-v', '--verbose'):
                verbose = True
                i += 1
            elif arg == '--isolate':
                isolate = True
                i += 1
            else:
                i += 1

        # Validate profile
        if profile not in PROFILES_BY_NAME:
            print(f"Error: Unknown profile '{profile}'")
            print(f"Available profiles: {', '.join(PROFILES_BY_NAME.keys())}")
            sys.exit(1)

        # Launch the protected script
        exit_code = launch_protected_script(
            script_path=script_path,
            agent_name=agent_name,
            capability_profile=profile,
            policy_file=policy_file,
            log_events=True,
            isolate=isolate
        )
        sys.exit(exit_code)

    elif command == "dashboard":
        # Parse dashboard options
        host = '127.0.0.1'
        port = 9123

        i = 2
        while i < len(sys.argv):
            arg = sys.argv[i]
            if arg == '--host' and i + 1 < len(sys.argv):
                host = sys.argv[i + 1]
                i += 2
            elif arg == '--port' and i + 1 < len(sys.argv):
                try:
                    port = int(sys.argv[i + 1])
                except ValueError:
                    print(f"Error: Invalid port '{sys.argv[i + 1]}'")
                    sys.exit(1)
                i += 2
            else:
                i += 1

        # Enforce remote opt-in
        import os
        if host not in ('127.0.0.1', 'localhost', '::1'):
            if os.environ.get('AGENTSHIELD_ALLOW_REMOTE') != '1':
                print(f"Error: Remote dashboard binding to {host} requires explicit opt-in.", file=sys.stderr)
                print(f"  Set AGENTSHIELD_ALLOW_REMOTE=1 to allow remote access.", file=sys.stderr)
                print(f"  Default: localhost only (127.0.0.1:9123)", file=sys.stderr)
                sys.exit(1)
            print(f"[AgentShield] WARNING: Binding to {host} exposes the dashboard to the network.", file=sys.stderr)
            print(f"[AgentShield] WARNING: Ensure network-level access control is in place.", file=sys.stderr)

        # Import and run dashboard
        from agentshield.dashboard import app, init_dashboard
        from agentshield import policy as policy_mod
        import uvicorn

        token = init_dashboard(policy_engine=policy_mod)

        print(f"[AgentShield] Starting dashboard on {host}:{port}")
        print(f"[AgentShield] Open http://{host}:{port} in your browser")
        print(f"[AgentShield] Dashboard auth token: {token}")
        print(f"[AgentShield] All endpoints require: Authorization: Bearer {token}")

        uvicorn.run(app, host=host, port=port)

    else:
        print(f"Error: Unknown command '{command}'")
        print("Use 'agentshield --help' for usage information")
        sys.exit(1)


if __name__ == "__main__":
    main()

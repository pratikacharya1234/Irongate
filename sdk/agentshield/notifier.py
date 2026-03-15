"""Notifier for owner approvals and alerts (local dashboard-compatible).

This notifier intentionally avoids CLI prompts. When an action requires
review, the runtime will write a pending event to SQLite and the dashboard
polls/reads that table. The notifier writes a small notification record to
`~/.agentshield/notifications.log` so local tooling can be aware of alerts
without triggering a blocking terminal prompt.
"""
import os
import json
from datetime import datetime


class Notifier:
    def __init__(self, storage=None):
        self.storage = storage
        self.log_path = os.path.expanduser('~/.agentshield/notifications.log')
        # ensure directory
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def notify(self, action, level='info'):
        """Write a single-line JSON notification to the local notifications log.

        This keeps notifications local-first and dashboard-compatible without
        printing or prompting on the terminal.
        """
        entry = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'level': level,
            'agent': action.get('agent'),
            'type': action.get('type'),
            'subtype': action.get('subtype'),
            'target': action.get('target') or action.get('path') or None,
        }
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            # best-effort only; do not raise for notifier
            pass

    def prompt_for_approval(self, action) -> bool:
        """Deprecated synchronous prompt; keep for backward compatibility but
        behave non-interactively (always return False) so callers don't block.
        Runtime now uses the approval queue + dashboard to make decisions.
        """
        # write a notification for dashboards/tools but do NOT prompt in terminal
        self.notify(action, level='warning')
        return False

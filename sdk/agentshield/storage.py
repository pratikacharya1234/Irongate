"""LocalStorage using SQLite for event logs (local-first).

Events are stored in ~/.agentshield/events.db with:
- WAL mode for safe concurrent access
- Thread-safe writes via threading.Lock
- Hash chaining for tamper evidence (each event includes hash of previous)
"""
import os
import sqlite3
import time
import json
import ast
import hashlib
import threading
from typing import Optional


DEFAULT_DB = os.path.expanduser("~/.agentshield/events.db")


class LocalStorage:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB
        self._ensure_dir()
        self._write_lock = threading.Lock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._enable_wal()
        self._create_tables()
        self._baseline_stats = self._get_file_stats()  # Baseline for tamper detection

    def _ensure_dir(self):
        d = os.path.dirname(self.db_path)
        os.makedirs(d, exist_ok=True)

    def _enable_wal(self):
        """Enable WAL mode for safe concurrent reads during writes."""
        try:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass  # Proceed with default journal mode if WAL fails

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                agent TEXT,
                action_type TEXT,
                subtype TEXT,
                target TEXT,
                decision TEXT,
                reason TEXT,
                raw TEXT,
                prev_hash TEXT,
                event_hash TEXT
            )
            """
        )
        self.conn.commit()

        # Migrate existing tables: add hash columns if missing
        try:
            cur.execute("SELECT prev_hash FROM events LIMIT 1")
        except sqlite3.OperationalError:
            try:
                cur.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT")
                cur.execute("ALTER TABLE events ADD COLUMN event_hash TEXT")
                self.conn.commit()
            except Exception:
                pass

    def _compute_event_hash(self, ts, agent, action_type, subtype, target,
                            decision, reason, raw, prev_hash) -> str:
        """Compute SHA-256 hash of event data for tamper evidence.

        The hash includes the previous event's hash, creating a chain.
        If any event is modified or deleted, the chain breaks.
        """
        data = f"{ts}|{agent}|{action_type}|{subtype}|{target}|{decision}|{reason}|{raw}|{prev_hash}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _get_last_hash(self, cursor) -> str:
        """Get the hash of the most recent event (for chaining)."""
        cursor.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row and row[0]:
            return row[0]
        return "genesis"

    def log_event(self, action: dict, decision: str, reason: str):
        with self._write_lock:
            cur = self.conn.cursor()
            agent = action.get('agent') or action.get('agent_id') or 'unknown'
            typ = action.get('type')
            subtype = action.get('subtype')
            target = action.get('path') or action.get('target') or action.get('cmd') or ''
            ts = time.time()

            # Serialize action as JSON
            try:
                raw = json.dumps(action)
            except Exception:
                try:
                    raw = str(action)
                except Exception:
                    raw = ''

            # Hash chaining
            prev_hash = self._get_last_hash(cur)
            event_hash = self._compute_event_hash(
                ts, agent, typ, subtype, target, decision, reason, raw, prev_hash
            )

            cur.execute(
                "INSERT INTO events (ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ts, agent, typ, subtype, target, decision, reason, raw, prev_hash, event_hash),
            )
            self.conn.commit()
            return cur.lastrowid

    def recent(self, limit: int = 100):
        cur = self.conn.cursor()
        cur.execute("SELECT ts, agent, action_type, subtype, target, decision, reason, raw FROM events ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            ts, agent, action_type, subtype, target, decision, reason, raw = r
            matched = None
            parsed_raw = None
            if raw:
                try:
                    parsed_raw = json.loads(raw)
                except Exception:
                    try:
                        parsed_raw = ast.literal_eval(raw)
                    except Exception:
                        parsed_raw = None
                if isinstance(parsed_raw, dict):
                    matched = parsed_raw.get('_matched_rule')

            out.append({
                'timestamp': float(ts),
                'agent': agent,
                'action_type': action_type,
                'subtype': subtype,
                'target': target,
                'decision': decision,
                'reason': reason,
                'matched_rule': matched,
                'raw': parsed_raw or raw,
            })
        return out

    def pending(self, limit: int = 100):
        """Return events which are awaiting review (decision == 'review')."""
        cur = self.conn.cursor()
        cur.execute("SELECT id, ts, agent, action_type, subtype, target, decision, reason, raw FROM events WHERE decision = 'review' ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        out = []
        for r in rows:
            _id, ts, agent, action_type, subtype, target, decision, reason, raw = r
            matched = None
            parsed_raw = None
            if raw:
                try:
                    parsed_raw = json.loads(raw)
                except Exception:
                    try:
                        parsed_raw = ast.literal_eval(raw)
                    except Exception:
                        parsed_raw = None
                if isinstance(parsed_raw, dict):
                    matched = parsed_raw.get('_matched_rule')

            out.append({
                'id': _id,
                'timestamp': float(ts),
                'agent': agent,
                'action_type': action_type,
                'subtype': subtype,
                'target': target,
                'decision': decision,
                'reason': reason,
                'matched_rule': matched,
                'raw': parsed_raw or raw,
            })
        return out

    def set_decision(self, event_id: int, decision: str, reason: str = None):
        """Set decision for an existing event (allow/block) and update reason."""
        with self._write_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT id FROM events WHERE id = ?", (event_id,))
            row = cur.fetchone()
            if not row:
                raise ValueError('event not found')
            reason = reason or ("owner_approved" if decision == 'allow' else 'owner_blocked')
            cur.execute("UPDATE events SET decision = ?, reason = ? WHERE id = ?", (decision, reason, event_id))
            self.conn.commit()

    def clear_events(self):
        """Delete all events from the database. Used by dashboard clear action."""
        with self._write_lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM events")
            self.conn.commit()

    def get_event(self, event_id: int):
        cur = self.conn.cursor()
        cur.execute("SELECT id, ts, agent, action_type, subtype, target, decision, reason, raw FROM events WHERE id = ?", (event_id,))
        r = cur.fetchone()
        if not r:
            return None
        _id, ts, agent, action_type, subtype, target, decision, reason, raw = r
        return {
            'id': _id,
            'timestamp': float(ts),
            'agent': agent,
            'action_type': action_type,
            'subtype': subtype,
            'target': target,
            'decision': decision,
            'reason': reason,
            'raw': raw,
        }

    def verify_chain(self, limit: int = 1000) -> dict:
        """Verify the hash chain integrity of the most recent events.

        Returns:
            dict with 'valid' (bool), 'checked' (int), 'broken_at' (int or None)
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash, event_hash "
            "FROM events ORDER BY id ASC LIMIT ?",
            (limit,)
        )
        rows = cur.fetchall()

        expected_prev = "genesis"
        for row in rows:
            _id, ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash, event_hash = row

            # Skip events without hash (pre-migration)
            if not event_hash:
                continue

            if prev_hash != expected_prev:
                return {'valid': False, 'checked': len(rows), 'broken_at': _id}

            computed = self._compute_event_hash(
                ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash
            )
            if computed != event_hash:
                return {'valid': False, 'checked': len(rows), 'broken_at': _id}

            expected_prev = event_hash

        return {'valid': True, 'checked': len(rows), 'broken_at': None}

    def verify_full_chain(self) -> dict:
        """Verify the complete hash chain integrity of all events.

        Returns:
            dict with 'valid' (bool), 'total_events' (int), 'broken_at' (int or None),
            'gaps' (list of missing IDs), 'duplicates' (list of duplicate IDs)
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT id, ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash, event_hash "
            "FROM events ORDER BY id ASC"
        )
        rows = cur.fetchall()

        if not rows:
            return {'valid': True, 'total_events': 0, 'broken_at': None, 'gaps': [], 'duplicates': []}

        # Check for gaps in IDs
        ids = [row[0] for row in rows]
        expected_ids = set(range(1, max(ids) + 1))
        actual_ids = set(ids)
        gaps = sorted(expected_ids - actual_ids)

        # Check for duplicates
        duplicates = [id for id in ids if ids.count(id) > 1]

        expected_prev = "genesis"
        prev_ts = 0

        for row in rows:
            _id, ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash, event_hash = row

            # Validate timestamp monotonicity (events should be in chronological order)
            if ts < prev_ts:
                return {
                    'valid': False,
                    'total_events': len(rows),
                    'broken_at': _id,
                    'gaps': gaps,
                    'duplicates': duplicates,
                    'error': 'timestamp_not_monotonic'
                }
            prev_ts = ts

            # Skip events without hash (pre-migration)
            if not event_hash:
                continue

            if prev_hash != expected_prev:
                return {
                    'valid': False,
                    'total_events': len(rows),
                    'broken_at': _id,
                    'gaps': gaps,
                    'duplicates': duplicates,
                    'error': 'chain_broken'
                }

            computed = self._compute_event_hash(
                ts, agent, action_type, subtype, target, decision, reason, raw, prev_hash
            )
            if computed != event_hash:
                return {
                    'valid': False,
                    'total_events': len(rows),
                    'broken_at': _id,
                    'gaps': gaps,
                    'duplicates': duplicates,
                    'error': 'hash_mismatch'
                }

            expected_prev = event_hash

        return {
            'valid': True,
            'total_events': len(rows),
            'broken_at': None,
            'gaps': gaps,
            'duplicates': duplicates
        }

    def verify_database_integrity(self) -> dict:
        """Verify database file integrity and schema consistency.

        Returns:
            dict with 'valid' (bool), 'issues' (list of str)
        """
        issues = []

        try:
            # Check if database file exists and is readable
            if not os.path.exists(self.db_path):
                issues.append("database_file_missing")
                return {'valid': False, 'issues': issues}

            # Check file permissions (should not be world-writable)
            file_mode = os.stat(self.db_path).st_mode
            if file_mode & 0o022:  # group or other write permissions
                issues.append("insecure_file_permissions")

            # Verify schema integrity
            cur = self.conn.cursor()
            cur.execute("PRAGMA table_info(events)")
            columns = cur.fetchall()
            expected_columns = {
                'id': 'INTEGER',
                'ts': 'REAL',
                'agent': 'TEXT',
                'action_type': 'TEXT',
                'subtype': 'TEXT',
                'target': 'TEXT',
                'decision': 'TEXT',
                'reason': 'TEXT',
                'raw': 'TEXT',
                'prev_hash': 'TEXT',
                'event_hash': 'TEXT'
            }

            actual_columns = {col[1]: col[2] for col in columns}
            for col_name, expected_type in expected_columns.items():
                if col_name not in actual_columns:
                    issues.append(f"missing_column_{col_name}")
                elif actual_columns[col_name].upper() != expected_type:
                    issues.append(f"wrong_type_{col_name}")

            # Check for orphaned or invalid data
            cur.execute("SELECT COUNT(*) FROM events WHERE id IS NULL OR ts IS NULL")
            null_count = cur.fetchone()[0]
            if null_count > 0:
                issues.append(f"null_required_fields_{null_count}")

            # Check WAL mode is enabled
            cur.execute("PRAGMA journal_mode")
            journal_mode = cur.fetchone()[0]
            if journal_mode.upper() != 'WAL':
                issues.append("wal_mode_disabled")

        except Exception as e:
            issues.append(f"database_error_{str(e)}")

        return {'valid': len(issues) == 0, 'issues': issues}

    def get_integrity_report(self) -> dict:
        """Generate comprehensive integrity report.

        Returns:
            dict with overall status and detailed validation results
        """
        chain_verification = self.verify_full_chain()
        db_integrity = self.verify_database_integrity()
        file_tampering = self.detect_file_tampering()
        event_consistency = self.validate_event_consistency()

        # Get recent chain verification for performance
        recent_chain = self.verify_chain(limit=100)

        # Overall status
        overall_valid = (
            chain_verification['valid'] and
            db_integrity['valid'] and
            not file_tampering['tampered'] and
            event_consistency['valid']
        )

        return {
            'overall_valid': overall_valid,
            'timestamp': time.time(),
            'full_chain_verification': chain_verification,
            'recent_chain_verification': recent_chain,
            'database_integrity': db_integrity,
            'file_tampering_detection': file_tampering,
            'event_consistency': event_consistency,
            'recommendations': self._generate_integrity_recommendations(
                chain_verification, db_integrity, file_tampering, event_consistency
            )
        }

    def _generate_integrity_recommendations(self, chain_result: dict, db_result: dict,
                                          file_tamper_result: dict = None,
                                          consistency_result: dict = None) -> list:
        """Generate actionable recommendations based on integrity check results."""
        recommendations = []

        if not chain_result['valid']:
            if chain_result.get('error') == 'chain_broken':
                recommendations.append("CRITICAL: Hash chain is broken - possible tampering detected")
            elif chain_result.get('error') == 'hash_mismatch':
                recommendations.append("CRITICAL: Event data has been modified - integrity compromised")
            elif chain_result.get('error') == 'timestamp_not_monotonic':
                recommendations.append("WARNING: Events are not in chronological order")

            if chain_result.get('gaps'):
                recommendations.append(f"WARNING: Missing {len(chain_result['gaps'])} events - possible deletion")

            if chain_result.get('duplicates'):
                recommendations.append(f"WARNING: {len(chain_result['duplicates'])} duplicate events detected")

        if not db_result['valid']:
            for issue in db_result['issues']:
                if issue == "database_file_missing":
                    recommendations.append("CRITICAL: Database file is missing")
                elif issue == "insecure_file_permissions":
                    recommendations.append("SECURITY: Database file has insecure permissions")
                elif issue.startswith("missing_column"):
                    recommendations.append(f"CRITICAL: Database schema corrupted - {issue}")
                elif issue == "wal_mode_disabled":
                    recommendations.append("PERFORMANCE: WAL mode disabled - concurrent access unsafe")
                elif issue.startswith("database_error"):
                    recommendations.append(f"CRITICAL: Database access error - {issue}")

        if file_tamper_result and file_tamper_result['tampered']:
            recommendations.append("CRITICAL: Database file appears to have been tampered with externally")
            for change in file_tamper_result['changes']:
                recommendations.append(f"  - {change}")

        if consistency_result and not consistency_result['valid']:
            for issue in consistency_result['issues']:
                if issue.startswith("future_timestamps"):
                    recommendations.append("WARNING: Events with future timestamps detected")
                elif issue.startswith("ancient_timestamps"):
                    recommendations.append("WARNING: Events with very old timestamps detected")
                elif issue.startswith("rapid_events"):
                    recommendations.append("WARNING: Suspiciously rapid event sequence detected")
                elif issue == "mostly_allow_decisions":
                    recommendations.append("INFO: Unusual pattern - mostly allow decisions")
                elif issue == "mostly_block_decisions":
                    recommendations.append("INFO: Unusual pattern - mostly block decisions")

        if not recommendations:
            recommendations.append("All integrity checks passed")

        return recommendations

    def _get_file_stats(self) -> dict:
        """Get file statistics for tamper detection."""
        try:
            stat = os.stat(self.db_path)
            return {
                'size': stat.st_size,
                'mtime': stat.st_mtime,
                'ctime': stat.st_ctime,
                'ino': stat.st_ino
            }
        except Exception:
            return {}

    def detect_file_tampering(self) -> dict:
        """Detect if database file has been tampered with externally.

        Compares current file stats against baseline taken at initialization.
        Note: This is not foolproof but provides additional detection layer.

        Returns:
            dict with 'tampered' (bool), 'changes' (list of str)
        """
        current_stats = self._get_file_stats()
        if not self._baseline_stats:
            return {'tampered': False, 'changes': []}

        changes = []
        tampered = False

        # Check file size changes (unexpected growth/shrinkage)
        size_diff = current_stats.get('size', 0) - self._baseline_stats.get('size', 0)
        if abs(size_diff) > 1024:  # More than 1KB change
            changes.append(f"size_changed_{size_diff}bytes")
            tampered = True

        # Check modification time changes (file modified externally)
        mtime_diff = current_stats.get('mtime', 0) - self._baseline_stats.get('mtime', 0)
        if mtime_diff > 1.0:  # Modified more than 1 second after our baseline
            changes.append(f"mtime_changed_{mtime_diff:.1f}seconds")
            tampered = True

        # Check inode changes (file replaced)
        if current_stats.get('ino') != self._baseline_stats.get('ino'):
            changes.append("inode_changed_file_replaced")
            tampered = True

        return {'tampered': tampered, 'changes': changes}

    def validate_event_consistency(self) -> dict:
        """Validate logical consistency of events.

        Returns:
            dict with 'valid' (bool), 'issues' (list of str)
        """
        issues = []

        try:
            cur = self.conn.cursor()

            # Check for events with future timestamps
            future_threshold = time.time() + 300  # 5 minutes in future
            cur.execute("SELECT COUNT(*) FROM events WHERE ts > ?", (future_threshold,))
            future_count = cur.fetchone()[0]
            if future_count > 0:
                issues.append(f"future_timestamps_{future_count}")

            # Check for events with timestamps too far in the past
            past_threshold = time.time() - (365 * 24 * 60 * 60)  # 1 year ago
            cur.execute("SELECT COUNT(*) FROM events WHERE ts < ?", (past_threshold,))
            past_count = cur.fetchone()[0]
            if past_count > 0:
                issues.append(f"ancient_timestamps_{past_count}")

            # Check for suspiciously rapid events (possible automated attacks)
            # Use a simpler approach that works with SQLite
            cur.execute("""
                SELECT ts FROM events ORDER BY ts ASC LIMIT 1000
            """)
            timestamps = [row[0] for row in cur.fetchall()]
            rapid_count = 0
            for i in range(1, len(timestamps)):
                if timestamps[i] - timestamps[i-1] < 0.001:  # Less than 1ms apart
                    rapid_count += 1
            if rapid_count > 10:  # More than 10 events within 1ms
                issues.append(f"rapid_events_{rapid_count}")

            # Check decision distribution (shouldn't be all same decision)
            cur.execute("SELECT decision, COUNT(*) FROM events GROUP BY decision")
            decisions = dict(cur.fetchall())
            total_events = sum(decisions.values())

            if total_events > 10:  # Only check if we have meaningful data
                allow_ratio = decisions.get('allow', 0) / total_events
                block_ratio = decisions.get('block', 0) / total_events

                # If >95% same decision, might indicate policy issues or tampering
                if allow_ratio > 0.95:
                    issues.append("mostly_allow_decisions")
                elif block_ratio > 0.95:
                    issues.append("mostly_block_decisions")

        except Exception as e:
            issues.append(f"validation_error_{str(e)}")

        return {'valid': len(issues) == 0, 'issues': issues}

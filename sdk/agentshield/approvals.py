"""Approvals: First-class pending approval system.

When an action is marked for review, it enters the approval queue. This module
manages creating, waiting for, and resolving pending approvals.

Design: Approvals are stored in the storage backend (SQLite by default) with
timestamps, action details, and approval/block decisions. No CLI prompts—all
approvals happen via the dashboard.
"""
import time
from typing import Optional, Dict, Any


class ApprovalQueue:
    """Manages pending approvals for actions requiring review."""
    
    def __init__(self, storage):
        """Initialize with a storage backend.
        
        Args:
            storage: Storage instance (e.g., LocalStorage) that has:
                - set_decision(event_id, decision) -> mark approval as approve/block
                - get_event(event_id) -> retrieve event by id
        """
        self.storage = storage
    
    def create_pending(self, event_id: int, action: Dict[str, Any], 
                      timeout: int = 300) -> Dict[str, Any]:
        """Create a pending approval for an action.
        
        Args:
            event_id: Event ID from storage.log_event()
            action: The action being reviewed
            timeout: Seconds to wait before auto-denying (5 minutes default)
            
        Returns:
            Pending approval dict with timestamp, event_id, action, status
        """
        pending = {
            "event_id": event_id,
            "action": action,
            "created_at": time.time(),
            "timeout": timeout,
            "status": "pending",  # pending, approved, blocked
            "decided_at": None,
            "decided_by": None,
        }
        return pending
    
    def wait_for_approval(self, event_id: int, timeout: int = 300, 
                         poll_interval: float = 1.0) -> bool:
        """Wait for an approval decision on an event.
        
        Polls storage.get_event() until the decision field changes from
        'review' to either 'allow' or 'block', or until timeout elapses.
        
        Args:
            event_id: Event ID to wait for
            timeout: Max seconds to wait
            poll_interval: Sleep between polls (seconds)
            
        Returns:
            True if approved, False if blocked or timeout
        """
        start = time.time()
        while time.time() - start < timeout:
            ev = self.storage.get_event(event_id)
            if not ev:
                time.sleep(poll_interval)
                continue
            
            decision = ev.get('decision')
            if decision == 'allow':
                return True
            elif decision == 'block':
                return False
            
            time.sleep(poll_interval)
        
        # Timeout: deny by default (safe failure)
        return False
    
    def resolve_pending(self, event_id: int, approved: bool, 
                       decided_by: Optional[str] = None) -> Dict[str, Any]:
        """Resolve a pending approval (approve or block).
        
        Args:
            event_id: Event ID to resolve
            approved: True to approve, False to block
            decided_by: Optional identifier of who made the decision
            
        Returns:
            Updated approval dict with decision recorded
        """
        decision = 'allow' if approved else 'block'
        try:
            self.storage.set_decision(event_id, decision)
        except Exception:
            # If storage update fails, still record locally
            pass
        
        return {
            "event_id": event_id,
            "decision": decision,
            "decided_at": time.time(),
            "decided_by": decided_by,
            "status": "approved" if approved else "blocked",
        }
    
    def list_pending(self) -> list:
        """List all pending approvals from storage.

        Queries storage for events with decision='review'.

        Returns:
            List of pending approval events
        """
        try:
            return self.storage.pending()
        except Exception:
            return []


def normalize_approval_dto(approval: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an approval to a clean DTO for API/JSON serialization.
    
    Args:
        approval: Approval dict from queue or storage
        
    Returns:
        Clean DTO with relevant fields
    """
    return {
        "event_id": approval.get("event_id"),
        "action": approval.get("action"),
        "created_at": approval.get("created_at"),
        "status": approval.get("status", "pending"),
        "decided_at": approval.get("decided_at"),
        "decided_by": approval.get("decided_by"),
    }

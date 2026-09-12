"""
Subtree and Master Root Write-Freeze Manager for Module 3 (M3).

Provides temporary write-freeze mitigation capabilities triggered upon
anomaly detection alerts from Module 4 or administrative commands.
"""

from typing import Dict, Tuple, Optional, Any
from datetime import datetime, timezone
import uuid


class FreezeManager:
    """
    Manages write-freeze states for user subtrees and the global Master Root.
    Synchronizes state to an M3Database instance if provided.
    """
    MASTER_ID = "__GLOBAL_MASTER__"

    def __init__(self, db=None):
        self._master_frozen: bool = False
        self._master_freeze_reason: Optional[str] = None
        self._master_frozen_at: Optional[str] = None
        self._master_freeze_id: Optional[str] = None
        self._master_expires_at: Optional[str] = None
        self._master_initiated_by: Optional[str] = None

        # Maps user_id -> {"reason": str, "frozen_at": str, "freeze_id": str, "expires_at": str, "initiated_by": str}
        self._subtree_freezes: Dict[str, Dict[str, str]] = {}
        self.db = db
        
        if self.db:
            self._load_from_db()

    def _load_from_db(self):
        states = self.db.load_freeze_states()
        if self.MASTER_ID in states:
            master = states.pop(self.MASTER_ID)
            self._master_frozen = True
            self._master_freeze_reason = master["reason"]
            self._master_frozen_at = master["frozen_at"]
            self._master_freeze_id = master.get("freeze_id")
            self._master_expires_at = master.get("expires_at")
            self._master_initiated_by = master.get("initiated_by")
        self._subtree_freezes = states

    def freeze_master(self, reason: str = "Global security incident triggered", initiated_by: str = "system", expires_at: Optional[str] = None) -> Dict[str, Any]:
        """Freezes all write operations system-wide across all subtrees."""
        self._master_frozen = True
        self._master_freeze_reason = reason
        self._master_frozen_at = datetime.now(timezone.utc).isoformat()
        self._master_freeze_id = str(uuid.uuid4())
        self._master_expires_at = expires_at
        self._master_initiated_by = initiated_by
        
        if self.db:
            self.db.save_freeze_state(self.MASTER_ID, reason, self._master_frozen_at, self._master_freeze_id, self._master_expires_at, self._master_initiated_by)
            
        return {
            "target": "master",
            "status": "frozen",
            "freeze_id": self._master_freeze_id,
            "reason": self._master_freeze_reason,
            "timestamp": self._master_frozen_at,
            "expires_at": self._master_expires_at,
            "initiated_by": self._master_initiated_by
        }

    def unfreeze_master(self) -> Dict[str, Any]:
        """Unfreezes system-wide write operations."""
        self._master_frozen = False
        reason = self._master_freeze_reason
        self._master_freeze_reason = None
        self._master_frozen_at = None
        
        if self.db:
            self.db.delete_freeze_state(self.MASTER_ID)
            
        return {
            "target": "master",
            "status": "unfrozen",
            "previous_reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def freeze_subtree(self, user_id: str, reason: str = "Suspicious activity detected for user", initiated_by: str = "system", expires_at: Optional[str] = None) -> Dict[str, Any]:
        """Freezes write operations on a specific user's subtree."""
        frozen_at = datetime.now(timezone.utc).isoformat()
        freeze_id = str(uuid.uuid4())
        self._subtree_freezes[user_id] = {
            "reason": reason,
            "frozen_at": frozen_at,
            "freeze_id": freeze_id,
            "expires_at": expires_at,
            "initiated_by": initiated_by
        }
        
        if self.db:
            self.db.save_freeze_state(user_id, reason, frozen_at, freeze_id, expires_at, initiated_by)
            
        return {
            "target": "subtree",
            "user_id": user_id,
            "status": "frozen",
            "freeze_id": freeze_id,
            "reason": reason,
            "timestamp": frozen_at,
            "expires_at": expires_at,
            "initiated_by": initiated_by
        }

    def unfreeze_subtree(self, user_id: str) -> Dict[str, Any]:
        """Unfreezes write operations on a specific user's subtree."""
        prev = self._subtree_freezes.pop(user_id, None)
        
        if self.db:
            self.db.delete_freeze_state(user_id)
            
        return {
            "target": "subtree",
            "user_id": user_id,
            "status": "unfrozen",
            "previous_reason": prev["reason"] if prev else None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def is_frozen(self, user_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Checks if write operations are currently frozen for master or a user subtree.
        Enforces expiry logic dynamically.

        Returns:
            Tuple[bool, Optional[str]]: (is_frozen, reason)
        """
        now = datetime.now(timezone.utc)
        
        # Check master freeze
        if self._master_frozen:
            if self._master_expires_at:
                try:
                    expires_dt = datetime.fromisoformat(self._master_expires_at.replace("Z", "+00:00"))
                    if now >= expires_dt:
                        self.unfreeze_master()
                        return False, None
                except ValueError:
                    pass
            return True, f"Master Tree Frozen: {self._master_freeze_reason}"

        # Check subtree freeze
        if user_id and user_id in self._subtree_freezes:
            info = self._subtree_freezes[user_id]
            expires_at_str = info.get("expires_at")
            if expires_at_str:
                try:
                    expires_dt = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    if now >= expires_dt:
                        self.unfreeze_subtree(user_id)
                        return False, None
                except ValueError:
                    pass
            return True, f"Subtree Frozen: {info['reason']}"

        return False, None

    def get_freeze_status(self) -> Dict[str, Any]:
        """Returns overview of all current freezes."""
        return {
            "master_frozen": self._master_frozen,
            "master_freeze_reason": self._master_freeze_reason,
            "master_frozen_at": self._master_frozen_at,
            "subtree_freezes_count": len(self._subtree_freezes),
            "subtree_freezes": self._subtree_freezes
        }

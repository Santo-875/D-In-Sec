"""
Subtree and Master Root Write-Freeze Manager for Module 3 (M3).

Provides temporary write-freeze mitigation capabilities triggered upon
anomaly detection alerts from Module 4 or administrative commands.
"""

from typing import Dict, Tuple, Optional, Any
from datetime import datetime, timezone


class FreezeManager:
    """
    Manages write-freeze states for user subtrees and the global Master Root.
    """
    def __init__(self):
        self._master_frozen: bool = False
        self._master_freeze_reason: Optional[str] = None
        self._master_frozen_at: Optional[str] = None

        # Maps user_id -> {"reason": str, "frozen_at": str}
        self._subtree_freezes: Dict[str, Dict[str, str]] = {}

    def freeze_master(self, reason: str = "Global security incident triggered") -> Dict[str, Any]:
        """Freezes all write operations system-wide across all subtrees."""
        self._master_frozen = True
        self._master_freeze_reason = reason
        self._master_frozen_at = datetime.now(timezone.utc).isoformat()
        return {
            "target": "master",
            "status": "frozen",
            "reason": self._master_freeze_reason,
            "timestamp": self._master_frozen_at
        }

    def unfreeze_master(self) -> Dict[str, Any]:
        """Unfreezes system-wide write operations."""
        self._master_frozen = False
        reason = self._master_freeze_reason
        self._master_freeze_reason = None
        self._master_frozen_at = None
        return {
            "target": "master",
            "status": "unfrozen",
            "previous_reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def freeze_subtree(self, user_id: str, reason: str = "Suspicious activity detected for user") -> Dict[str, Any]:
        """Freezes write operations on a specific user's subtree."""
        frozen_at = datetime.now(timezone.utc).isoformat()
        self._subtree_freezes[user_id] = {
            "reason": reason,
            "frozen_at": frozen_at
        }
        return {
            "target": "subtree",
            "user_id": user_id,
            "status": "frozen",
            "reason": reason,
            "timestamp": frozen_at
        }

    def unfreeze_subtree(self, user_id: str) -> Dict[str, Any]:
        """Unfreezes write operations on a specific user's subtree."""
        prev = self._subtree_freezes.pop(user_id, None)
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

        Returns:
            Tuple[bool, Optional[str]]: (is_frozen, reason)
        """
        if self._master_frozen:
            return True, f"Master Tree Frozen: {self._master_freeze_reason}"

        if user_id and user_id in self._subtree_freezes:
            info = self._subtree_freezes[user_id]
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

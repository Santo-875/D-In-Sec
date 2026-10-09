"""
Append-Only Audit Log & CERT-In 180-Day Retention Manager for Module 3 (M3).

Maintains a permanent, tamper-evident record of all system events:
  - Detailed update logs retained for rolling 180-day window (CERT-In requirement).
  - Permanent 32-byte Root Hash chain checkpoints retained indefinitely.
  - External Anchoring Export (WORM / RFC 3161 / Public Ledger).
"""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any


def _compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


class AuditLogEntry:
    """
    Detailed audit log entry recording a single signed state update.
    """
    def __init__(
        self,
        event_id: str,
        timestamp: str,
        user_id: str,
        leaf_id: str,
        old_leaf_hash: str | None,
        new_leaf_hash: str,
        old_master_root: str,
        new_master_root: str,
        signature_hex: str,
        signer_fingerprint: str,
        previous_hash: str | None = None,
        event_hash: str | None = None
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.user_id = user_id
        self.leaf_id = leaf_id
        self.old_leaf_hash = old_leaf_hash
        self.new_leaf_hash = new_leaf_hash
        self.old_master_root = old_master_root
        self.new_master_root = new_master_root
        self.signature_hex = signature_hex
        self.signer_fingerprint = signer_fingerprint
        self.previous_hash = previous_hash
        
        if event_hash:
            self.event_hash = event_hash
        else:
            # Compute event_hash cryptographically linking to previous_hash
            payload_to_hash = f"{self.previous_hash or 'GENESIS'}:{self.event_id}:{self.timestamp}:{self.new_leaf_hash}:{self.new_master_root}:{self.signature_hex}"
            self.event_hash = _compute_hash(payload_to_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "leaf_id": self.leaf_id,
            "old_leaf_hash": self.old_leaf_hash,
            "new_leaf_hash": self.new_leaf_hash,
            "old_master_root": self.old_master_root,
            "new_master_root": self.new_master_root,
            "signature_hex": self.signature_hex,
            "signer_fingerprint": self.signer_fingerprint,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash
        }


class PermanentRootCheckpoint:
    """
    32-byte Master Root Checkpoint retained permanently even after detailed log pruning.
    Forms a cryptographic hash chain.
    """
    def __init__(self, event_id: str, timestamp: str, master_root: str, user_id: str, previous_hash: str | None = None, checkpoint_hash: str | None = None):
        self.event_id = event_id
        self.timestamp = timestamp
        self.master_root = master_root
        self.user_id = user_id
        self.previous_hash = previous_hash
        
        if checkpoint_hash:
            self.checkpoint_hash = checkpoint_hash
        else:
            payload_to_hash = f"{self.previous_hash or 'GENESIS'}:{self.event_id}:{self.timestamp}:{self.master_root}"
            self.checkpoint_hash = _compute_hash(payload_to_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "master_root": self.master_root,
            "user_id": self.user_id,
            "previous_hash": self.previous_hash,
            "checkpoint_hash": self.checkpoint_hash
        }


class AppendOnlyAuditLog:
    """
    Append-only log store managing detailed event logs and permanent root hash checkpoints.
    Synchronizes state to an M3Database instance if provided.
    """
    RETENTION_DAYS = 180

    def __init__(self, db=None, external_anchor=None):
        self._detailed_logs: list[AuditLogEntry] = []
        self._permanent_root_chain: list[PermanentRootCheckpoint] = []
        self._event_index: dict[str, AuditLogEntry] = {}
        self.db = db
        self.external_anchor = external_anchor
        
        if self.db:
            self._load_from_db()

    def _load_from_db(self):
        """Loads existing audit events and checkpoints from the database."""
        self._detailed_logs.clear()
        self._event_index.clear()
        self._permanent_root_chain.clear()
        
        events = self.db.load_audit_events()
        for e in events:
            entry = AuditLogEntry(**e)
            self._detailed_logs.append(entry)
            self._event_index[entry.event_id] = entry
            
        checkpoints = self.db.load_checkpoints()
        for c in checkpoints:
            chk = PermanentRootCheckpoint(**c)
            self._permanent_root_chain.append(chk)

    def log_event(
        self,
        user_id: str,
        leaf_id: str,
        old_leaf_hash: str | None,
        new_leaf_hash: str,
        old_master_root: str,
        new_master_root: str,
        signature_hex: str,
        signer_fingerprint: str,
        timestamp: str | None = None,
        event_id: str | None = None,
        conn = None
    ) -> AuditLogEntry:
        """
        Records a new verified tree update.
        Maintains cryptographic chain via previous_hash.
        """
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat()
        if not event_id:
            event_id = f"evt_{uuid.uuid4().hex[:12]}"

        # Calculate previous event hash
        prev_event_hash = self._detailed_logs[-1].event_hash if self._detailed_logs else None

        entry = AuditLogEntry(
            event_id=event_id,
            timestamp=timestamp,
            user_id=user_id,
            leaf_id=leaf_id,
            old_leaf_hash=old_leaf_hash,
            new_leaf_hash=new_leaf_hash,
            old_master_root=old_master_root,
            new_master_root=new_master_root,
            signature_hex=signature_hex,
            signer_fingerprint=signer_fingerprint,
            previous_hash=prev_event_hash
        )

        self._detailed_logs.append(entry)
        self._event_index[event_id] = entry

        # Calculate previous checkpoint hash
        prev_chk_hash = self._permanent_root_chain[-1].checkpoint_hash if self._permanent_root_chain else None

        checkpoint = PermanentRootCheckpoint(
            event_id=event_id,
            timestamp=timestamp,
            master_root=new_master_root,
            user_id=user_id,
            previous_hash=prev_chk_hash
        )
        self._permanent_root_chain.append(checkpoint)
        
        # Save to DB and external anchor if configured
        if self.db:
            self.db.save_audit_event(entry.to_dict(), conn=conn)
            self.db.save_checkpoint(checkpoint.to_dict(), conn=conn)
        
        if self.external_anchor:
            self.external_anchor.anchor_checkpoint(checkpoint.to_dict())

        return entry

    def get_event(self, event_id: str) -> AuditLogEntry | None:
        """Retrieves a detailed event entry by event_id."""
        return self._event_index.get(event_id)

    def get_all_detailed_logs(self) -> list[dict[str, Any]]:
        """Returns all detailed logs."""
        return [log.to_dict() for log in self._detailed_logs]

    def get_permanent_root_chain(self) -> list[dict[str, Any]]:
        """Returns the complete permanent root hash checkpoint chain."""
        return [cp.to_dict() for cp in self._permanent_root_chain]

    def prune_logs_older_than(self, days: int = RETENTION_DAYS, reference_now: datetime | None = None) -> dict[str, Any]:
        """
        Prunes detailed event logs older than `days` (default 180 days for CERT-In).
        The permanent 32-byte root hash chain is NEVER pruned.

        Returns:
            Dict[str, Any]: Pruning summary metrics.
        """
        if reference_now is None:
            reference_now = datetime.now(timezone.utc)

        cutoff_date = reference_now - timedelta(days=days)
        retained_logs = []
        pruned_count = 0

        for entry in self._detailed_logs:
            try:
                entry_dt = datetime.fromisoformat(entry.timestamp.replace('Z', '+00:00'))
            except ValueError:
                retained_logs.append(entry)
                continue

            if entry_dt >= cutoff_date:
                retained_logs.append(entry)
            else:
                pruned_count += 1
                if entry.event_id in self._event_index:
                    del self._event_index[entry.event_id]

        self._detailed_logs = retained_logs

        if self.db:
            self.db.prune_audit_events(cutoff_date.isoformat())

        return {
            "retention_policy_days": days,
            "cutoff_timestamp": cutoff_date.isoformat(),
            "logs_pruned": pruned_count,
            "detailed_logs_remaining": len(self._detailed_logs),
            "permanent_root_checkpoints_preserved": len(self._permanent_root_chain)
        }

    def export_external_anchors(self) -> list[dict[str, Any]]:
        """
        Exports permanent 32-byte root checkpoints formatted for external WORM / RFC 3161 / ledger anchoring.
        """
        return [
            {
                "sequence_id": idx + 1,
                "event_id": cp.event_id,
                "timestamp": cp.timestamp,
                "root_hash_32bytes": cp.master_root,
                "anchor_payload": f"{cp.event_id}:{cp.timestamp}:{cp.master_root}"
            }
            for idx, cp in enumerate(self._permanent_root_chain)
        ]

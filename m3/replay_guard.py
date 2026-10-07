"""
Anti-Replay Protection Guard for Module 3 (M3).

Prevents replay attacks by tracking and rejecting:
  1. Duplicate event_id values (attacker resending a captured request)
  2. Duplicate nonce values (same request body replayed)
  3. Stale timestamps (captured requests replayed after a time window)
  4. Version regression (leaf version going backwards)

Storage is in-memory with periodic TTL-based cleanup.
Phase 2 will persist this to SQLite for durability across restarts.
"""

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("m3.replay_guard")

# Requests older than this many seconds are rejected as stale
DEFAULT_MAX_AGE_SECONDS = 300  # 5 minutes

# Cleanup entries older than this to prevent unbounded memory growth
CLEANUP_TTL_SECONDS = 600  # 10 minutes


class ReplayGuard:
    """
    Thread-safe anti-replay protection engine.

    Tracks seen event_ids and nonces, validates timestamps,
    and enforces monotonic version progression per leaf.
    """

    def __init__(self, max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS, db=None):
        self._max_age = max_age_seconds
        self._lock = threading.Lock()
        self.db = db

        # Seen event IDs with their insertion timestamp (for TTL cleanup)
        self._seen_event_ids: dict[str, float] = {}

        # Seen nonces with their insertion timestamp
        self._seen_nonces: dict[str, float] = {}

        # Current version per leaf: (user_id, leaf_id) -> version
        self._leaf_versions: dict[tuple[str, str], int] = {}
        
        if self.db:
            self._load_from_db()

    def _load_from_db(self):
        self._seen_event_ids.clear()
        self._seen_nonces.clear()
        self._leaf_versions.clear()
        
        with self.db.get_connection() as conn:
            # Load events
            cur = conn.execute("SELECT event_id, timestamp FROM replay_guard_events")
            for row in cur.fetchall():
                try:
                    ts = datetime.fromisoformat(row[1].replace("Z", "+00:00")).timestamp()
                    self._seen_event_ids[row[0]] = ts
                except ValueError:
                    pass
            # Load nonces
            cur = conn.execute("SELECT nonce, timestamp FROM replay_guard_nonces")
            for row in cur.fetchall():
                try:
                    ts = datetime.fromisoformat(row[1].replace("Z", "+00:00")).timestamp()
                    self._seen_nonces[row[0]] = ts
                except ValueError:
                    pass
            # Load versions
            cur = conn.execute("SELECT user_id, leaf_id, version FROM replay_guard_versions")
            for row in cur.fetchall():
                self._leaf_versions[(row[0], row[1])] = row[2]

    def validate_request(
        self,
        event_id: str,
        nonce: str,
        timestamp: str,
        user_id: str,
        leaf_id: str,
        version: int | None = None,
        conn: Any | None = None
    ) -> tuple[bool, str | None]:
        """
        Validates an incoming request against all replay protection checks.

        Args:
            event_id: Unique identifier for this event.
            nonce: Random value ensuring request uniqueness.
            timestamp: ISO-8601 timestamp from the client.
            user_id: User identifier.
            leaf_id: Leaf identifier.
            version: Optional leaf version number.

        Returns:
            (True, None) if the request is valid.
            (False, reason) if the request should be rejected.
        """
        now = time.time()

        # Periodically clean up expired entries
        self._cleanup_expired(now)

        with self._lock:
            # 1. Check duplicate event_id
            if event_id in self._seen_event_ids:
                return False, f"Duplicate event_id '{event_id}'. Possible replay attack."

            # 2. Check duplicate nonce
            if nonce in self._seen_nonces:
                return False, f"Duplicate nonce '{nonce}'. Possible replay attack."

            # 3. Validate timestamp freshness
            ts_valid, ts_reason = self._check_timestamp(timestamp)
            if not ts_valid:
                return False, ts_reason

            # 4. Check version regression (if version provided)
            if version is not None:
                leaf_key = (user_id, leaf_id)
                current_version = self._leaf_versions.get(leaf_key, 0)
                if version <= current_version:
                    return False, (
                        f"Version regression detected for ({user_id}, {leaf_id}): "
                        f"received v{version}, current is v{current_version}."
                    )

            # All checks passed — record this request
            self._seen_event_ids[event_id] = now
            self._seen_nonces[nonce] = now

            if version is not None:
                self._leaf_versions[(user_id, leaf_id)] = version
                
            if self.db:
                self.db.save_replay_guard(event_id, nonce, timestamp, user_id, leaf_id, version, conn=conn)

        return True, None

    def _check_timestamp(self, timestamp: str) -> tuple[bool, str | None]:
        """Validates that the timestamp is within the acceptable time window."""
        try:
            ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return False, f"Invalid timestamp format: '{timestamp}'. Expected ISO-8601."

        now_utc = datetime.now(timezone.utc)
        age = (now_utc - ts).total_seconds()

        if age > self._max_age:
            return False, (
                f"Stale timestamp: {timestamp} is {int(age)}s old "
                f"(max allowed: {self._max_age}s). Possible replay attack."
            )

        # Also reject timestamps significantly in the future (clock skew tolerance: 30s)
        if age < -30:
            return False, (
                f"Timestamp {timestamp} is {int(abs(age))}s in the future. "
                f"Check client clock synchronization."
            )

        return True, None

    def _cleanup_expired(self, now: float) -> None:
        """Removes entries older than CLEANUP_TTL_SECONDS to prevent memory growth."""
        cutoff = now - CLEANUP_TTL_SECONDS

        with self._lock:
            expired_events = [eid for eid, ts in self._seen_event_ids.items() if ts < cutoff]
            for eid in expired_events:
                del self._seen_event_ids[eid]

            expired_nonces = [n for n, ts in self._seen_nonces.items() if ts < cutoff]
            for n in expired_nonces:
                del self._seen_nonces[n]
                
            if self.db and (expired_events or expired_nonces):
                self.db.delete_expired_replay_guard(expired_events, expired_nonces, conn=None)

        if expired_events or expired_nonces:
            logger.debug(
                f"Replay guard cleanup: removed {len(expired_events)} event_ids, "
                f"{len(expired_nonces)} nonces."
            )

    def get_stats(self) -> dict[str, int]:
        """Returns current tracking counts for monitoring."""
        with self._lock:
            return {
                "tracked_event_ids": len(self._seen_event_ids),
                "tracked_nonces": len(self._seen_nonces),
                "tracked_leaf_versions": len(self._leaf_versions),
            }

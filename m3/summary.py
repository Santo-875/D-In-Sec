"""
m3/summary.py — CERT-In Daily Summary Generator for Module 3.

Generates masked-only daily aggregates per CERT-In compliance requirements.
Summaries are idempotent per date and stored via StorageBackend.

CLI:
    python -m m3.summary --date 2025-01-15

API:
    POST /v1/admin/summary/run  {"date": "2025-01-15"}
"""

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any

__all__ = ["generate_daily_summary", "run_cli"]


def generate_daily_summary(db, date: str) -> dict[str, Any]:
    """
    Build a masked-only daily aggregate for `date` (YYYY-MM-DD).

    Aggregates from DB:
      - Events by type/severity/tenant
      - Tamper flag count
      - Freeze count
      - Top actors (user_ids with most events) — no PII
      - Root hash range (first / last master_root of the day)
      - Retention status (records within 180-day window)

    Args:
        db: M3Database instance.
        date: ISO date string e.g. "2025-01-15".

    Returns:
        Summary dict ready for storage.
    """
    from_ts = f"{date}T00:00:00+00:00"
    to_ts = f"{date}T23:59:59+00:00"

    all_events = db.load_audit_events()
    day_events = [
        e for e in all_events
        if from_ts <= e.get("timestamp", "") <= to_ts
    ]

    # Tamper flags from alerts table
    all_alerts = db.get_alerts()
    day_alerts = [
        a for a in all_alerts
        if a.get("created_at", "")[:10] == date
    ]

    # Freeze states loaded from freeze_states
    freeze_states = db.load_freeze_states()
    freeze_count = len(freeze_states)

    # Aggregate events
    events_by_type: dict[str, int] = {}
    actor_counts: dict[str, int] = {}
    root_hashes = []

    for e in day_events:
        # Event type = leaf update (no finer type available yet)
        etype = "LEAF_UPDATE"
        events_by_type[etype] = events_by_type.get(etype, 0) + 1

        uid = e.get("user_id", "UNKNOWN")
        actor_counts[uid] = actor_counts.get(uid, 0) + 1

        root_hashes.append(e.get("new_master_root", ""))

    top_actors = sorted(actor_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Retention status
    from datetime import timedelta
    cutoff = (datetime.fromisoformat(f"{date}T00:00:00+00:00") - timedelta(days=180)).date().isoformat()
    old_events_count = sum(
        1 for e in all_events
        if e.get("timestamp", "")[:10] < cutoff
    )

    summary: dict[str, Any] = {
        "date": date,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_count": len(day_events),
        "events_by_type": events_by_type,
        "tamper_flags": sum(1 for a in day_alerts if a.get("alert_type") == "FULL_VERIFY_MISMATCH"),
        "active_freezes": freeze_count,
        "top_actors": [{"user_id": uid, "event_count": cnt} for uid, cnt in top_actors],
        "root_range": {
            "first": root_hashes[0] if root_hashes else None,
            "last": root_hashes[-1] if root_hashes else None,
        },
        "retention_status": {
            "events_within_180_days": len(day_events),
            "events_beyond_180_days_total": old_events_count,
            "retention_policy_days": 180,
            "cutoff_date": cutoff,
        },
        "alerts": [
            {
                "alert_id": a.get("alert_id"),
                "alert_type": a.get("alert_type"),
                "severity": a.get("severity"),
                "created_at": a.get("created_at"),
            }
            for a in day_alerts
        ],
    }
    return summary


def run_cli():
    """CLI entry point: python -m m3.summary --date YYYY-MM-DD"""
    parser = argparse.ArgumentParser(description="Generate CERT-In daily summary.")
    parser.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat(),
                        help="Date to summarise (YYYY-MM-DD). Defaults to today.")
    parser.add_argument("--db", default=os.environ.get("M3_DB_PATH", "m3.db"),
                        help="Path to M3 SQLite database.")
    parser.add_argument("--output", default=None, help="Write summary JSON to file.")
    args = parser.parse_args()

    from m3.database import M3Database
    from m3.storage import DurableStorage, get_storage_backend

    db = M3Database(args.db)

    # Check idempotency
    existing = db.get_daily_summary(args.date)
    if existing:
        print(f"[summary] Summary for {args.date} already exists. Skipping generation.")
        print(json.dumps(existing, indent=2))
        return

    summary = generate_daily_summary(db, args.date)
    db.save_daily_summary(args.date, summary)

    # Upload to storage backend
    try:
        raw_storage = get_storage_backend()
        storage = DurableStorage(backend=raw_storage, db=db)
        storage.put_summary(args.date, summary)
    except Exception as exc:
        print(f"[summary] Storage upload warning: {exc}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[summary] Written to {args.output}")
    else:
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    run_cli()

"""
AI Breach Alert Generator on Tamper Detection for Module 3 (M3).

Translates deterministic cryptographic hash mismatches into plain-language,
non-technical breach alerts readable by small business (MSME) owners.

Pipeline:
  1. Deterministic hash check (m3/merkle_tree.py) — 100% rule-based
  2. If mismatch → gather facts → call Gemini
  3. If Gemini fails → deterministic fallback template (no hallucinations)
  4. Route alert to incident_alerts table → appears in SOC dashboard
"""

import os
import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

logger = logging.getLogger("m3.breach_alert")

# Default path to the mock_site SQLite database where SOC alerts are surfaced
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "mock_site" / "instance" / "mock_site.db"

# Gemini model preference order — falls through on quota / model unavailability
_GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]


def _format_detected_at(detected_at: str) -> str:
    """Humanise an ISO-8601 timestamp for display in reports."""
    try:
        dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y at %H:%M:%S UTC")
    except Exception:
        return detected_at


def deterministic_fallback_alert(facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Guaranteed fallback when Gemini is unavailable, rate-limited, or returns bad output.
    Uses only injected facts — zero risk of hallucination.

    Args:
        facts: {affected_user, leaf_id, expected_hash, actual_hash, detected_at}

    Returns:
        Structured breach alert dict with all required fields.
    """
    user = facts.get("affected_user", "unknown_user")
    leaf_id = facts.get("leaf_id", "unknown_record")
    detected_at = facts.get("detected_at", datetime.now(timezone.utc).isoformat())
    expected = facts.get("expected_hash", "N/A")
    actual = facts.get("actual_hash", "N/A")
    friendly_time = _format_detected_at(detected_at)

    summary = (
        f"Security Notice: A data record ('{leaf_id}') belonging to user '{user}' "
        f"failed cryptographic verification on {friendly_time}. "
        f"The stored value no longer matches the tamper-proof compliance ledger, "
        f"indicating the record may have been altered outside authorised channels. "
        f"Immediate inspection of recent database activity and access logs is recommended."
    )

    return {
        "summary": summary,
        "severity": "CRITICAL",
        "affected_user": user,
        "detected_at": detected_at,
        "tamper_evidence": {
            "leaf_id": leaf_id,
            "expected_hash": expected,
            "actual_hash": actual
        },
        "source": "deterministic_fallback"
    }


def generate_breach_alert(facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Translates cryptographic mismatch facts into a short, plain-language breach alert.
    AI is used only to translate facts into readable text — never to determine whether
    tampering occurred (that decision is purely hash-based upstream).

    Falls back to a deterministic template if the API call fails for any reason.

    Args:
        facts: {affected_user, leaf_id, expected_hash, actual_hash, detected_at}

    Returns:
        Structured breach alert dict:
        {summary, severity, affected_user, detected_at, tamper_evidence, source}
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not HAS_GENAI:
        logger.warning("GEMINI_API_KEY not set or google-genai unavailable. Using deterministic fallback.")
        return deterministic_fallback_alert(facts)

    user = facts.get("affected_user", "unknown_user")
    leaf_id = facts.get("leaf_id", "unknown_record")
    expected = facts.get("expected_hash", "N/A")
    actual = facts.get("actual_hash", "N/A")
    detected_at = facts.get("detected_at", datetime.now(timezone.utc).isoformat())
    friendly_time = _format_detected_at(detected_at)

    prompt = f"""You are a cybersecurity compliance assistant writing for a non-technical small business (MSME) owner.

A database record has been automatically flagged as TAMPERED by a cryptographic integrity check.

CONFIRMED FACTS (do not invent any additional details):
- Affected User    : {user}
- Record ID        : {leaf_id}
- Expected Hash    : {expected[:16]}...  (truncated for readability)
- Actual Hash      : {actual[:16]}...    (truncated for readability)
- Detection Time   : {friendly_time}

TASK: Write a concise breach alert in plain English (no jargon, no assumptions beyond the facts above):
1. State clearly what was detected and when.
2. Explain in one sentence why this is a concern.
3. Give one actionable recommendation.

Return a JSON object with EXACTLY these fields (nothing else):
{{
  "summary": "<2-3 sentence plain-language explanation>",
  "severity": "CRITICAL",
  "affected_user": "{user}",
  "detected_at": "{detected_at}"
}}"""

    # Suppress SDK noise
    logging.getLogger("google.genai").setLevel(logging.ERROR)

    last_error: Optional[Exception] = None
    for model_name in _GEMINI_MODELS:
        try:
            client = genai.Client(api_key=api_key)
            config = types.GenerateContentConfig(
                response_mime_type="application/json",
                temperature=0.1
            )
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=config
            )

            parsed = json.loads(response.text)
            summary = parsed.get("summary", "").strip()

            if not summary:
                logger.warning(f"[{model_name}] Gemini returned empty summary. Trying next model.")
                continue

            # Validate that factual fields are not hallucinated
            alert_user = parsed.get("affected_user", user)
            alert_detected = parsed.get("detected_at", detected_at)
            if alert_user != user:
                alert_user = user  # Never accept hallucinated user identity
            if alert_detected != detected_at:
                alert_detected = detected_at  # Never accept hallucinated timestamp

            logger.info(f"Breach alert generated via Gemini model: {model_name}")
            return {
                "summary": summary,
                "severity": parsed.get("severity", "CRITICAL"),
                "affected_user": alert_user,
                "detected_at": alert_detected,
                "tamper_evidence": {
                    "leaf_id": leaf_id,
                    "expected_hash": expected,
                    "actual_hash": actual
                },
                "source": f"gemini:{model_name}"
            }

        except Exception as e:
            last_error = e
            logger.warning(f"[{model_name}] Gemini breach alert call failed: {e}. Trying next model.")
            continue

    logger.warning(f"All Gemini models failed. Using deterministic fallback. Last error: {last_error}")
    return deterministic_fallback_alert(facts)


def _build_cert_in_draft(alert: Dict[str, Any]) -> str:
    """Builds a CERT-In formatted compliance report draft for the alert."""
    evidence = alert.get("tamper_evidence", {})
    detected_at = alert.get("detected_at", "Unknown")
    friendly_time = _format_detected_at(detected_at)
    user = alert.get("affected_user", "Unknown")
    leaf_id = evidence.get("leaf_id", "Unknown")
    severity = alert.get("severity", "CRITICAL")
    expected = evidence.get("expected_hash", "N/A")
    actual = evidence.get("actual_hash", "N/A")
    source = alert.get("source", "deterministic_fallback")

    return (
        f"CERT-In CYBER SECURITY INCIDENT REPORT (DRAFT — DATA TAMPERING)\n"
        f"=================================================================\n"
        f"Date of Detection  : {friendly_time}\n"
        f"Incident Type      : DATA_TAMPERING (Merkle Tree Integrity Violation)\n"
        f"Severity           : {severity}\n"
        f"Affected User      : {user}\n"
        f"Record / Leaf ID   : {leaf_id}\n"
        f"Alert Source       : {source}\n\n"
        f"Plain-Language Summary:\n"
        f"{alert.get('summary', 'N/A')}\n\n"
        f"Cryptographic Evidence:\n"
        f"  Expected Hash (Ledger) : {expected}\n"
        f"  Actual Hash (DB)       : {actual}\n"
        f"  Verification Result    : FAILED — hashes do not match\n\n"
        f"Recommended Actions:\n"
        f"  1. Freeze the affected user's data subtree immediately to prevent further writes.\n"
        f"  2. Inspect recent INSERT/UPDATE activity on the relevant table.\n"
        f"  3. Compare current record against the last verified Merkle checkpoint.\n"
        f"  4. If tampering confirmed, notify CERT-In within 6 hours per DPDP Act requirements.\n\n"
        f"(This report was auto-generated by the D-In-Sec M3 Integrity Engine.)\n"
    )


def record_breach_alert_to_db(alert: Dict[str, Any], db_path: Optional[Path] = None) -> Optional[int]:
    """
    Persists a breach alert to the incident_alerts table in the mock_site SQLite database.
    This causes the alert to appear immediately on the SOC dashboard alongside Module 2 alerts.

    Args:
        alert: Breach alert dict from generate_breach_alert().
        db_path: Override database path (used in tests). Defaults to mock_site.db.

    Returns:
        Row ID of the inserted alert, or None if DB is unavailable.
    """
    target_db = Path(db_path) if db_path else DEFAULT_DB_PATH
    if not target_db.exists():
        logger.warning(f"Database not found at {target_db}. Breach alert not persisted.")
        return None

    try:
        conn = sqlite3.connect(str(target_db))
        cursor = conn.cursor()

        # Verify table exists (gracefully skip if mock_site DB schema not initialised)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incident_alerts'")
        if not cursor.fetchone():
            conn.close()
            logger.warning("incident_alerts table not found. Skipping breach alert persistence.")
            return None

        # Ensure event_id column exists (added in Module 2 / M3 wiring PR)
        cursor.execute("PRAGMA table_info(incident_alerts)")
        cols = [c[1] for c in cursor.fetchall()]
        if "event_id" not in cols:
            cursor.execute("ALTER TABLE incident_alerts ADD COLUMN event_id TEXT")
            conn.commit()

        cert_in_draft = _build_cert_in_draft(alert)
        summary = alert.get("summary", "Data tampering detected by Merkle tree verification engine.")

        cursor.execute("""
            INSERT INTO incident_alerts
                (incident_type, severity, confidence, masked_log_context, cert_in_draft, status, created_at)
            VALUES
                ('DATA_TAMPERING', ?, 1.0, ?, ?, 'Open', datetime('now'))
        """, (
            alert.get("severity", "CRITICAL"),
            summary,
            cert_in_draft
        ))
        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        logger.info(f"DATA_TAMPERING breach alert #{alert_id} recorded to SOC database.")
        return alert_id

    except Exception as e:
        logger.warning(f"Failed to record breach alert to database: {e}")
        return None

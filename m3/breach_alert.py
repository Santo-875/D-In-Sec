"""
AI Breach Alert Generator on Tamper Detection for Module 3 (M3).

Translates deterministic cryptographic hash mismatches into plain-language,
non-technical breach alerts readable by small business (MSME) owners.
Reuses Gemini API pattern with a deterministic fallback to prevent hallucination or downtime.
"""

import os
import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

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

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "mock_site" / "instance" / "mock_site.db"


def deterministic_fallback_alert(facts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic rule-based fallback when Gemini is unavailable or rate-limited.
    Ensures zero hallucinations and guaranteed fact reporting.
    """
    user = facts.get("affected_user", "unknown_user")
    leaf_id = facts.get("leaf_id", "unknown_record")
    detected_at = facts.get("detected_at", datetime.now(timezone.utc).isoformat())
    expected = facts.get("expected_hash", "N/A")
    actual = facts.get("actual_hash", "N/A")

    summary = (
        f"Security Notice: Data record '{leaf_id}' for user '{user}' failed cryptographic verification "
        f"at {detected_at}. The stored record hash does not match the immutable compliance ledger. "
        f"Please inspect database audit logs immediately."
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

    Args:
        facts (Dict[str, Any]): Dictionary with keys:
            - affected_user: user identifier
            - leaf_id: leaf identifier
            - expected_hash: expected cryptographic hash
            - actual_hash: actual cryptographic hash
            - detected_at: ISO-8601 timestamp

    Returns:
        Dict[str, Any]: JSON alert with summary, severity, affected_user, detected_at.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not HAS_GENAI:
        return deterministic_fallback_alert(facts)

    user = facts.get("affected_user", "unknown_user")
    leaf_id = facts.get("leaf_id", "unknown_record")
    expected = facts.get("expected_hash", "N/A")
    actual = facts.get("actual_hash", "N/A")
    detected_at = facts.get("detected_at", datetime.now(timezone.utc).isoformat())

    prompt = f"""
You are a cybersecurity compliance assistant writing for a non-technical small business (MSME) owner.
A cryptographic tamper detection alert was triggered because a database record failed hash verification against the tamper-evident Merkle ledger.

TAMPER FACTS:
- Affected User: {user}
- Record ID: {leaf_id}
- Expected Hash: {expected}
- Stored/Actual Hash: {actual}
- Detection Time: {detected_at}

INSTRUCTIONS:
1. Explain what happened in 2 short, clear sentences without using complex mathematical jargon.
2. Clearly state what was altered, when it was detected, and recommend inspecting recent database activity.
3. Return ONLY a JSON object matching this schema:
{{
  "summary": "plain-language explanation of what happened for the business owner",
  "severity": "CRITICAL",
  "affected_user": "{user}",
  "detected_at": "{detected_at}"
}}
"""

    try:
        # Suppress noisy google.genai logs
        logging.getLogger("google.genai").setLevel(logging.ERROR)

        client = genai.Client(api_key=api_key)
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.1
        )

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=config
        )

        parsed = json.loads(response.text)
        summary = parsed.get("summary")
        if not summary:
            return deterministic_fallback_alert(facts)

        return {
            "summary": summary,
            "severity": parsed.get("severity", "CRITICAL"),
            "affected_user": user,
            "detected_at": detected_at,
            "tamper_evidence": {
                "leaf_id": leaf_id,
                "expected_hash": expected,
                "actual_hash": actual
            },
            "source": "gemini"
        }
    except Exception as e:
        logger.warning(f"Gemini breach alert generation failed: {e}. Falling back to deterministic template.")
        return deterministic_fallback_alert(facts)


def record_breach_alert_to_db(alert: Dict[str, Any], db_path: Optional[Path] = None) -> Optional[int]:
    """
    Persists breach alert directly into the IncidentAlert SOC table in SQLite
    so it appears immediately on the SOC Alert Dashboard alongside Module 2 alerts.
    """
    target_db = Path(db_path) if db_path else DEFAULT_DB_PATH
    if not target_db.exists():
        return None

    try:
        conn = sqlite3.connect(str(target_db))
        cursor = conn.cursor()

        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incident_alerts'")
        if not cursor.fetchone():
            conn.close()
            return None

        # Ensure event_id column exists
        cursor.execute("PRAGMA table_info(incident_alerts)")
        cols = [c[1] for c in cursor.fetchall()]
        if "event_id" not in cols:
            cursor.execute("ALTER TABLE incident_alerts ADD COLUMN event_id TEXT")
            conn.commit()

        evidence = alert.get("tamper_evidence", {})
        draft_text = (
            f"CERT-In CYBER SECURITY INCIDENT REPORT (DRAFT - DATA TAMPERING)\n"
            f"===============================================================\n"
            f"Date of Detection: {alert.get('detected_at')}\n"
            f"Incident Type: DATA_TAMPERING\n"
            f"Severity: {alert.get('severity')}\n"
            f"Affected User: {alert.get('affected_user')}\n\n"
            f"Summary:\n{alert.get('summary')}\n\n"
            f"Cryptographic Evidence:\n"
            f"- Leaf ID: {evidence.get('leaf_id')}\n"
            f"- Expected Hash: {evidence.get('expected_hash')}\n"
            f"- Actual Hash: {evidence.get('actual_hash')}\n\n"
            f"Recommended Action:\n"
            f"- Freeze user subtree to prevent further unauthorized state transitions.\n"
            f"- Audit access logs and restore data from verified root checkpoint.\n"
        )

        cursor.execute("""
            INSERT INTO incident_alerts (incident_type, severity, confidence, masked_log_context, cert_in_draft, status, created_at)
            VALUES ('DATA_TAMPERING', ?, 1.0, ?, ?, 'Open', datetime('now'))
        """, (
            alert.get("severity", "CRITICAL"),
            alert.get("summary", "Data tampering detected by Merkle tree verification engine."),
            draft_text
        ))
        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        logger.info(f"Recorded DATA_TAMPERING breach alert #{alert_id} to database.")
        return alert_id
    except Exception as e:
        logger.warning(f"Failed to record breach alert to database: {e}")
        return None

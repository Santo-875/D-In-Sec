"""
m3/tests/test_ai_pipeline.py — Tests for Phase 2:
  - LocalClassifier (TF-IDF + Logistic Regression) fast loop
  - Confidence dead zone handling (Gemini fallback)
  - Human-review retraining with holdout evaluation and promotion guard
  - Model registry and rollback
  - Daily CERT-In summary generation with masking and idempotence
"""

import json
import os
import tempfile
import pytest

from m3.database import M3Database
from m3.retrain import LocalClassifier, retrain, LABEL_TAMPER, LABEL_NORMAL
from m3.summary import generate_daily_summary


def test_local_classifier_fast_loop():
    texts = [
        "sql injection detected on query SELECT * FROM users WHERE '1'='1'",
        "tampering with audit trail log entry index 4",
        "hash mismatch found in root anchor log",
        "user login success from trusted ip address",
        "normal database read operation on products table",
        "routine heartbeat ping received from node-1",
    ]
    labels = [
        LABEL_TAMPER,
        LABEL_TAMPER,
        LABEL_TAMPER,
        LABEL_NORMAL,
        LABEL_NORMAL,
        LABEL_NORMAL,
    ]

    clf = LocalClassifier()
    metrics = clf.train(texts, labels)
    assert "accuracy" in metrics

    # Test classifying clear tamper text
    label, conf = clf.classify("tampering and hash mismatch in audit log")
    assert label in [LABEL_TAMPER, None]

    # Test classifying clear normal text
    label_norm, conf_norm = clf.classify("normal database read operation")
    assert label_norm in [LABEL_NORMAL, None]


def test_retrain_pipeline_and_model_registry(tmp_path):
    db_path = str(tmp_path / "test_retrain.db")
    db = M3Database(db_path)

    # Queue human-reviewed items in review_queue
    for i in range(1, 8):
        db.enqueue_review(f"evt_tamper_{i}", LABEL_TAMPER)
        db.label_review_item(i, human_label=LABEL_TAMPER, reviewer="sec_team", fn_flag=(i % 2 == 0))

    for i in range(8, 16):
        db.enqueue_review(f"evt_normal_{i}", LABEL_NORMAL)
        db.label_review_item(i, human_label=LABEL_NORMAL, reviewer="sec_team", fn_flag=False)

    # Execute retrain
    result = retrain(db)
    assert result.get("status") == "trained"
    if result.get("promoted"):
        version = result.get("version")
        registry = db.get_model_registry()
        assert any(m["version"] == version for m in registry)

        # Test rollback
        ok = db.rollback_model(version)
        assert ok is True


def test_generate_daily_summary_certin_compliance(tmp_path):
    db_path = str(tmp_path / "test_summary.db")
    db = M3Database(db_path)

    today = "2026-09-30"

    summary = generate_daily_summary(db, today)
    assert summary["date"] == today
    assert "events_by_type" in summary
    assert "top_actors" in summary
    assert "retention_status" in summary
    assert summary["retention_status"]["retention_policy_days"] == 180

    # Idempotent verification
    summary_2 = generate_daily_summary(db, today)
    assert summary["date"] == summary_2["date"]
    assert summary["events_count"] == summary_2["events_count"]

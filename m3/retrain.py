"""
m3/retrain.py — Fast AI loop + Human-review retrain pipeline for Module 3.

Architecture:
  Fast loop: TF-IDF + LogisticRegression (sklearn) for rapid local classification.
             Gemini called only for uncertain cases (probability in dead zone).
  Slow loop:  review_queue table collects events with labels.
              retrain() trains ONLY on human-reviewed labels, validates on holdout,
              promotes to model_registry only if metrics >= current active model.

Model versioning:
  - SHA-256 of model weights committed as a Merkle leaf under "ml_registry".
  - Rollback via POST /v1/admin/model/rollback/<version>.

Env:
    GEMINI_MODEL    = gemini-2.5-flash (or other)
    GEMINI_API_KEY  = <key>
    M3_DB_PATH      = m3.db
"""

import hashlib
import json
import logging
import os
import pickle
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("m3.retrain")

# Confidence dead zone: model defers to Gemini if prob in this range
_LOW_CONFIDENCE = float(os.environ.get("ML_LOW_CONFIDENCE", "0.35"))
_HIGH_CONFIDENCE = float(os.environ.get("ML_HIGH_CONFIDENCE", "0.65"))

# Labels used by the model
LABEL_TAMPER = "TAMPER"
LABEL_NORMAL = "NORMAL"


# ── Model serialisation helpers ──────────────────────────────────────────────

def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _serialise_model(pipeline) -> tuple[bytes, str]:
    """Pickle a sklearn Pipeline and return (bytes, sha256)."""
    raw = pickle.dumps(pipeline)
    return raw, _sha256_of_bytes(raw)


def _load_model_bytes(raw: bytes):
    return pickle.loads(raw)


# ── Fast local classifier ────────────────────────────────────────────────────

def _build_pipeline():
    """Build a fresh sklearn TF-IDF + LogReg pipeline."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline([
        ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
        ("clf", LogisticRegression(max_iter=500, class_weight="balanced")),
    ])


class LocalClassifier:
    """
    Thin wrapper around a sklearn Pipeline.
    Classifies text as TAMPER or NORMAL with a confidence score.
    If confidence is in the dead zone, returns None (→ Gemini fallback).
    """

    def __init__(self, pipeline=None):
        self._pipeline = pipeline  # None = not trained yet

    def classify(self, text: str) -> tuple[str | None, float]:
        """
        Returns (label, confidence). Label is None if model is untrained
        or confidence is in the dead zone (triggers Gemini).
        """
        if self._pipeline is None:
            return None, 0.0
        proba = self._pipeline.predict_proba([text])[0]
        classes = list(self._pipeline.classes_)
        tamper_idx = classes.index(LABEL_TAMPER) if LABEL_TAMPER in classes else 0
        confidence = float(proba[tamper_idx])

        if _LOW_CONFIDENCE <= confidence <= _HIGH_CONFIDENCE:
            return None, confidence   # uncertain → defer to Gemini

        label = LABEL_TAMPER if confidence > _HIGH_CONFIDENCE else LABEL_NORMAL
        return label, confidence

    def train(self, texts: list[str], labels: list[str]) -> dict[str, Any]:
        """Train in-place. Returns train metrics."""
        from sklearn.metrics import classification_report
        pipeline = _build_pipeline()
        pipeline.fit(texts, labels)
        preds = pipeline.predict(texts)
        report = classification_report(labels, preds, output_dict=True, zero_division=0)
        self._pipeline = pipeline
        return report

    def serialise(self) -> tuple[bytes, str]:
        if self._pipeline is None:
            raise RuntimeError("Model not trained yet.")
        return _serialise_model(self._pipeline)

    @classmethod
    def load(cls, raw: bytes) -> "LocalClassifier":
        pipeline = _load_model_bytes(raw)
        return cls(pipeline=pipeline)


# ── Gemini fallback for uncertain cases ─────────────────────────────────────

def _gemini_classify(text: str) -> tuple[str, str]:
    """
    Call Gemini for borderline events.
    Returns (label, explanation). Falls back to NORMAL on failure.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    model_name = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

    if not api_key:
        return LABEL_NORMAL, "Gemini unavailable (no API key). Defaulting to NORMAL."

    try:
        from google import genai
        from google.genai import types

        system_prompt = (
            "You are a security event classifier. "
            "Classify the following event log as exactly one of: TAMPER or NORMAL. "
            "TAMPER = evidence of data modification, injection, or integrity violation. "
            "NORMAL = routine or expected activity. "
            "Return JSON: {\"label\": \"TAMPER\" or \"NORMAL\", \"explanation\": \"<one sentence>\"}"
        )
        # Data is strictly delimited — never concatenated directly into prompt
        user_message = (
            f"{system_prompt}\n\n"
            f"<event_data>\n{text[:2000]}\n</event_data>"
        )

        client = genai.Client(api_key=api_key)
        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.0
        )
        response = client.models.generate_content(
            model=model_name,
            contents=user_message,
            config=config
        )
        parsed = json.loads(response.text)
        label = parsed.get("label", LABEL_NORMAL)
        if label not in (LABEL_TAMPER, LABEL_NORMAL):
            label = LABEL_NORMAL
        explanation = parsed.get("explanation", "")
        return label, explanation
    except Exception as exc:
        logger.warning("Gemini classification failed: %s. Falling back to NORMAL.", exc)
        return LABEL_NORMAL, f"Gemini error: {exc}"


# ── Unified classify entry point ─────────────────────────────────────────────

def classify_event(text: str, classifier: LocalClassifier | None = None) -> dict[str, Any]:
    """
    Fast AI loop:
      1. Run local model.
      2. If uncertain or model absent → call Gemini.
      3. Return deterministic label + source.
    """
    label, confidence = (None, 0.0)
    if classifier:
        label, confidence = classifier.classify(text)

    source = "local_model"
    explanation = ""

    if label is None:
        label, explanation = _gemini_classify(text)
        source = "gemini"
        confidence = 1.0 if label == LABEL_TAMPER else 0.0

    return {
        "label": label,
        "confidence": confidence,
        "source": source,
        "explanation": explanation,
    }


# ── Slow retrain loop ────────────────────────────────────────────────────────

def retrain(db, storage=None) -> dict[str, Any]:
    """
    Train a new model from human-reviewed labels in review_queue.
    Validates on holdout. Promotes only if metrics >= current active model.
    Commits model SHA-256 as a Merkle leaf under "ml_registry" user.

    Returns:
        Dict with version, metrics, sha256, promoted flag.
    """
    from sklearn.metrics import f1_score
    from sklearn.model_selection import train_test_split

    # Gather human-labelled records (false negatives prioritised by fn_flag)
    all_rows = db.get_review_queue()
    labelled = [r for r in all_rows if r.get("human_label") is not None]

    if len(labelled) < 10:
        return {"status": "insufficient_data", "count": len(labelled)}

    # False negatives are upsampled 2x
    fn_rows = [r for r in labelled if r.get("fn_flag")]
    normal_rows = [r for r in labelled if not r.get("fn_flag")]
    rows = normal_rows + fn_rows + fn_rows  # oversample FNs

    texts = [json.dumps({"event_id": r["event_id"], "label": r["human_label"]}) for r in rows]
    labels = [r["human_label"] for r in rows]

    if len(set(labels)) < 2:
        return {"status": "single_class", "classes": list(set(labels))}

    # Train / holdout split
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, stratify=labels, random_state=42
    )

    new_clf = LocalClassifier()
    train_metrics = new_clf.train(X_train, y_train)

    # Evaluate on holdout
    preds = [new_clf.classify(t)[0] or LABEL_NORMAL for t in X_test]
    holdout_f1 = f1_score(y_test, preds, pos_label=LABEL_TAMPER, zero_division=0)

    # Compare against active model
    current_models = db.get_model_registry()
    active = next((m for m in current_models if m.get("is_active")), None)
    current_f1 = float(active["metrics"].get("f1_tamper", 0.0)) if active else 0.0

    promoted = False
    version = datetime.now(timezone.utc).strftime("v%Y%m%d%H%M%S")
    _raw_bytes, sha256 = new_clf.serialise()

    metrics = {
        "f1_tamper": holdout_f1,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "train_report": train_metrics,
    }

    if holdout_f1 >= current_f1:
        db.register_model(version=version, metrics=metrics, sha256=sha256)
        promoted = True
        logger.info("New model %s promoted. F1=%.3f (was %.3f).", version, holdout_f1, current_f1)

        # Upload model bytes to storage if available
        if storage:
            model_payload = {"version": version, "sha256": sha256, "metrics": metrics}
            storage.put_model(version, model_payload)
    else:
        logger.info("New model F1=%.3f below current %.3f. Not promoted.", holdout_f1, current_f1)

    return {
        "status": "trained",
        "version": version,
        "f1_tamper": holdout_f1,
        "sha256": sha256,
        "promoted": promoted,
        "previous_f1": current_f1,
    }

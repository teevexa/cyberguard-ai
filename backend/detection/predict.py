import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from .features import ALL_FEATURES, CATEGORICAL_FEATURES, SEVERITY_BY_CATEGORY

MODEL_PATH = Path(__file__).parent / "model.joblib"
EXPLAIN_PATH = Path(__file__).parent / "explainability.json"
_model = None


def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def reload_model() -> None:
    """Forces the next score_event() call to re-read model.joblib from disk.
    Must be called after retraining — _model is a process-lifetime cache, so
    without this a freshly retrained model on disk would silently keep being
    ignored in favor of the one loaded at server startup."""
    global _model
    _model = None


def _coerce_feature_row(features: dict[str, Any]) -> dict[str, Any]:
    """Real ingest clients (the public API, in particular) can't be trusted
    to send a complete, well-typed 39-field payload every time. A missing or
    malformed field shouldn't 500 the request — RandomForestClassifier can't
    accept NaN/strings-where-numbers-expected, so fall back to a neutral
    default per field, the same "never drop it, best-effort instead" choice
    already made for syslog parsing (see syslog_server.py)."""
    row: dict[str, Any] = {}
    for key in ALL_FEATURES:
        value = features.get(key)
        if key in CATEGORICAL_FEATURES:
            row[key] = value if isinstance(value, str) and value else "unknown"
        else:
            try:
                row[key] = float(value) if value is not None else 0.0
            except (TypeError, ValueError):
                row[key] = 0.0
    return row


def score_event(features: dict[str, Any]) -> dict[str, Any]:
    """Score one log event's feature dict against the trained classifier.

    Returns the predicted attack category (or "Normal"), a confidence score,
    a severity bucket, and whether it should be recorded as a threat.
    """
    model = _get_model()
    row = pd.DataFrame([_coerce_feature_row(features)])
    proba = model.predict_proba(row)[0]
    classes = model.classes_
    best_idx = proba.argmax()
    label = classes[best_idx]
    confidence = float(proba[best_idx])
    return {
        "label": label,
        "score": confidence,
        "severity": SEVERITY_BY_CATEGORY.get(label, "medium"),
        "is_threat": label != "Normal",
    }


def get_feature_importance(top_n: int = 15) -> list[dict[str, Any]]:
    if not EXPLAIN_PATH.exists():
        return []
    data = json.loads(EXPLAIN_PATH.read_text())
    ranked = sorted(data["feature_importance"].items(), key=lambda kv: -kv[1])
    return [{"feature": k, "importance": v} for k, v in ranked[:top_n]]


def explain_event(features: dict[str, Any], top_n: int = 6) -> list[dict[str, Any]]:
    """For the features that most influence the model overall, compare this
    event's actual values against the real mean/std of Normal-labeled
    training rows — a concrete, data-driven answer to "why was this flagged",
    distinct from (and complementary to) the qualitative Ollama triage note."""
    if not EXPLAIN_PATH.exists():
        return []
    data = json.loads(EXPLAIN_PATH.read_text())
    baseline = data["normal_baseline"]
    ranked = sorted(data["feature_importance"].items(), key=lambda kv: -kv[1])

    result = []
    for name, importance in ranked:
        if name not in baseline or name not in features:
            continue
        value = features[name]
        try:
            value = float(value)
        except (TypeError, ValueError):
            continue
        mean, std = baseline[name]["mean"], baseline[name]["std"]
        z_score = (value - mean) / std
        result.append(
            {
                "feature": name,
                "value": value,
                "normal_mean": mean,
                "normal_std": std,
                "z_score": z_score,
                "importance": importance,
            }
        )
        if len(result) >= top_n:
            break
    return result

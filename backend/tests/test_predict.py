from detection.features import ALL_FEATURES, CATEGORICAL_FEATURES, NUMERIC_FEATURES
from detection.predict import _coerce_feature_row


def test_coerce_feature_row_fills_every_required_field():
    row = _coerce_feature_row({})
    assert set(row.keys()) == set(ALL_FEATURES)


def test_coerce_feature_row_keeps_valid_values():
    row = _coerce_feature_row({"sbytes": 1234, "proto": "tcp"})
    assert row["sbytes"] == 1234.0
    assert row["proto"] == "tcp"


def test_coerce_feature_row_defaults_missing_numeric_to_zero():
    row = _coerce_feature_row({})
    for feature in NUMERIC_FEATURES:
        assert row[feature] == 0.0


def test_coerce_feature_row_defaults_missing_categorical_to_unknown():
    row = _coerce_feature_row({})
    for feature in CATEGORICAL_FEATURES:
        assert row[feature] == "unknown"


def test_coerce_feature_row_never_raises_on_malformed_numeric_value():
    # A real public-API caller (or a hand-built log source) sending a string
    # where a number is expected must degrade gracefully, not 500 the request.
    row = _coerce_feature_row({"sbytes": "not-a-number", "dur": None, "sttl": [1, 2]})
    assert row["sbytes"] == 0.0
    assert row["dur"] == 0.0
    assert row["sttl"] == 0.0


def test_coerce_feature_row_rejects_non_string_categorical_value():
    row = _coerce_feature_row({"proto": 42, "service": "", "state": "FIN"})
    assert row["proto"] == "unknown"
    assert row["service"] == "unknown"
    assert row["state"] == "FIN"

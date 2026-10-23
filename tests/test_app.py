"""Offline UI regressions for decision/score separation; no trained artifacts."""
from pathlib import Path
import socket

import numpy as np
import pytest
import requests
import streamlit as st
from streamlit.testing.v1 import AppTest

from phishing_analyzer import analyzer, model

APP = Path(__file__).resolve().parents[1] / "app.py"
LOW = 0.03768347266841587
HIGH = 0.08012717594132758
META = {"legitimate_threshold": LOW, "phishing_threshold": HIGH}


class FixedClassifier:
    classes_ = np.array([0, 1])

    def __init__(self, score):
        self.score = score

    def predict_proba(self, urls):
        return np.array([[self.score, 1 - self.score] for _ in urls])


@pytest.fixture(autouse=True)
def offline_ui(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("UI regression tests must not use live checks or network")

    for name in ("read_html", "rdap_check", "tls_check"):
        monkeypatch.setattr(analyzer, name, unexpected)
    monkeypatch.setattr(socket, "create_connection", unexpected)
    monkeypatch.setattr(requests.sessions.Session, "request", unexpected)
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def submit(monkeypatch, score, url="https://example.org/"):
    pair = (None, None) if score is None else (FixedClassifier(score), META)
    monkeypatch.setattr(model, "load_model", lambda _: pair)
    app = AppTest.from_file(str(APP)).run(timeout=30)
    assert not app.exception
    assert app.checkbox[0].value is False
    app.text_input[0].set_value(url)
    app.button[0].click().run(timeout=30)
    assert not app.exception
    return app


@pytest.mark.parametrize("score,label,notice", [
    (0.9, "PHISHING", "error"),
    (0.05, "UNCERTAIN", "warning"),
    (0.01, "LEGITIMATE", "info"),
    (HIGH, "PHISHING", "error"),
    (LOW, "LEGITIMATE", "info"),
])
def test_model_decision_is_primary_and_not_replaced_by_low_band(monkeypatch, score, label, notice):
    app = submit(monkeypatch, score)
    metrics = {item.label: item.value for item in app.metric}
    assert metrics["Model decision"] == label
    assert "Risk level" not in metrics
    # The original low numeric score is preserved, not inflated to manufacture HIGH.
    expected = analyzer.analyze("https://example.org/", FixedClassifier(score), META)
    assert expected["risk_level"] == "LOW"
    assert metrics["Combined signal score"] == f"{expected['risk_score']} / 100"
    assert any(f"Model decision: {label}." in item.value for item in getattr(app, notice))
    assert any("Scores are not calibrated probabilities" in c.value for c in app.caption)
    assert any(f"{LOW:.6f}" in c.value and f"{HIGH:.6f}" in c.value for c in app.caption)
    assert all(item.value != "LOW" for item in app.metric)


def test_missing_model_is_unavailable_not_a_legitimate_prediction(monkeypatch):
    app = submit(monkeypatch, None)
    assert app.metric[0].value == "UNAVAILABLE"
    assert app.metric[1].value == "0 / 100"
    assert any("heuristic-only demo" in w.value for w in app.warning)
    assert any("cannot establish whether this URL is phishing or legitimate" in w.value for w in app.warning)
    assert not app.error


def test_legitimate_prediction_does_not_hide_other_signals(monkeypatch):
    app = submit(monkeypatch, 0.01, "http://192.0.2.10/login")
    assert app.metric[0].value == "LEGITIMATE"
    assert app.metric[1].value == "30 / 100"
    assert any("not verified legitimacy or a safety guarantee" in i.value for i in app.info)
    assert any("HTTPS is not used" in m.value for m in app.markdown)


def test_invalid_input_has_no_decision_or_score(monkeypatch):
    app = submit(monkeypatch, None, "ftp://example.org/")
    assert not app.metric
    assert any("Invalid URL" in error.value for error in app.error)

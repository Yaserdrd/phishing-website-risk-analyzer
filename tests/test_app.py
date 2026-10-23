"""Offline UI regressions for decision/score separation; no trained artifacts."""
from pathlib import Path
import socket

import numpy as np
import pytest
import requests
import streamlit as st
from streamlit.testing.v1 import AppTest

from phishing_analyzer import analyzer, serving

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
    original_socket = socket.socket
    def guarded_socket(family=socket.AF_INET, *args, **kwargs):
        # Streamlit's event loop uses local AF_UNIX socketpairs internally.
        if family in (socket.AF_INET, socket.AF_INET6):
            unexpected()
        return original_socket(family, *args, **kwargs)
    monkeypatch.setattr(socket, "socket", guarded_socket)
    monkeypatch.setattr(requests.sessions.Session, "request", unexpected)
    for name in ("PHISHING_MODEL_DIR", "PHISHING_MODEL_MANIFEST", "PHISHING_MODEL_MANIFEST_SHA256"):
        monkeypatch.delenv(name, raising=False)
    st.cache_resource.clear()
    yield
    st.cache_resource.clear()


def submit(monkeypatch, score, url="https://example.org/"):
    pair = (None, None) if score is None else (FixedClassifier(score), META)
    monkeypatch.setattr(serving, "load_app_model", lambda *args, **kwargs: pair)
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


def test_empty_input_has_actionable_guidance_and_no_result(monkeypatch):
    app = submit(monkeypatch, None, '   ')
    assert not app.metric
    assert not app.error
    assert any('Enter a website URL' in w.value for w in app.warning)


def test_bad_model_startup_still_allows_explicit_demo_without_raw_errors(monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise serving.ModelUnavailable('PRIVATE-PATH-AND-TOKEN')
    monkeypatch.setattr(serving, 'load_app_model', broken)
    app = AppTest.from_file(str(APP)).run(timeout=30)
    assert not app.exception
    assert any('could not be verified' in error.value for error in app.error)
    app.text_input[0].set_value('https://example.org/')
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert app.metric[0].value == 'UNAVAILABLE'
    assert 'PRIVATE-PATH-AND-TOKEN' not in str(app) + caplog.text


def test_prediction_failure_falls_back_without_exposing_error_or_url(monkeypatch, caplog):
    class FailingModel:
        classes_ = np.array([0, 1])
        def predict_proba(self, urls):
            raise serving.ModelUnavailable('PRIVATE-INFERENCE-DETAILS')
    monkeypatch.setattr(serving, 'load_app_model', lambda *args, **kwargs: (FailingModel(), META))
    app = AppTest.from_file(str(APP)).run(timeout=30)
    app.text_input[0].set_value('https://example.org/?token=PRIVATE-URL')
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert app.metric[0].value == 'UNAVAILABLE'
    assert any('could not provide a prediction' in error.value for error in app.error)
    assert 'PRIVATE-INFERENCE-DETAILS' not in str(app) + caplog.text
    assert 'PRIVATE-URL' not in caplog.text


def test_unexpected_analysis_failure_gives_retry_without_a_verdict(monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise RuntimeError('PRIVATE-BACKEND-DETAILS')
    monkeypatch.setattr(analyzer, 'analyze', fail)
    app = submit(monkeypatch, None)
    assert not app.metric
    assert any('Try again' in error.value for error in app.error)
    assert 'PRIVATE-BACKEND-DETAILS' not in str(app) + caplog.text


def test_model_installation_or_replacement_invalidates_cached_absence(monkeypatch, tmp_path):
    monkeypatch.setenv('PHISHING_MODEL_DIR', str(tmp_path))
    calls = []
    def current(*args, **kwargs):
        calls.append(1)
        return (FixedClassifier(.9), META) if (tmp_path / 'url_phishing_model.pkl').exists() else (None, None)
    monkeypatch.setattr(serving, 'load_app_model', current)
    app = AppTest.from_file(str(APP)).run(timeout=30)
    app.run()
    assert len(calls) == 1
    (tmp_path / 'url_phishing_model.pkl').write_bytes(b'cache-key-only-not-a-pickle')
    app.run()
    assert len(calls) == 2
    app.text_input[0].set_value('https://example.org/')
    app.button[0].click().run(timeout=30)
    assert app.metric[0].value == 'PHISHING'


def test_approved_digest_change_invalidates_cache(monkeypatch):
    calls = []
    def load(*args, **kwargs):
        calls.append(args[2])
        return None, None
    monkeypatch.setattr(serving, 'load_app_model', load)
    monkeypatch.setenv('PHISHING_MODEL_MANIFEST_SHA256', 'a' * 64)
    app = AppTest.from_file(str(APP)).run(timeout=30)
    monkeypatch.setenv('PHISHING_MODEL_MANIFEST_SHA256', 'b' * 64)
    app.run()
    assert calls == ['a' * 64, 'b' * 64]


def test_prediction_fallback_does_not_duplicate_opted_in_network_checks(monkeypatch):
    class FailedModel:
        classes_ = np.array([0, 1])
        def predict_proba(self, urls):
            raise serving.ModelUnavailable('test failure')
    monkeypatch.setattr(serving, 'load_app_model', lambda *args, **kwargs: (FailedModel(), META))
    calls = []
    def tls(url, **kwargs):
        calls.append('tls')
        return {'status': 'verified', 'valid': True}
    def rdap(url, **kwargs):
        calls.append('rdap')
        return 0, [], {'age_days': None}
    def html(url, **kwargs):
        calls.append('html')
        return '<p>Offline fixture</p>', url, 0
    monkeypatch.setattr(analyzer, 'tls_check', tls)
    monkeypatch.setattr(analyzer, 'rdap_check', rdap)
    monkeypatch.setattr(analyzer, 'read_html', html)
    app = AppTest.from_file(str(APP)).run(timeout=30)
    app.checkbox[0].set_value(True)
    app.text_input[0].set_value('https://example.org/')
    app.button[0].click().run(timeout=30)
    assert not app.exception
    assert app.metric[0].value == 'UNAVAILABLE'
    assert calls == ['tls', 'rdap', 'html']

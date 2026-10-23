import numpy as np
import pandas as pd
import pytest

from phishing_analyzer.model import (
    load_csv, load_model, train, predict, choose_thresholds,
    selective_labels, widen_uncertainty_band, _split_by_domain,
)
from phishing_analyzer.urls import domain_group


def sample_frame(n=90):
    # SYNTHETIC-only data. Each row's registrable domain differs.
    rows = []
    for index in range(n):
        phishing = index % 2 == 0
        host = f"{'verify' if phishing else 'store'}-{index}.sample-{index}.com"
        rows.append((f"https://{host}/{'login-check' if phishing else 'catalog'}", 0 if phishing else 1))
    return pd.DataFrame(rows, columns=["URL", "label"])


def test_csv_requires_labels(tmp_path):
    file = tmp_path / "bad.csv"
    pd.DataFrame({"URL": ["https://example.org"], "label": [3]}).to_csv(file, index=False)
    with pytest.raises(ValueError, match="Labels"):
        load_csv(file)


@pytest.mark.parametrize('bad_label', [0.5, 1.5, -0.5, float('inf'), float('-inf'), 2])
def test_csv_rejects_labels_before_lossy_integer_conversion(tmp_path, bad_label):
    frame = sample_frame()
    frame['label'] = frame['label'].astype(float)
    frame.loc[0, 'label'] = bad_label
    file = tmp_path / 'labels.csv'
    frame.to_csv(file, index=False)
    with pytest.raises(ValueError, match='Labels'):
        load_csv(file)


def test_csv_accepts_exact_numeric_binary_labels(tmp_path):
    frame = sample_frame()
    frame['label'] = frame['label'].astype(float)
    file = tmp_path / 'labels.csv'
    frame.to_csv(file, index=False)
    result = load_csv(file)
    assert result.label.tolist() == [i % 2 for i in range(90)]


@pytest.mark.parametrize('label', ['1.00000000000000000001', '1e-999', 'not-a-label', 'True'])
def test_csv_rejects_labels_that_float_parsing_would_round_or_coerce(tmp_path, label):
    frame = sample_frame()
    frame['label'] = frame.label.astype(str)
    frame.loc[0, 'label'] = label
    file = tmp_path / 'labels.csv'
    frame.to_csv(file, index=False)
    with pytest.raises(ValueError, match='Labels'):
        load_csv(file)


def test_csv_quarantines_conflicting_labels_and_tracks_duplicates(tmp_path):
    file = tmp_path / "mixed.csv"
    frame = sample_frame(30)
    frame = pd.concat([frame, pd.DataFrame([
        {"URL": frame.iloc[0].URL, "label": 1},
        {"URL": frame.iloc[1].URL, "label": 1},
        {"URL": "not a website at all", "label": 1},
    ])], ignore_index=True)
    frame.to_csv(file, index=False)
    cleaned = load_csv(file)
    assert len(cleaned) == 29
    assert cleaned.attrs["cleaning"]["contradictory_url_count"] == 1
    assert cleaned.attrs["cleaning"]["quarantined_conflict_rows"] == 2
    assert cleaned.attrs["cleaning"]["duplicate_rows_removed"] == 1
    assert cleaned.attrs["cleaning"]["dropped_missing_or_invalid"] == 1


def test_registrable_domain_keeps_subdomains_together():
    assert domain_group("https://login.example.co.uk/path") == "example.co.uk"
    assert domain_group("https://www.example.co.uk/shop") == "example.co.uk"
    assert domain_group("https://example.com") == domain_group("https://a.b.example.com")
    assert domain_group("http://127.0.0.1") == "127.0.0.1"


def test_split_domain_leakage_never_occurs(tmp_path):
    file = tmp_path / "synthetic.csv"
    frame = sample_frame(90)
    frame = pd.concat([frame, pd.DataFrame([
        {"URL": "https://www.sample-0.com/extra", "label": 0},
        {"URL": "https://signup.sample-1.com/extra", "label": 1},
    ])], ignore_index=True)
    frame.to_csv(file, index=False)
    prepared = load_csv(file)
    fit, val, test, _ = _split_by_domain(prepared)
    f, v, t = [set(x.domain_group) for x in (fit, val, test)]
    assert not (f & v or f & t or v & t)
    assert sum(map(len, (fit, val, test))) == len(prepared)


def test_thresholds_respect_validation_fpr_and_miss():
    p = np.array([0.03, .08, .60, .89, .92, .94, .15, .17, .18, .25, .35])
    y = np.array([0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    low, high = choose_thresholds(p, y, max_fp_rate=0.0, max_missed_phishing_rate=0.0)
    choices = selective_labels(p, low, high)
    assert low < high
    assert not ((choices == "LEGITIMATE") & (y == 0)).any()
    assert not ((choices == "PHISHING") & (y == 1)).any()
    assert "UNCERTAIN" in choices


def test_train_and_load_smoke(tmp_path):
    file = tmp_path / "synthetic.csv"
    sample_frame().to_csv(file, index=False)
    frame = load_csv(file)
    meta = train(frame, tmp_path / "models", url_features=500, host_features=300)
    model, loaded = load_model(tmp_path / "models")
    assert model is not None
    assert loaded["version"] == "2.1.0"
    assert loaded["legitimate_threshold"] < loaded["phishing_threshold"]
    metrics = loaded["metrics"]
    assert "selective" in metrics
    assert "forced_binary_at_high_threshold" in metrics
    assert "average_precision_phishing" in metrics
    assert loaded["split"]["fit_domains"] > 0
    assert metrics["test_rows"] == loaded["split"]["test_rows"]
    assert sum(metrics["selective"]["decisions"].values()) == metrics["test_rows"]
    result = predict("https://example.net", model, loaded)
    assert result["label"] in {"PHISHING", "LEGITIMATE", "UNCERTAIN"}
    assert 0 <= result["probability"] <= 1

def test_conservative_abstention_band():
    scores = np.linspace(.01, .99, 100)
    low, high = widen_uncertainty_band(scores, .4, .4 + 1e-9, target_abstention=.1)
    assert low <= .4 < high
    labels = selective_labels(scores, low, high)
    assert np.mean(labels == "UNCERTAIN") >= .1


def test_conservative_band_invalid_values():
    with pytest.raises(ValueError):
        widen_uncertainty_band([float("nan")], .1, .2)
    with pytest.raises(ValueError):
        widen_uncertainty_band([.2, .5], .2, .1)


def test_training_uses_validation_to_expand_abstention(tmp_path):
    file = tmp_path / "synthetic.csv"
    sample_frame().to_csv(file, index=False)
    report = train(load_csv(file), tmp_path / "model", url_features=500, host_features=300)
    assert report["target_validation_abstention"] == .05
    assert report["validation_uncertain_count"] >= 1
    assert report["validation_coverage"] <= .95
    assert report["base_validation_thresholds"]["phishing"] <= report["phishing_threshold"]

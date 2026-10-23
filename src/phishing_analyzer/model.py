"""Reproducible URL-only ML with domain-isolated evaluation and abstention."""
from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, average_precision_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer

from .urls import domain_group, hosts_for_vectorizer, normalize_url, urls_for_vectorizer

MODEL_FILE = "url_phishing_model.pkl"
META_FILE = "url_model_meta.json"


def make_model(max_url_features: int = 60000, max_host_features: int = 30000):
    url_pipe = Pipeline([
        ("extract", FunctionTransformer(urls_for_vectorizer, validate=False)),
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2,
                                  max_features=max_url_features, sublinear_tf=True)),
    ])
    host_pipe = Pipeline([
        ("extract", FunctionTransformer(hosts_for_vectorizer, validate=False)),
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=2,
                                  max_features=max_host_features, sublinear_tf=True)),
    ])
    return Pipeline([
        ("features", FeatureUnion([("url_char", url_pipe), ("host_char", host_pipe)])),
        ("classifier", LogisticRegression(max_iter=1200, class_weight="balanced", random_state=42)),
    ])


def load_csv(path: str | Path):
    """Return cleaned URL,label frame; drop contradictory labels (with audit)."""
    frame = pd.read_csv(path, usecols=lambda c: c.lower() in {"url", "label"}, dtype=str)
    lookup = {c.lower(): c for c in frame.columns}
    if set(lookup) != {"url", "label"}:
        raise ValueError("Expected CSV columns: URL,label (0 phishing / 1 legitimate)")
    frame = frame[[lookup["url"], lookup["label"]]].rename(columns={lookup["url"]: "url", lookup["label"]: "label"})
    before = len(frame)
    frame = frame.dropna()
    try:
        valid_labels = frame.label.map(lambda value: Decimal(value) in (0, 1)).all()
    except InvalidOperation as exc:
        raise ValueError("Labels must be 0 (phishing) and 1 (legitimate)") from exc
    if not valid_labels:
        raise ValueError("Labels must be 0 (phishing) and 1 (legitimate)")
    frame["label"] = frame.label.map(lambda value: int(Decimal(value)))

    def safe_normalize(value):
        try:
            return normalize_url(value)
        except ValueError:
            return None

    frame["url"] = frame.url.map(safe_normalize)
    frame = frame.dropna(subset=["url"])
    valid = len(frame)
    contradictory = set(frame.groupby("url").label.nunique().loc[lambda values: values > 1].index)
    quarantined_rows = int(frame.url.isin(contradictory).sum())
    frame = frame[~frame.url.isin(contradictory)].drop_duplicates("url").reset_index(drop=True)
    if not len(frame):
        raise ValueError("No consistent URL labels remain after cleaning")
    frame["domain_group"] = frame.url.map(domain_group)
    if frame.label.nunique() < 2 or frame.domain_group.nunique() < 6:
        raise ValueError("Need both classes and at least six distinct registrable domains")
    frame.attrs["cleaning"] = {
        "input_rows": before, "valid_rows_before_dedup": valid,
        "dropped_missing_or_invalid": before - valid,
        "contradictory_url_count": len(contradictory),
        "quarantined_conflict_rows": quarantined_rows,
        "duplicate_rows_removed": valid - quarantined_rows - len(frame),
        "retained_unique_urls": len(frame),
    }
    return frame


def choose_thresholds(probabilities, true_labels, *, max_fp_rate=0.03, max_missed_phishing_rate=0.01):
    """Choose selective-decision boundaries using *validation only*.

    high: smallest cutoff with <=max_fp_rate of legitimate validation URLs
    labelled PHISHING. low: largest cutoff with <=max_missed_phishing_rate
    of phishing URLs labelled LEGITIMATE. Everything between abstains.
    Rates are validation empirical estimates, NOT future risk guarantees.
    """
    probs = np.asarray(probabilities, dtype=float)
    y = np.asarray(true_labels, dtype=int)
    if not len(probs) or len(probs) != len(y) or not np.isfinite(probs).all() or not set(y) == {0, 1}:
        raise ValueError("Validation requires finite probabilities and both classes")
    candidates = np.r_[0.0, np.unique(probs), 1.0, np.nextafter(1.0, np.inf)]
    legit = probs[y == 1]
    phishing = probs[y == 0]
    high = next((float(t) for t in candidates if np.mean(legit >= t) <= max_fp_rate), float(candidates[-1]))
    low_candidates = [float(t) for t in candidates if t < high and np.mean(phishing <= t) <= max_missed_phishing_rate]
    low = max(low_candidates) if low_candidates else float(np.nextafter(0.0, -1.0))
    return low, high


def widen_uncertainty_band(probabilities, low, high, *, target_abstention=0.05):
    """Expand a validation-selected abstention band near the decision boundary.

    The band only widens: it never creates additional confident decisions.
    Target abstention is defined on validation, not on unseen URLs.
    """
    probs = np.asarray(probabilities, dtype=float)
    if not len(probs) or not np.isfinite(probs).all():
        raise ValueError("Valid finite validation scores are required")
    if not 0 <= target_abstention < 1 or low >= high:
        raise ValueError("Invalid band or abstention target")
    current = (probs > low) & (probs < high)
    n = int(np.ceil(len(probs) * target_abstention))
    if current.sum() >= n or n == 0:
        return float(low), float(high)
    center = (float(low) + float(high)) / 2
    selected = np.argsort(np.abs(probs - center), kind="stable")[:n]
    return (
        min(float(low), float(np.nextafter(probs[selected].min(), -np.inf))),
        max(float(high), float(np.nextafter(probs[selected].max(), np.inf))),
    )


def selective_labels(probabilities, low, high):
    probs = np.asarray(probabilities, dtype=float)
    return np.where(probs >= high, "PHISHING", np.where(probs <= low, "LEGITIMATE", "UNCERTAIN"))


def _split_by_domain(frame):
    """Three disjoint registrable-domain groups, with seeded retry for imbalance."""
    groups = frame.domain_group
    for seed in range(42, 62):
        train_i, test_i = next(GroupShuffleSplit(n_splits=1, test_size=.20, random_state=seed).split(frame, frame.label, groups))
        train_df, test_df = frame.iloc[train_i].copy(), frame.iloc[test_i].copy()
        for v_seed in range(17, 37):
            fit_i, val_i = next(GroupShuffleSplit(n_splits=1, test_size=.18, random_state=v_seed).split(
                train_df, train_df.label, train_df.domain_group))
            fit, val = train_df.iloc[fit_i].copy(), train_df.iloc[val_i].copy()
            if all(set(part.label) == {0, 1} for part in (fit, val, test_df)):
                domains = [set(part.domain_group) for part in (fit, val, test_df)]
                assert not any(domains[i] & domains[j] for i, j in ((0, 1), (0, 2), (1, 2)))
                return fit, val, test_df, {"train_seed": seed, "validation_seed": v_seed}
    raise ValueError("Unable to create three domain-disjoint splits containing both classes")


def train(frame, model_dir: str | Path, *, url_features=60000, host_features=30000):
    """Fit model on fit only; validation chooses thresholds; test untouched."""
    cleaning = frame.attrs.get("cleaning", {})
    fit_df, val_df, test_df, seeds = _split_by_domain(frame)
    model = make_model(url_features, host_features)
    model.fit(fit_df.url, fit_df.label)
    idx = list(model.classes_).index(0)
    val_probs = model.predict_proba(val_df.url)[:, idx]
    low_original, high_original = choose_thresholds(val_probs, val_df.label)
    low, high = widen_uncertainty_band(val_probs, low_original, high_original)
    probs = model.predict_proba(test_df.url)[:, idx]
    decisions = selective_labels(probs, low, high)
    y = test_df.label.to_numpy()
    # Report the abstention-aware results, and make forced-binary metrics explicit.
    decided = decisions != "UNCERTAIN"
    false_legit = (decisions == "LEGITIMATE") & (y == 0)
    false_phish = (decisions == "PHISHING") & (y == 1)
    forced_binary = np.where(probs >= high, 0, 1)
    counts = {k.lower(): int((decisions == k).sum()) for k in ("PHISHING", "LEGITIMATE", "UNCERTAIN")}
    metrics = {
        "test_rows": int(len(test_df)),
        "average_precision_phishing": round(float(average_precision_score((y == 0).astype(int), probs)), 5),
        "selective": {
            "coverage": round(float(decided.mean()), 5),
            "decided_accuracy": round(float(np.mean(np.where(decisions[decided] == "PHISHING", 0, 1) == y[decided])) if decided.any() else 0.0, 5),
            "phishing_detected_fraction": round(float(((decisions == "PHISHING") & (y == 0)).sum() / (y == 0).sum()), 5),
            "phishing_mislabelled_legitimate_fraction": round(float(false_legit.sum() / (y == 0).sum()), 5),
            "legitimate_mislabelled_phishing_fraction": round(float(false_phish.sum() / (y == 1).sum()), 5),
            "decisions": counts,
        },
        "forced_binary_at_high_threshold": {
            "accuracy": round(float(accuracy_score(y, forced_binary)), 5),
            "precision_phishing": round(float(precision_score(y, forced_binary, pos_label=0, zero_division=0)), 5),
            "recall_phishing": round(float(recall_score(y, forced_binary, pos_label=0, zero_division=0)), 5),
            "f1_phishing": round(float(f1_score(y, forced_binary, pos_label=0, zero_division=0)), 5),
            "confusion_matrix_labels_0_1": confusion_matrix(y, forced_binary, labels=[0, 1]).tolist(),
            "warning": "Forced-binary metrics count every uncertain URL as legitimate; not the application's abstaining decision policy.",
        },
    }
    val_decisions = selective_labels(val_probs, low, high)
    val_coverage = float(np.mean(val_decisions != "UNCERTAIN"))
    meta = {
        "version": "2.1.0",
        "decision_policy": "validation-only conservative threshold expansion, 5% target abstention",
        "target_validation_abstention": 0.05,
        "validation_coverage": round(val_coverage, 5),
        "validation_uncertain_count": int(np.sum(val_decisions == "UNCERTAIN")),
        "base_validation_thresholds": {"legitimate": low_original, "phishing": high_original},
        "phishing_threshold": high, "legitimate_threshold": low, "phishing_class": 0,
        "target_validation_fpr": 0.03,
        "target_validation_phishing_miss_rate": 0.01,
        "validation_observed_fpr": round(float(((val_decisions == "PHISHING") & (val_df.label.to_numpy() == 1)).sum() / (val_df.label == 1).sum()), 5),
        "validation_observed_phishing_miss_rate": round(float(((val_decisions == "LEGITIMATE") & (val_df.label.to_numpy() == 0)).sum() / (val_df.label == 0).sum()), 5),
        "source": "UCI PhiUSIIL Phishing URL (id=967); labels 0 phishing / 1 legitimate",
        "cleaning": cleaning,
        "split": {
            "strategy": "GroupShuffleSplit by registrable domain / eTLD+1",
            "fit_rows": len(fit_df), "validation_rows": len(val_df), "test_rows": len(test_df),
            "fit_domains": int(fit_df.domain_group.nunique()),
            "validation_domains": int(val_df.domain_group.nunique()),
            "test_domains": int(test_df.domain_group.nunique()),
            **seeds,
        },
        "metrics": metrics,
        "warning": "Dataset-specific results. Validation thresholds are not guarantees; ML scores are not calibrated probabilities.",
    }
    target = Path(model_dir)
    target.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, target / MODEL_FILE)
    (target / META_FILE).write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


def load_model(model_dir: str | Path):
    target = Path(model_dir)
    if not (target / MODEL_FILE).exists() or not (target / META_FILE).exists():
        return None, None
    model = joblib.load(target / MODEL_FILE)  # NEVER load an untrusted artifact.
    meta = json.loads((target / META_FILE).read_text(encoding="utf-8"))
    return model, meta


def predict(url: str, model, meta):
    normalized = normalize_url(url)
    score = float(model.predict_proba([normalized])[0][list(model.classes_).index(0)])
    low, high = float(meta["legitimate_threshold"]), float(meta["phishing_threshold"])
    label = "PHISHING" if score >= high else ("LEGITIMATE" if score <= low else "UNCERTAIN")
    contribution = 25 * max(0, min(1, (score - low) / max(high - low, .01)))
    return {"probability": score, "label": label, "contribution": contribution, "low": low, "high": high}

"""Reproducible URL-text model based on the notebook's v7 approach."""
from __future__ import annotations

import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
from .urls import host_group, hosts_for_vectorizer, normalize_url, root_url, urls_for_vectorizer

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
    """CSV must contain URL, label; label=0 phishing, label=1 legitimate."""
    frame = pd.read_csv(path)
    lookup = {c.lower(): c for c in frame.columns}
    if "url" not in lookup or "label" not in lookup:
        raise ValueError("Expected CSV columns: URL,label (0=phishing; 1=legitimate)")
    frame = frame[[lookup["url"], lookup["label"]]].rename(columns={lookup["url"]: "url", lookup["label"]: "label"}).dropna()
    frame["label"] = pd.to_numeric(frame.label, errors="raise").astype(int)
    if not set(frame.label.unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (phishing) and 1 (legitimate)")
    # Public URL datasets may contain malformed URLs; discard invalid input
    # rather than crashing the entire training run.
    def safe_normalize(value):
        try:
            return normalize_url(value)
        except ValueError:
            return None
    frame["url"] = frame.url.map(safe_normalize)
    frame = frame.dropna(subset=["url"])
    conflicting = frame.groupby("url").label.nunique()
    if (conflicting > 1).any():
        raise ValueError("Same normalized URL has contradictory labels")
    frame = frame.drop_duplicates("url").reset_index(drop=True)
    frame["host_group"] = frame.url.map(host_group)
    if frame.label.nunique() < 2 or frame.host_group.nunique() < 6:
        raise ValueError("Need both classes and at least six distinct host groups")
    return frame


def _augment_root_urls(frame):
    """Add root URLs within existing training groups only, not test data."""
    # Never invent contradictory root URL labels for a mixed-label hostname.
    consistent = frame.groupby("host_group").label.nunique()
    allowed = set(consistent[consistent == 1].index)
    roots = frame[frame.host_group.isin(allowed)][["host_group", "label"]].drop_duplicates().copy()
    roots["url"] = roots.host_group.map(root_url)
    return pd.concat([frame[["url", "label"]], roots[["url", "label"]]], ignore_index=True).drop_duplicates(["url", "label"])


def choose_threshold(model, validation):
    phishing_index = list(model.classes_).index(0)
    prob = model.predict_proba(validation.url)[:, phishing_index]
    legit = validation.label.to_numpy() == 1
    if not legit.any():
        raise ValueError("Validation split has no legitimate samples")
    # If no candidate meets the FPR target, choose 0.95 and report achieved FPR.
    threshold = 0.95
    for candidate in np.arange(0.50, 0.951, 0.01):
        fpr = float(np.mean(prob[legit] >= candidate))
        if fpr <= 0.03:
            threshold = float(round(candidate, 2))
            break
    return threshold


def train(frame, model_dir: str | Path, *, url_features=60000, host_features=30000):
    """Never use test data to select thresholds or fit TF-IDF vocabulary."""
    train_index, test_index = next(GroupShuffleSplit(n_splits=1, test_size=.20, random_state=42).split(
        frame, frame.label, groups=frame.host_group))
    train_df = frame.iloc[train_index].copy()
    test_df = frame.iloc[test_index].copy()
    fit_index, val_index = next(GroupShuffleSplit(n_splits=1, test_size=.18, random_state=17).split(
        train_df, train_df.label, groups=train_df.host_group))
    fit_df = train_df.iloc[fit_index].copy()
    val_df = train_df.iloc[val_index].copy()
    for name, split in (("fit", fit_df), ("validation", val_df), ("test", test_df)):
        if set(split.label) != {0, 1}:
            raise ValueError(f"{name} split lacks one class; obtain a larger/diverse dataset")
    interim = make_model(url_features, host_features)
    interim_data = _augment_root_urls(fit_df)
    interim.fit(interim_data.url, interim_data.label)
    high = choose_threshold(interim, val_df)
    low = max(0.20, round(high - .25, 2))
    model = make_model(url_features, host_features)
    full_train = _augment_root_urls(train_df)
    model.fit(full_train.url, full_train.label)
    probs = model.predict_proba(test_df.url)[:, list(model.classes_).index(0)]
    predictions = np.where(probs >= high, 0, 1)
    y = test_df.label.to_numpy()
    metrics = {
        "accuracy": round(float(accuracy_score(y, predictions)), 4),
        "precision_phishing": round(float(precision_score(y, predictions, pos_label=0, zero_division=0)), 4),
        "recall_phishing": round(float(recall_score(y, predictions, pos_label=0, zero_division=0)), 4),
        "f1_phishing": round(float(f1_score(y, predictions, pos_label=0, zero_division=0)), 4),
        "confusion_matrix_labels_0_1": confusion_matrix(y, predictions, labels=[0, 1]).tolist(),
        "test_rows": len(test_df),
        "train_rows": len(train_df),
        "validation_rows": len(val_df),
        "dataset_unique_urls": len(frame),
        "split_method": "GroupShuffleSplit by normalized hostname",
    }
    meta = {
        "version": "1.0.0", "phishing_threshold": high,
        "legitimate_threshold": low, "phishing_class": 0,
        "source": "UCI PhiUSIIL Phishing URL (id=967) when trained from that data",
        "metrics": metrics,
        "warning": "Model probabilities are not guaranteed to be calibrated; test metrics are dataset-specific.",
    }
    target = Path(model_dir)
    target.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, target / MODEL_FILE)
    (target / META_FILE).write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


def load_model(model_dir: str | Path):
    """Load locally generated trusted artifacts only (joblib is unsafe for untrusted files)."""
    target = Path(model_dir)
    if not (target / MODEL_FILE).exists() or not (target / META_FILE).exists():
        return None, None
    model = joblib.load(target / MODEL_FILE)
    meta = json.loads((target / META_FILE).read_text(encoding="utf-8"))
    return model, meta


def predict(url: str, model, meta):
    normalized = normalize_url(url)
    phishing_prob = float(model.predict_proba([normalized])[0][list(model.classes_).index(0)])
    low, high = float(meta["legitimate_threshold"]), float(meta["phishing_threshold"])
    label = "PHISHING" if phishing_prob >= high else ("LEGITIMATE" if phishing_prob <= low else "UNCERTAIN")
    contribution = 25 * max(0, min(1, (phishing_prob - low) / max(high - low, 0.01)))
    return {"probability": phishing_prob, "label": label, "contribution": contribution, "low": low, "high": high}

"""Validate and print a *saved* UCI holdout report without inventing metrics."""
from __future__ import annotations
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    meta = json.loads(args.report.read_text(encoding="utf-8"))
    split = meta["split"]
    results = meta["metrics"]
    assert meta["legitimate_threshold"] < meta["phishing_threshold"], "Invalid confidence boundaries"
    assert all(split[k] > 0 for k in ("fit_domains", "validation_domains", "test_domains")), "Missing split"
    assert split["test_rows"] == results["test_rows"], "Different test populations"
    assert sum(results["selective"]["decisions"].values()) == results["test_rows"], "Unaccounted decisions"
    assert all(0 <= results["selective"][k] <= 1 for k in (
        "coverage", "decided_accuracy", "phishing_detected_fraction",
        "phishing_mislabelled_legitimate_fraction", "legitimate_mislabelled_phishing_fraction")), "Out-of-range metric"
    print(json.dumps(meta, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

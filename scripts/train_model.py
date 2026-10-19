"""Train from a local CSV: python scripts/train_model.py --csv data/urls.csv"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from phishing_analyzer.model import load_csv, train


def main():
    parser = argparse.ArgumentParser(description="Train phishing URL text model using a labelled CSV")
    parser.add_argument("--csv", required=True, help="CSV with URL,label columns (0 phishing / 1 legitimate)")
    parser.add_argument("--out", default=str(ROOT / "models"), help="Model artifacts output directory")
    args = parser.parse_args()
    report = train(load_csv(args.csv), args.out)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

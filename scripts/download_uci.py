"""Opt-in dataset downloader for UCI PhiUSIIL (ID 967). Network required."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    try:
        from ucimlrepo import fetch_ucirepo
    except ImportError as exc:
        raise SystemExit("Install training dependencies first: pip install -r requirements-train.txt") from exc
    dataset = fetch_ucirepo(id=967)
    x = dataset.data.features
    y = dataset.data.targets.iloc[:, 0]
    col = "URL" if "URL" in x else next((c for c in x if c.lower() == "url"), None)
    if col is None:
        raise ValueError("No URL column returned by UCI dataset 967")
    import pandas as pd
    frame = pd.DataFrame({"URL": x[col], "label": y}).dropna()
    dest = ROOT / "data" / "phiusiil_urls.csv"
    dest.parent.mkdir(exist_ok=True)
    frame.to_csv(dest, index=False)
    print(f"Saved {len(frame)} labelled URLs to {dest}")
    print("Label convention is 0=phishing, 1=legitimate. Verify with dataset documentation before training.")


if __name__ == "__main__":
    main()

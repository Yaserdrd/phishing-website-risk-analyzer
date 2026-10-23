"""Record a trusted frozen build without loading its pickle or retraining it."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from phishing_analyzer.provenance import create_manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--uci-csv", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    destination = Path(args.out)
    inputs = [Path(args.uci_csv), Path(args.model_dir) / "url_phishing_model.pkl",
              Path(args.model_dir) / "url_model_meta.json"]
    if destination.resolve() in {p.resolve() for p in inputs}:
        parser.error("Manifest output must differ from input artifacts")
    manifest = create_manifest(args.source_root, args.model_dir, args.uci_csv)
    raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as handle:
        handle.write(raw)
    print(hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    main()

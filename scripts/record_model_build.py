"""Record candidate build evidence after an authorized build; never retrain/load."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from phishing_analyzer.build_evidence import capture
from phishing_analyzer.model import MODEL_FILE, META_FILE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', default=str(ROOT))
    parser.add_argument('--model-dir', required=True)
    parser.add_argument('--uci-csv', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    destination = Path(args.out).resolve()
    inputs = [Path(args.model_dir) / MODEL_FILE, Path(args.model_dir) / META_FILE, Path(args.uci_csv)]
    if destination.exists() or destination in {p.resolve() for p in inputs}:
        parser.error('Build evidence must be new and must not overwrite an input')
    evidence = capture(args.source_root, args.model_dir, args.uci_csv)
    data = (json.dumps(evidence, indent=2, sort_keys=True) + '\n').encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as handle:
        handle.write(data)
    print(hashlib.sha256(data).hexdigest())


if __name__ == '__main__':
    main()

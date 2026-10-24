"""Retain approved packages and prepare reversible operator configuration offline."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from phishing_analyzer.releases import stage, smoke, activate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("stage", "smoke", "activate"):
        command = commands.add_parser(name)
        command.add_argument("--store", required=True, help="Private persistent directory outside checkout")
        command.add_argument("--manifest-sha256", required=True, help="Digest approved independently of the package supplier")
        if name == "stage":
            command.add_argument("--model-dir", required=True)
            command.add_argument("--manifest", required=True)
        if name == "activate":
            command.add_argument("--env-file", required=True, help="Trusted shell config outside retained store; restart required")
    args = parser.parse_args()
    if args.command == "stage":
        stage(args.store, args.model_dir, args.manifest, args.manifest_sha256)
        result = {"staged_manifest_sha256": args.manifest_sha256, "deserialized": False}
    elif args.command == "smoke":
        result = smoke(args.store, args.manifest_sha256)
    else:
        result = activate(args.store, args.manifest_sha256, args.env_file)
        result["restart_required"] = True
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

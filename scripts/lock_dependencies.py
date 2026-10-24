"""Refresh or verify Linux x86_64 development/research dependency locks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("requirements.txt", "requirements-train.txt", "requirements-dev.txt")
VERSIONS = ("3.10", "3.11", "3.12")
UV_VERSION = "0.12.23"
MANIFEST = "requirements/lock-manifest.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {
        "schema_version": 1,
        "compiler": f"uv {UV_VERSION}",
        "platform": "x86_64-unknown-linux-gnu",
        "inputs": {name: digest(root / name) for name in INPUTS},
        "locks": {f"requirements/py{version.replace('.', '')}.lock": digest(
            root / f"requirements/py{version.replace('.', '')}.lock") for version in VERSIONS},
    }


def verify(root=ROOT):
    if json.loads((root / MANIFEST).read_text()) != snapshot(root):
        raise ValueError("Dependency inputs or locks changed; refresh and review all locks")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Offline input/lock identity check; no resolver needed")
    args = parser.parse_args()
    if args.check:
        verify()
        print("Dependency inputs and three locks match the recorded identities")
        return
    installed = subprocess.check_output(["uv", "--version"], text=True).split()
    if installed[:2] != ["uv", UV_VERSION]:
        parser.error(f"Refresh requires uv {UV_VERSION}")
    (ROOT / "requirements").mkdir(exist_ok=True)
    for version in VERSIONS:
        subprocess.run([
            "uv", "pip", "compile", "requirements-dev.txt", "--python-version", version,
            "--python-platform", "x86_64-unknown-linux-gnu", "--generate-hashes",
            "--only-binary", ":all:", "--custom-compile-command", "python scripts/lock_dependencies.py",
            "--output-file", f"requirements/py{version.replace('.', '')}.lock", "--quiet",
        ], cwd=ROOT, check=True)
    (ROOT / MANIFEST).write_text(json.dumps(snapshot(ROOT), indent=2) + "\n")
    verify()


if __name__ == "__main__":
    main()

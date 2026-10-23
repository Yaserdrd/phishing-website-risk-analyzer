"""Identity checks for artifacts approved by a trusted build/review process.

A digest pins bytes; it does not authenticate whoever supplied those bytes.
Never accept an artifact and its trust-anchor digest from an untrusted source.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import platform
import re
import subprocess
from importlib import metadata, resources
from pathlib import Path

import joblib

from .model import META_FILE, MODEL_FILE

FROZEN_COMMIT = "9a3ced00d98a40773837e0f52aa236c9c1b3c45f"
MODEL_VERSION = "2.1.0"


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def runtime_identity():
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "packages": dict(sorted((dist.metadata["Name"].lower(), dist.version)
                                for dist in metadata.distributions())),
        "psl_sha256": hashlib.sha256(
            resources.files("tldextract").joinpath(".tld_set_snapshot").read_bytes()
        ).hexdigest(),
    }


def evaluation_code_identity(root):
    """Record actual evaluator bytes, including any local tracked modifications."""
    root = Path(root)
    files = sorted([*(root / "src" / "phishing_analyzer").glob("*.py"),
                    *(root / "scripts").glob("*.py")])
    return {
        "commit": subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip(),
        "files_sha256": {str(path.relative_to(root)): sha256_file(path) for path in files},
    }


def _metadata(data):
    meta = json.loads(data)
    if not isinstance(meta, dict) or meta.get("version") != MODEL_VERSION:
        raise ValueError("Frozen v2.1 metadata required")
    low, high = meta.get("legitimate_threshold"), meta.get("phishing_threshold")
    if (any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
            for v in (low, high)) or low >= high):
        raise ValueError("Invalid frozen decision thresholds")
    return meta


def create_manifest(source_root, model_dir, uci_csv):
    """Record identities immediately after a trusted, clean frozen-source build.

    This checks checkout identity, not whether a particular training command ran.
    The caller's trusted pipeline must bind the training operation to these files.
    """
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source_root), *args], text=True).strip()

    if git("rev-parse", "HEAD") != FROZEN_COMMIT:
        raise ValueError("Training checkout is not the registered frozen commit")
    if git("status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Frozen training checkout must be clean")
    target = Path(model_dir)
    _metadata((target / META_FILE).read_bytes())
    return {
        "schema_version": 1,
        "training_commit": FROZEN_COMMIT,
        "model_version": MODEL_VERSION,
        "sha256": {
            "model": sha256_file(target / MODEL_FILE),
            "metadata": sha256_file(target / META_FILE),
            "uci_csv": sha256_file(uci_csv),
        },
        "environment": runtime_identity(),
    }


def load_verified_model(model_dir, uci_csv, manifest_path, expected_manifest_sha256):
    """Check the trusted envelope and all inputs BEFORE deserializing pickle.

    Deserialize the exact verified buffer so a later pathname replacement cannot
    change which model is loaded. The general-purpose app loader is unchanged.
    """
    if not isinstance(expected_manifest_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", expected_manifest_sha256):
        raise ValueError("A trusted lowercase manifest SHA-256 is required")
    with Path(manifest_path).open("rb") as handle:
        raw = handle.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Manifest too large")
    if hashlib.sha256(raw).hexdigest() != expected_manifest_sha256:
        raise ValueError("Manifest digest mismatch")
    manifest = json.loads(raw)
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
            or manifest.get("training_commit") != FROZEN_COMMIT
            or manifest.get("model_version") != MODEL_VERSION):
        raise ValueError("Unsupported frozen model identity")
    hashes = manifest.get("sha256")
    if not isinstance(hashes, dict) or any(
            not isinstance(hashes.get(k), str) or not re.fullmatch(r"[0-9a-f]{64}", hashes[k])
            for k in ("model", "metadata", "uci_csv")):
        raise ValueError("Invalid artifact digests")
    if manifest.get("environment") != runtime_identity():
        raise ValueError("Evaluation environment differs from the frozen build")
    target = Path(model_dir)
    model_data = (target / MODEL_FILE).read_bytes()
    meta_data = (target / META_FILE).read_bytes()
    if (hashlib.sha256(model_data).hexdigest() != hashes["model"]
            or hashlib.sha256(meta_data).hexdigest() != hashes["metadata"]
            or sha256_file(uci_csv) != hashes["uci_csv"]):
        raise ValueError("Frozen artifact or UCI digest mismatch")
    meta = _metadata(meta_data)
    model = joblib.load(io.BytesIO(model_data))
    provenance = {**manifest, "manifest_sha256": expected_manifest_sha256}
    return model, meta, provenance

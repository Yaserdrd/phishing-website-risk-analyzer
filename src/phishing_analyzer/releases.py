"""Operator-only approved package retention and atomic shell configuration.

Files remain operator-owned: read-only modes prevent accidents, not an owner's
tampering. No training, network access, approval generation or threshold edits.
"""
from contextlib import contextmanager
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

from .analyzer import analyze
from .model import MODEL_FILE, META_FILE
from .private_files import private_path
from .provenance import verify_model_bundle
from .serving import load_app_model, MAX_SERVING_MODEL_BYTES, MAX_SERVING_METADATA_BYTES

MANIFEST = "frozen_manifest.json"
LIMITS = {MODEL_FILE: MAX_SERVING_MODEL_BYTES, META_FILE: MAX_SERVING_METADATA_BYTES,
          MANIFEST: 1_000_000}


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Independently approved lowercase manifest SHA-256 required")
    return value


@contextmanager
def _writer(store):
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = store / ".release.lock"
    with lock.open("x") as handle:
        handle.write(f"{os.getpid()}\n")
    try:
        yield
    finally:
        lock.unlink()


def _package(store, digest):
    root = private_path(store)
    package = root / _digest(digest)
    if package.is_symlink() or not package.is_dir():
        raise ValueError("Retained package missing or symlinked")
    for name in LIMITS:
        path = package / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > LIMITS[name]:
            raise ValueError("Invalid retained package file")
    return package


def stage(store, model_dir, manifest, approved_digest):
    """Retain a verified exact-byte snapshot without ever unpickling it."""
    root = private_path(store)
    approved_digest = _digest(approved_digest)
    source = private_path(model_dir)
    manifest = private_path(manifest)
    with _writer(root):
        destination = root / approved_digest
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("Retained release already exists; never overwrite it")
        temporary = Path(tempfile.mkdtemp(prefix=".incoming-", dir=root))
        try:
            for name, limit in LIMITS.items():
                path = manifest if name == MANIFEST else source / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Package source must contain regular files")
                with path.open("rb") as handle:
                    data = handle.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("Package file exceeds size limit")
                with (temporary / name).open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            verify_model_bundle(temporary, temporary / MANIFEST, approved_digest)
            for path in temporary.iterdir():
                path.chmod(0o444)
            temporary.chmod(0o555)
            temporary.rename(destination)
        finally:
            if temporary.exists():
                temporary.chmod(0o700)
                shutil.rmtree(temporary)
    return destination


def smoke(store, approved_digest):
    """Trusted pickle execution: verify identity and run one reserved URL offline."""
    package = _package(store, approved_digest)
    model, meta = load_app_model(package, package / MANIFEST, approved_digest, required=True)
    result = analyze("https://example.invalid/", model, meta, active=False)
    return {"manifest_sha256": approved_digest, "model_version": meta["version"],
            "model_decision": result["ml"]["label"], "live_checks": False}


def activate(store, approved_digest, env_file):
    """Smoke first, atomically replace one shell env file; rollback uses same path.

    Does not modify running processes. Restart the service after sourcing the
    operator-owned file. A failed smoke leaves the previous config untouched.
    """
    root = private_path(store)
    supplied = Path(env_file)
    if supplied.is_symlink():
        raise ValueError("Service configuration must not be a symlink")
    destination = private_path(env_file)
    if destination == root or root in destination.parents:
        raise ValueError("Service configuration must be outside the retained store")
    with _writer(root):
        result = smoke(root, approved_digest)
        package = _package(root, approved_digest)
        values = {"PHISHING_MODEL_DIR": str(package),
                  "PHISHING_MODEL_MANIFEST": str(package / MANIFEST),
                  "PHISHING_MODEL_MANIFEST_SHA256": approved_digest}
        content = "".join(f"export {key}={shlex.quote(value)}\n" for key, value in values.items())
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix=".model-env-", dir=destination.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    return result

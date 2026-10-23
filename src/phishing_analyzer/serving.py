"""Trusted model startup and a guarded local inference contract for the UI."""
import io
from pathlib import Path

import joblib
import numpy as np

from .model import META_FILE, MODEL_FILE
from .provenance import verify_model_bundle

MAX_SERVING_MODEL_BYTES = 256 * 1024 * 1024
MAX_SERVING_METADATA_BYTES = 1024 * 1024


class ModelUnavailable(RuntimeError):
    """A model cannot provide a usable prediction; do not expose its raw error."""


class ServingModel:
    def __init__(self, model):
        self._model = model
        try:
            self.classes_ = np.asarray(model.classes_).copy()
            if (self.classes_.shape != (2,) or set(self.classes_.tolist()) != {0, 1}
                    or not callable(model.predict_proba)):
                raise ValueError("Incompatible classifier contract")
            self.predict_proba(["https://example.invalid/"])
        except Exception as exc:
            raise ModelUnavailable("Model startup validation failed") from exc

    def predict_proba(self, urls):
        try:
            values = np.asarray(self._model.predict_proba(urls), dtype=float)
            if (values.shape != (len(urls), 2) or not np.isfinite(values).all()
                    or (values < 0).any() or (values > 1).any()
                    or not np.allclose(values.sum(axis=1), 1, rtol=0, atol=1e-6)):
                raise ValueError("Invalid classifier output")
            return values
        except Exception as exc:
            raise ModelUnavailable("Model prediction unavailable") from exc


def model_revision(model_dir, manifest_path):
    """Cache key detects installation/removal/replacement without reading pickle."""
    result = []
    for path in (Path(model_dir) / MODEL_FILE, Path(model_dir) / META_FILE, Path(manifest_path)):
        try:
            stat = path.stat()
            result.append((stat.st_ino, stat.st_size, stat.st_mtime_ns))
        except FileNotFoundError:
            result.append(None)
        except OSError as exc:
            raise ModelUnavailable("Model files unavailable") from exc
    return tuple(result)


def load_app_model(model_dir, manifest_path, approved_sha256, *, required=False):
    """Missing installation is demo mode; partial/unapproved packages are errors.

    Trust is operator-supplied. Hashing an arbitrary pickle does not make it safe.
    No training corpus, network call, model training or threshold change occurs.
    """
    try:
        revision = model_revision(model_dir, manifest_path)
        if not required and not approved_sha256 and all(item is None for item in revision):
            return None, None
        for path, limit in ((Path(model_dir) / MODEL_FILE, MAX_SERVING_MODEL_BYTES),
                            (Path(model_dir) / META_FILE, MAX_SERVING_METADATA_BYTES)):
            if path.stat().st_size > limit:
                raise ValueError("Model package exceeds serving size limit")
        data, meta, _ = verify_model_bundle(model_dir, manifest_path, approved_sha256)
        return ServingModel(joblib.load(io.BytesIO(data))), meta
    except Exception as exc:
        raise ModelUnavailable("Model package unavailable") from exc

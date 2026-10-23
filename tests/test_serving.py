"""Safe temporary packages and guarded inference; no training or live URLs."""
import hashlib
import json

import joblib
import numpy as np
import pytest

from phishing_analyzer import provenance, serving
from phishing_analyzer.model import META_FILE, MODEL_FILE


class GoodModel:
    classes_ = np.array([0, 1])
    def predict_proba(self, urls):
        return np.array([[.9, .1] for _ in urls])


class OutputModel(GoodModel):
    def __init__(self, output):
        self.output = output
    def predict_proba(self, urls):
        return self.output


@pytest.fixture
def package(tmp_path):
    joblib.dump(GoodModel(), tmp_path / MODEL_FILE)
    meta = {'version': '2.1.0', 'legitimate_threshold': .03, 'phishing_threshold': .08}
    (tmp_path / META_FILE).write_text(json.dumps(meta))
    manifest = {'schema_version': 1, 'training_commit': provenance.FROZEN_COMMIT,
        'model_version': '2.1.0', 'environment': provenance.runtime_identity(),
        'sha256': {'model': provenance.sha256_file(tmp_path / MODEL_FILE),
                   'metadata': provenance.sha256_file(tmp_path / META_FILE), 'uci_csv': '0' * 64}}
    path = tmp_path / 'frozen_manifest.json'
    def approve():
        path.write_text(json.dumps(manifest))
        return hashlib.sha256(path.read_bytes()).hexdigest()
    digest = approve()
    return tmp_path, path, manifest, digest, approve


def test_serving_verifies_package_without_training_csv(package):
    root, path, _, digest, _ = package
    model, meta = serving.load_app_model(root, path, digest)
    assert model.predict_proba(['https://example.invalid/']).tolist() == [[.9, .1]]
    assert meta['phishing_threshold'] == .08


def test_missing_unconfigured_package_is_intentional_demo(tmp_path):
    assert serving.load_app_model(tmp_path, tmp_path / 'manifest.json', '') == (None, None)


@pytest.mark.parametrize('condition', ['required', 'partial', 'unapproved', 'tampered', 'metadata', 'environment'])
def test_bad_packages_are_controlled_and_invalid_identity_never_unpickles(package, monkeypatch, condition):
    root, path, manifest, digest, approve = package
    required = False
    if condition == 'required':
        for file in root.iterdir(): file.unlink()
        required = True
    if condition == 'partial': (root / META_FILE).unlink()
    if condition == 'unapproved': digest = ''
    if condition == 'tampered': (root / MODEL_FILE).write_bytes(b'changed')
    if condition == 'metadata':
        (root / META_FILE).write_text(json.dumps({'version': 'unsupported'}))
        manifest['sha256']['metadata'] = provenance.sha256_file(root / META_FILE)
        digest = approve()
    if condition == 'environment':
        manifest['environment']['python'] = '0.0.0'
        digest = approve()
    monkeypatch.setattr(serving.joblib, 'load', lambda _: pytest.fail('Invalid package reached unpickling'))
    with pytest.raises(serving.ModelUnavailable):
        serving.load_app_model(root, path, digest, required=required)


def test_corrupt_but_approved_model_does_not_escape_as_raw_exception(package):
    root, path, manifest, _, approve = package
    (root / MODEL_FILE).write_bytes(b'not-a-model')
    manifest['sha256']['model'] = provenance.sha256_file(root / MODEL_FILE)
    with pytest.raises(serving.ModelUnavailable):
        serving.load_app_model(root, path, approve())


def test_wrong_classifier_contract_is_rejected(package):
    root, path, manifest, _, approve = package
    joblib.dump({'not': 'a classifier'}, root / MODEL_FILE)
    manifest['sha256']['model'] = provenance.sha256_file(root / MODEL_FILE)
    with pytest.raises(serving.ModelUnavailable):
        serving.load_app_model(root, path, approve())


@pytest.mark.parametrize('output', [[[float('nan'), .1]], [[float('inf'), .1]],
    [[-.1, 1.1]], [[.5]], [[.2, .2]], [[.9, .1], [.9, .1]]])
def test_invalid_probabilities_never_become_model_decisions(output):
    with pytest.raises(serving.ModelUnavailable):
        serving.ServingModel(OutputModel(output))


def test_output_contract_is_checked_on_every_request():
    raw = GoodModel()
    model = serving.ServingModel(raw)
    raw.predict_proba = lambda _: [[float('nan'), .1]]
    with pytest.raises(serving.ModelUnavailable):
        model.predict_proba(['https://example.invalid/'])


def test_model_backend_failure_becomes_sanitized_unavailability():
    raw = GoodModel()
    model = serving.ServingModel(raw)
    def fail(urls):
        raise RuntimeError('PRIVATE-MODEL-DETAILS')
    raw.predict_proba = fail
    with pytest.raises(serving.ModelUnavailable) as error:
        model.predict_proba(['https://example.invalid/'])
    assert 'PRIVATE-MODEL-DETAILS' not in str(error.value)


def test_package_size_limits_are_checked_before_deserialization(package, monkeypatch):
    root, path, _, digest, _ = package
    monkeypatch.setattr(serving, 'MAX_SERVING_MODEL_BYTES', 1)
    monkeypatch.setattr(serving.joblib, 'load', lambda _: pytest.fail('Oversized package unpickled'))
    with pytest.raises(serving.ModelUnavailable):
        serving.load_app_model(root, path, digest)

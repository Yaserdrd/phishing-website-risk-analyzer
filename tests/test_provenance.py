"""Offline trust-boundary and CLI checks; only safe temporary fake artifacts."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pytest

from phishing_analyzer import provenance as identity
from phishing_analyzer.model import META_FILE, MODEL_FILE

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import prospective_holdout as positive
import evaluate_vetted_holdout as vetted
import freeze_manifest

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)


@pytest.fixture
def bundle(tmp_path):
    models = tmp_path / 'models'
    models.mkdir()
    joblib.dump({'safe_fake_model': True}, models / MODEL_FILE)
    (models / META_FILE).write_text(json.dumps({
        'version': '2.1.0', 'legitimate_threshold': .03, 'phishing_threshold': .08}))
    uci = tmp_path / 'uci.csv'
    uci.write_text('URL,label\nhttps://uci.test/,1\n')
    manifest = {
        'schema_version': 1, 'training_commit': identity.FROZEN_COMMIT,
        'model_version': '2.1.0', 'environment': identity.runtime_identity(),
        'sha256': {'model': identity.sha256_file(models / MODEL_FILE),
                   'metadata': identity.sha256_file(models / META_FILE),
                   'uci_csv': identity.sha256_file(uci)},
    }
    path = tmp_path / 'manifest.json'
    def write():
        path.write_text(json.dumps(manifest))
        return identity.sha256_file(path)
    digest = write()
    return models, uci, path, manifest, digest, write


def load(bundle, digest=None):
    models, uci, path, _, approved, _ = bundle
    return identity.load_verified_model(models, uci, path, approved if digest is None else digest)


def test_matching_bundle_loads_and_reports_identity(bundle):
    model, meta, provenance = load(bundle)
    assert model == {'safe_fake_model': True}
    assert meta['phishing_threshold'] == .08
    assert provenance['manifest_sha256'] == bundle[4]
    assert provenance['training_commit'] == identity.FROZEN_COMMIT


@pytest.mark.parametrize('target', ['manifest', 'model', 'metadata', 'uci', 'environment', 'commit', 'version', 'schema', 'hash'])
def test_tampered_or_incompatible_bundle_never_deserializes(bundle, monkeypatch, target):
    models, uci, path, manifest, digest, write = bundle
    if target in ('manifest', 'model', 'metadata', 'uci'):
        file = {'manifest': path, 'model': models / MODEL_FILE,
                'metadata': models / META_FILE, 'uci': uci}[target]
        file.write_bytes(file.read_bytes() + b' ')
    else:
        if target == 'environment': manifest['environment']['python'] = '0.0.0'
        if target == 'commit': manifest['training_commit'] = '0' * 40
        if target == 'version': manifest['model_version'] = '3.0.0'
        if target == 'schema': manifest['schema_version'] = 2
        if target == 'hash': manifest['sha256']['model'] = 'not-a-hash'
        digest = write()
    def forbidden(*args, **kwargs):
        raise AssertionError('Invalid identity reached pickle loader')
    monkeypatch.setattr(identity.joblib, 'load', forbidden)
    with pytest.raises(ValueError):
        load(bundle, digest)


@pytest.mark.parametrize('digest', ['', 'untrusted', 'A' * 64])
def test_explicit_trust_anchor_required(bundle, digest):
    with pytest.raises(ValueError, match='trusted'):
        load(bundle, digest)


def test_invalid_metadata_rejected_before_unpickle_even_with_matching_hash(bundle, monkeypatch):
    models, _, _, manifest, _, write = bundle
    (models / META_FILE).write_text(json.dumps({
        'version': '2.1.0', 'legitimate_threshold': .9, 'phishing_threshold': .1}))
    manifest['sha256']['metadata'] = identity.sha256_file(models / META_FILE)
    digest = write()
    monkeypatch.setattr(identity.joblib, 'load', lambda _: pytest.fail('Unpickle before threshold validation'))
    with pytest.raises(ValueError, match='thresholds'):
        load(bundle, digest)


def test_deserializes_verified_buffer_not_replaceable_path(bundle, monkeypatch):
    original = identity.joblib.load
    def replace_path_then_load(buffer):
        assert hasattr(buffer, 'read')
        (bundle[0] / MODEL_FILE).write_bytes(b'replaced after verification')
        return original(buffer)
    monkeypatch.setattr(identity.joblib, 'load', replace_path_then_load)
    assert load(bundle)[0] == {'safe_fake_model': True}


@pytest.mark.parametrize('head,dirty', [('0' * 40, ''), (identity.FROZEN_COMMIT, ' M src/model.py')])
def test_manifest_builder_rejects_wrong_or_dirty_training_source(bundle, monkeypatch, head, dirty):
    monkeypatch.setattr(identity.subprocess, 'check_output',
                        lambda args, **kwargs: head if 'rev-parse' in args else dirty)
    with pytest.raises(ValueError):
        identity.create_manifest('.', bundle[0], bundle[1])


def test_manifest_builder_records_clean_frozen_source(bundle, monkeypatch):
    monkeypatch.setattr(identity.subprocess, 'check_output',
                        lambda args, **kwargs: identity.FROZEN_COMMIT if 'rev-parse' in args else '')
    assert identity.create_manifest('.', bundle[0], bundle[1]) == bundle[3]


def test_manifest_cli_writes_digest_and_refuses_overwrite(bundle, monkeypatch, tmp_path, capsys):
    destination = tmp_path / 'new-manifest.json'
    monkeypatch.setattr(identity.subprocess, 'check_output',
                        lambda args, **kwargs: identity.FROZEN_COMMIT if 'rev-parse' in args else '')
    monkeypatch.setattr(sys, 'argv', ['freeze_manifest', '--source-root', '.',
                        '--model-dir', str(bundle[0]), '--uci-csv', str(bundle[1]),
                        '--out', str(destination)])
    freeze_manifest.main()
    assert capsys.readouterr().out.strip() == identity.sha256_file(destination)
    original = destination.read_bytes()
    with pytest.raises(FileExistsError):
        freeze_manifest.main()
    assert destination.read_bytes() == original


def test_manifest_cli_cannot_overwrite_an_input(bundle, monkeypatch):
    monkeypatch.setattr(sys, 'argv', ['freeze_manifest', '--source-root', '.',
                        '--model-dir', str(bundle[0]), '--uci-csv', str(bundle[1]),
                        '--out', str(bundle[1])])
    with pytest.raises(SystemExit) as exc:
        freeze_manifest.main()
    assert exc.value.code == 2


@pytest.mark.parametrize('module', [positive, vetted])
def test_holdout_cli_requires_manifest_arguments(module, monkeypatch, tmp_path):
    output = tmp_path / 'report.json'
    flags = ['--uci-csv', 'uci.csv', '--out', str(output)]
    flags += ['--phishing-csv' if module is positive else '--vetted-csv', 'data.csv']
    monkeypatch.setattr(sys, 'argv', ['evaluate', *flags])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2
    assert not output.exists()


@pytest.mark.parametrize('module', [positive, vetted])
def test_holdout_cli_uses_verified_identity_and_emits_aggregates(bundle, monkeypatch, tmp_path, module):
    models, uci, path, _, digest, _ = bundle
    data = tmp_path / 'feed.csv'
    output = tmp_path / 'report.json'
    if module is positive:
        data.write_text('url,verified,online,submission_time,verification_time\n'
                        'https://new.test/,yes,yes,2026-10-24T00:00:00Z,2026-10-25T00:00:00Z\n')
        extra = ['--phishing-csv', str(data), '--min-count', '1']
    else:
        data.write_text('url,label,observed_at_utc,verified_at_utc,evidence_ref,reviewer_id\n'
                        'https://new.test/,PHISHING,2026-10-24T00:00:00Z,2026-10-25T00:00:00Z,ref1,a\n'
                        'https://other.test/,LEGITIMATE,2026-10-24T00:00:00Z,2026-10-25T00:00:00Z,ref2,b\n')
        extra = ['--vetted-csv', str(data), '--min-per-class', '1']
    monkeypatch.setattr(module, 'evaluation_time', lambda now=None: NOW if now is None else now)
    monkeypatch.setattr(module, 'predict', lambda url, *_: {
        'label': 'LEGITIMATE' if 'other.test' in url else 'PHISHING'})
    monkeypatch.setattr(sys, 'argv', ['evaluate', '--uci-csv', str(uci), '--model-dir', str(models),
                        '--manifest', str(path), '--manifest-sha256', digest, '--out', str(output), *extra])
    module.main()
    report = json.loads(output.read_text())
    assert report['model_provenance']['manifest_sha256'] == digest
    assert report['frozen_training_commit'] == identity.FROZEN_COMMIT
    assert 'src/phishing_analyzer/protocol.py' in report['evaluation_code']['files_sha256']
    assert 'https://new.test' not in output.read_text()
    # A stale/bad trust anchor must not produce a new report.
    output.unlink()
    monkeypatch.setattr(sys, 'argv', [arg if arg != digest else '0' * 64 for arg in sys.argv])
    with pytest.raises(ValueError, match='digest mismatch'):
        module.main()
    assert not output.exists()

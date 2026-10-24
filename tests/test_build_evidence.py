"""Source/data/runtime capture without any deserialization or training."""
import json
from pathlib import Path
import subprocess
import sys

import joblib
import pytest

from phishing_analyzer import build_evidence, provenance
from phishing_analyzer.model import MODEL_FILE, META_FILE


@pytest.fixture
def build(tmp_path):
    root, models = tmp_path / 'source', tmp_path / 'models'
    (root / 'src').mkdir(parents=True)
    (root / 'src' / 'example.py').write_text('VALUE = 1\n')
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True)
    git('init', '-q')
    git('add', 'src/example.py')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    models.mkdir()
    (models / MODEL_FILE).write_bytes(b'not a pickle; never load')
    (models / META_FILE).write_text(json.dumps({'version': '2.1.0',
        'legitimate_threshold': .03, 'phishing_threshold': .08}))
    csv = tmp_path / 'uci.csv'
    csv.write_text('URL,label\nhttps://private-fixture.invalid/,1\n')
    return root, models, csv, git


def test_capture_binds_inputs_source_and_runtime_without_approving(build, monkeypatch):
    root, models, csv, git = build
    monkeypatch.setattr(joblib, 'load', lambda *_: pytest.fail('Build evidence deserialized a model'))
    result = build_evidence.capture(root, models, csv)
    assert result['source']['commit'] == git('rev-parse', 'HEAD').strip()
    assert result['source']['files_sha256']['src/example.py'] == provenance.sha256_file(root / 'src/example.py')
    assert result['sha256']['uci_csv'] == provenance.sha256_file(csv)
    assert result['environment'] == provenance.runtime_identity()
    assert result['approval'] == 'not-approved'
    encoded = json.dumps(result)
    assert 'private-fixture' not in encoded and str(csv) not in encoded
    assert 'training_commit' not in result  # deliberately not an approved frozen manifest


@pytest.mark.parametrize('condition', ['tracked', 'untracked'])
def test_dirty_source_is_rejected(build, condition):
    root, models, csv, _ = build
    target = root / ('src/example.py' if condition == 'tracked' else 'extra.py')
    target.write_text('changed\n')
    with pytest.raises(ValueError, match='clean'):
        build_evidence.capture(root, models, csv)


def test_inputs_changing_during_capture_are_rejected(build, monkeypatch):
    root, models, csv, _ = build
    def runtime():
        csv.write_text('changed after hashing')
        return {}
    monkeypatch.setattr(build_evidence, 'runtime_identity', runtime)
    with pytest.raises(ValueError, match='changed'):
        build_evidence.capture(root, models, csv)


def test_unsupported_metadata_rejected(build):
    root, models, csv, _ = build
    (models / META_FILE).write_text('{"version": "unknown"}')
    with pytest.raises(ValueError, match='v2.1'):
        build_evidence.capture(root, models, csv)


def test_invalid_workflow_identity_rejected(build, monkeypatch):
    root, models, csv, _ = build
    monkeypatch.setenv('GITHUB_RUN_ID', 'not-a-run')
    with pytest.raises(ValueError, match='workflow'):
        build_evidence.capture(root, models, csv)


@pytest.mark.parametrize('destination', ['new', 'existing', 'input'])
def test_cli_new_report_only(build, tmp_path, monkeypatch, capsys, destination):
    root, models, csv, _ = build
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
    import record_model_build
    output = csv if destination == 'input' else tmp_path / 'evidence.json'
    if destination == 'existing': output.write_text('keep this report')
    original = output.read_bytes() if output.exists() else None
    monkeypatch.setattr(sys, 'argv', ['record_model_build', '--source-root', str(root),
        '--model-dir', str(models), '--uci-csv', str(csv), '--out', str(output)])
    if destination == 'new':
        record_model_build.main()
        assert capsys.readouterr().out.strip() == provenance.sha256_file(output)
        assert json.loads(output.read_text())['approval'] == 'not-approved'
    else:
        with pytest.raises(SystemExit): record_model_build.main()
        assert output.read_bytes() == original

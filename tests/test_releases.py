"""Retain/install/rollback safe fake models; never use a real model or network."""
import json
import subprocess
import sys

import pytest

from phishing_analyzer import releases, provenance, serving
from phishing_analyzer.model import MODEL_FILE, META_FILE
from phishing_analyzer.private_files import ROOT
from test_serving import package


def test_stage_preserves_exact_bytes_and_never_unpickles(package, tmp_path, monkeypatch):
    source, manifest, _, digest, _ = package
    monkeypatch.setattr(serving.joblib, 'load', lambda *_: pytest.fail('Stage unpickled a model'))
    destination = releases.stage(tmp_path / 'store', source, manifest, digest)
    for name in (MODEL_FILE, META_FILE, releases.MANIFEST):
        original = manifest if name == releases.MANIFEST else source / name
        assert (destination / name).read_bytes() == original.read_bytes()
        assert (destination / name).stat().st_mode & 0o222 == 0
    with pytest.raises(FileExistsError):
        releases.stage(tmp_path / 'store', source, manifest, digest)


@pytest.mark.parametrize('bad', ['digest', 'model', 'environment', 'symlink', 'size'])
def test_bad_stage_leaves_no_retained_release(package, tmp_path, monkeypatch, bad):
    source, manifest, info, digest, approve = package
    if bad == 'digest': digest = '0' * 64
    if bad == 'model': (source / MODEL_FILE).write_bytes(b'changed')
    if bad == 'environment':
        info['environment']['python'] = '0.0.0'
        digest = approve()
    if bad == 'symlink':
        target = tmp_path / 'alias'
        target.write_bytes((source / MODEL_FILE).read_bytes())
        (source / MODEL_FILE).unlink()
        (source / MODEL_FILE).symlink_to(target)
    if bad == 'size': monkeypatch.setitem(releases.LIMITS, MODEL_FILE, 1)
    store = tmp_path / 'store'
    monkeypatch.setattr(serving.joblib, 'load', lambda *_: pytest.fail('Invalid model unpickled'))
    with pytest.raises(ValueError):
        releases.stage(store, source, manifest, digest)
    assert list(store.iterdir()) == []


def test_activate_and_rollback_restore_exact_config(package, tmp_path):
    source, manifest, info, first, approve = package
    store, config = tmp_path / 'store', tmp_path / 'service.env'
    first_path = releases.stage(store, source, manifest, first)
    result = releases.activate(store, first, config)
    original = config.read_bytes()
    assert result['live_checks'] is False and result['model_decision'] == 'PHISHING'
    assert config.stat().st_mode & 0o077 == 0
    meta = json.loads((source / META_FILE).read_text())
    meta['release_note'] = 'second fake package, identical thresholds'
    (source / META_FILE).write_text(json.dumps(meta))
    info['sha256']['metadata'] = provenance.sha256_file(source / META_FILE)
    second = approve()
    releases.stage(store, source, manifest, second)
    releases.activate(store, second, config)
    assert config.read_bytes() != original
    releases.activate(store, first, config)
    assert config.read_bytes() == original and first_path.exists()


def test_failed_activation_preserves_previous_config(package, tmp_path):
    source, manifest, _, digest, _ = package
    store, config = tmp_path / 'store', tmp_path / 'service.env'
    destination = releases.stage(store, source, manifest, digest)
    releases.activate(store, digest, config)
    previous = config.read_bytes()
    artifact = destination / MODEL_FILE
    artifact.chmod(0o644)
    artifact.write_bytes(b'corrupt')
    with pytest.raises(serving.ModelUnavailable):
        releases.activate(store, digest, config)
    assert config.read_bytes() == previous


def test_bad_but_hash_approved_pickle_cannot_replace_config(package, tmp_path):
    source, manifest, info, _, approve = package
    (source / MODEL_FILE).write_bytes(b'not a pickle')
    info['sha256']['model'] = provenance.sha256_file(source / MODEL_FILE)
    digest = approve()
    store, config = tmp_path / 'store', tmp_path / 'service.env'
    releases.stage(store, source, manifest, digest)
    config.write_text('preserve previous configuration')
    with pytest.raises(serving.ModelUnavailable):
        releases.activate(store, digest, config)
    assert config.read_text() == 'preserve previous configuration'


def test_store_lock_prevents_concurrent_writer(package, tmp_path):
    source, manifest, _, digest, _ = package
    store = tmp_path / 'store'
    store.mkdir()
    lock = store / '.release.lock'
    lock.write_text('other operator')
    with pytest.raises(FileExistsError):
        releases.stage(store, source, manifest, digest)
    assert lock.read_text() == 'other operator'


@pytest.mark.parametrize('bad', ['checkout', 'traversal', 'config_in_store', 'config_symlink', 'package_symlink'])
def test_unsafe_targets_rejected(package, tmp_path, bad):
    source, manifest, _, digest, _ = package
    store, config = tmp_path / 'store', tmp_path / 'service.env'
    releases.stage(store, source, manifest, digest)
    if bad == 'checkout':
        with pytest.raises(ValueError): releases.stage(ROOT / 'models', source, manifest, digest)
    elif bad == 'traversal':
        with pytest.raises(ValueError): releases.activate(store, '../other', config)
    elif bad == 'config_in_store':
        with pytest.raises(ValueError): releases.activate(store, digest, store / 'active.env')
    elif bad == 'config_symlink':
        config.symlink_to(tmp_path / 'other.env')
        with pytest.raises(ValueError): releases.activate(store, digest, config)
    else:
        alias = 'f' * 64
        (store / alias).symlink_to(store / digest, target_is_directory=True)
        with pytest.raises(ValueError): releases.smoke(store, alias)


def test_config_quotes_shell_metacharacters(package, tmp_path):
    source, manifest, _, digest, _ = package
    store = tmp_path / "store with spaces ' $ ( ) ;"
    config = tmp_path / 'service.env'
    releases.stage(store, source, manifest, digest)
    releases.activate(store, digest, config)
    actual = subprocess.check_output(
        ['sh', '-c', '. "$1"; printf "%s" "$PHISHING_MODEL_DIR"', 'sh', str(config)], text=True)
    assert actual == str(store / digest)


def test_cli_smoke_emits_only_summary(package, tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / 'scripts'))
    import model_release
    source, manifest, _, digest, _ = package
    store = tmp_path / 'store'
    releases.stage(store, source, manifest, digest)
    monkeypatch.setattr(sys, 'argv', ['model_release', 'smoke', '--store', str(store),
                                    '--manifest-sha256', digest])
    model_release.main()
    output = capsys.readouterr().out
    assert json.loads(output)['manifest_sha256'] == digest
    assert str(store) not in output and 'https://' not in output


def test_original_changes_do_not_change_retained_package(package, tmp_path):
    source, manifest, _, digest, _ = package
    store = tmp_path / 'store'
    releases.stage(store, source, manifest, digest)
    (source / MODEL_FILE).write_bytes(b'changed original')
    manifest.write_text('{}')
    assert releases.smoke(store, digest)['model_version'] == '2.1.0'


def test_atomic_replace_failure_keeps_old_config_and_cleans_temp(package, tmp_path, monkeypatch):
    source, manifest, _, digest, _ = package
    store, config = tmp_path / 'store', tmp_path / 'service.env'
    releases.stage(store, source, manifest, digest)
    config.write_text('previous configuration')
    def fail(*args):
        raise OSError('simulated filesystem failure')
    monkeypatch.setattr(releases.os, 'replace', fail)
    with pytest.raises(OSError):
        releases.activate(store, digest, config)
    assert config.read_text() == 'previous configuration'
    assert not (store / '.release.lock').exists()
    assert list(tmp_path.glob('.model-env-*')) == []

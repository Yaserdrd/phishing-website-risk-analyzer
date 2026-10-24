"""The diagnostic never treats unknown files or process failures as approval."""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import research_model_compatibility as probe


def test_unknown_pickle_bytes_rejected_before_loading(tmp_path):
    path = tmp_path / 'unknown.zip'
    path.write_bytes(b'not an approved historical archive')
    with pytest.raises(ValueError, match='identity'):
        probe.trusted_bytes(path)


@pytest.mark.parametrize('failure', ['timeout', 'failed', 'invalid_json', 'empty_json'])
def test_worker_failure_is_sanitized_and_not_success(tmp_path, monkeypatch, capsys, failure):
    def run(*args, **kwargs):
        assert 'GITHUB_TOKEN' not in kwargs['env']
        assert kwargs['timeout'] == 30
        if failure == 'timeout': raise subprocess.TimeoutExpired('worker', 30)
        return subprocess.CompletedProcess(args[0], 1 if failure == 'failed' else 0,
                                            stdout='{}' if failure == 'empty_json' else 'not-json',
                                            stderr='PRIVATE ERROR DETAILS')
    monkeypatch.setattr(probe.subprocess, 'run', run)
    monkeypatch.setattr(sys, 'argv', ['probe', '--archive', str(tmp_path / 'archive.zip')])
    with pytest.raises(SystemExit) as error: probe.main()
    text = capsys.readouterr().out
    assert error.value.code == 1 and 'false' in text
    assert 'PRIVATE' not in text

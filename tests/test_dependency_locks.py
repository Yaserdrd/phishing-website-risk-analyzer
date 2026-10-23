"""Lock identity gates must catch stale source inputs and changed package files."""
from pathlib import Path
import shutil
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import lock_dependencies as locks


def test_committed_locks_match_all_inputs():
    locks.verify()


@pytest.mark.parametrize('changed', ['requirements.txt', 'requirements/py311.lock'])
def test_stale_or_altered_lock_is_rejected(tmp_path, changed):
    for name in (*locks.INPUTS, locks.MANIFEST, 'requirements/py310.lock',
                 'requirements/py311.lock', 'requirements/py312.lock'):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(locks.ROOT / name, target)
    target = tmp_path / changed
    target.write_text(target.read_text() + '\n# changed bytes\n')
    with pytest.raises(ValueError, match='changed'):
        locks.verify(tmp_path)

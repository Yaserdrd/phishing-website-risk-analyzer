"""Record candidate build identities without approving or loading a model."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess

from .model import MODEL_FILE, META_FILE
from .provenance import _metadata, runtime_identity, sha256_file


def capture(source_root, model_dir, uci_csv):
    root, models = Path(source_root), Path(model_dir)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
    def clean():
        if git('status', '--porcelain', '--untracked-files=normal'):
            raise ValueError('Build source checkout must be clean before capture')
    clean()
    commit = git('rev-parse', 'HEAD')
    source_tree = git('rev-parse', 'HEAD^{tree}')
    inputs = {'model': models / MODEL_FILE, 'metadata': models / META_FILE, 'uci_csv': Path(uci_csv)}
    if inputs['metadata'].stat().st_size > 1_000_000:
        raise ValueError('Model metadata too large')
    metadata_bytes = inputs['metadata'].read_bytes()
    meta = _metadata(metadata_bytes)
    hashes = {name: sha256_file(path) for name, path in inputs.items()}
    import hashlib
    if hashlib.sha256(metadata_bytes).hexdigest() != hashes['metadata']:
        raise ValueError('Build metadata changed during capture')
    tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z', '--',
        'src', 'scripts', 'app.py', '.github/workflows/train-uci.yml', 'requirements',
        'requirements.txt', 'requirements-dev.txt', 'requirements-train.txt']).decode().split('\0')
    files = {name: sha256_file(root / name) for name in tracked if name}
    environment = runtime_identity()
    clean()
    if (git('rev-parse', 'HEAD') != commit or
            any(sha256_file(path) != hashes[name] for name, path in inputs.items())):
        raise ValueError('Build inputs changed during capture')
    run_id = os.environ.get('GITHUB_RUN_ID')
    if run_id is not None and not re.fullmatch(r'[0-9]+', run_id):
        raise ValueError('Invalid workflow run identity')
    return {
        'protocol': 'candidate-model-build-evidence-v1', 'approval': 'not-approved',
        'recorded_at_utc': datetime.now(timezone.utc).isoformat(),
        'source': {'commit': commit, 'tree': source_tree, 'files_sha256': files},
        'model_version': meta['version'], 'sha256': hashes, 'environment': environment,
        'workflow_run_id': run_id,
        'limitations': [
            'Identity capture does not prove that training ran or authenticate an approver.',
            'This is not the approved frozen serving/evaluation manifest.',
            'Retain the original data and an environment/image independently; hashes are not backups.',
        ],
    }

"""Bounded offline diagnostic for the known historical ZIP; never serving approval."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA256 = '380622aa45ab410cf6ae499e5c271c271f05c1329f0f9c0066404b1262f45fda'


def trusted_bytes(path):
    with Path(path).open('rb') as handle:
        raw = handle.read(20_000_001)
    if len(raw) > 20_000_000 or hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Historical archive identity mismatch')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if len(archive.infolist()) != 2 or set(archive.namelist()) != {'url_model_meta.json', 'url_phishing_model.pkl'}:
            raise ValueError('Unexpected historical members')
        if archive.getinfo('url_model_meta.json').file_size > 1_000_000 or archive.getinfo('url_phishing_model.pkl').file_size > 256 * 1024**2:
            raise ValueError('Historical member exceeds bounds')
        meta = json.loads(archive.read('url_model_meta.json'))
        reference = json.loads((ROOT / 'reports/uci_phiusiil_selective_v21_2026-10-21.json').read_text())
        if meta != reference:
            raise ValueError('Historical metadata mismatch')
        return archive.read('url_phishing_model.pkl'), meta


def worker(path):
    # Linux-only operational diagnostic, separate from approved serving loader.
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    def deny_network(event, args):
        if event in {'socket.connect', 'socket.getaddrinfo', 'socket.bind'}:
            raise RuntimeError('Network disabled in compatibility diagnostic')
    sys.addaudithook(deny_network)
    data, meta = trusted_bytes(path)
    sys.path.insert(0, str(ROOT / 'src'))
    import warnings
    import joblib
    from sklearn.exceptions import InconsistentVersionWarning
    from phishing_analyzer.serving import ServingModel
    from phishing_analyzer.analyzer import analyze
    from phishing_analyzer.provenance import runtime_identity
    warnings.simplefilter('error', InconsistentVersionWarning)
    model = ServingModel(joblib.load(io.BytesIO(data)))
    result = analyze('https://example.invalid/', model, meta, active=False)
    assert result['ml']['label'] in {'PHISHING', 'UNCERTAIN', 'LEGITIMATE'}
    return {'protocol': 'trusted-historical-research-compatibility-v1',
        'archive_sha256': ARCHIVE_SHA256, 'model_sha256': hashlib.sha256(data).hexdigest(),
        'real_model_deserialized': True, 'reserved_url_contract_passed': True,
        'network_connections_allowed': False, 'cpu_limit_seconds': 20,
        'address_space_limit_bytes': 2 * 1024**3, 'environment': runtime_identity(),
        'version_warnings_are_errors': True, 'serving_manifest_verified': False,
        'serving_approved': False, 'original_runtime_reproduced': False,
        'running_service_rollback_tested': False, 'performance_evaluated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.archive), indent=2))
        return
    if sys.platform != 'linux':
        parser.error('Diagnostic requires Linux resource limits')
    environment = {'PATH': os.environ.get('PATH', ''), 'OPENBLAS_NUM_THREADS': '1',
                   'OMP_NUM_THREADS': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    try:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--worker',
                                 '--archive', str(Path(args.archive).resolve())],
                                env=environment, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('compatibility worker failed')
        output = json.loads(result.stdout)
        if (not isinstance(output, dict)
                or output.get('protocol') != 'trusted-historical-research-compatibility-v1'
                or output.get('serving_approved') is not False
                or output.get('reserved_url_contract_passed') is not True):
            raise ValueError('Invalid compatibility result contract')
    except (subprocess.TimeoutExpired, RuntimeError, ValueError, OSError):
        print(json.dumps({'compatibility_probe_passed': False, 'serving_approved': False,
                          'diagnostic': 'worker_unavailable_or_incompatible'}))
        raise SystemExit(1)
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()

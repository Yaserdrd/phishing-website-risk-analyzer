"""Adversarial offline provenance/CLI checks; all URLs are reserved fixtures."""
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import review_consensus as rc
import evaluate_vetted_holdout as audit
from phishing_analyzer.private_files import private_path, ROOT
from test_review_consensus import NOW, HEAD, row


@pytest.fixture
def reviews(tmp_path):
    source = tmp_path / 'reviews.csv'
    source.write_text(HEAD + ''.join(
        row(url, label, reviewer, 'evidence-' + reviewer)
        for url, label in [('https://one.example/', 'PHISHING'),
                           ('https://two.example/', 'LEGITIMATE')]
        for reviewer in ['analyst-a', 'analyst-b']))
    records, _ = rc.adjudicate(source, now=NOW)
    vetted = tmp_path / 'vetted.csv'
    vetted.write_bytes(rc.vetted_bytes(records))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return source, vetted, digest


def test_approved_bytes_and_aggregate_provenance(reviews):
    source, vetted, digest = reviews
    data, provenance = rc.approved_consensus(source, vetted, digest, now=NOW)
    assert data == vetted.read_bytes()
    assert provenance['source_sha256'] == digest
    assert provenance['counts']['accepted'] == 2
    assert provenance['review_rows'] == 4
    text = json.dumps(provenance)
    assert all(value not in text for value in ['https://', 'analyst-a', 'evidence-analyst-a'])


@pytest.mark.parametrize('digest', ['', '0' * 64, 'A' * 64, None])
def test_review_anchor_required_and_matched(reviews, digest):
    with pytest.raises(ValueError, match='SHA-256|digest mismatch'):
        rc.approved_consensus(*reviews[:2], digest, now=NOW)


@pytest.mark.parametrize('target', ['source', 'vetted'])
def test_tampered_review_or_consensus_rejected(reviews, target):
    source, vetted, digest = reviews
    path = source if target == 'source' else vetted
    path.write_bytes(path.read_bytes().replace(b'PHISHING', b'LEGITIMATE'))
    with pytest.raises(ValueError, match='digest mismatch|recomputed'):
        rc.approved_consensus(source, vetted, digest, now=NOW)


def test_piped_ids_do_not_substitute_for_original_reviews(reviews):
    source, vetted, _ = reviews
    source.write_bytes(vetted.read_bytes())
    with pytest.raises(ValueError, match='unsafe reviewer'):
        rc.approved_consensus(source, vetted, hashlib.sha256(source.read_bytes()).hexdigest(), now=NOW)


def test_single_reviewer_cannot_authorize_vetted_records(reviews):
    source, vetted, _ = reviews
    lines = source.read_text().splitlines(keepends=True)
    source.write_text(lines[0] + ''.join(line for line in lines[1:] if 'analyst-b' not in line))
    with pytest.raises(ValueError, match='recomputed'):
        rc.approved_consensus(source, vetted, hashlib.sha256(source.read_bytes()).hexdigest(), now=NOW)


def test_disputed_review_cannot_authorize_vetted_records(reviews):
    source, vetted, _ = reviews
    source.write_text(source.read_text().replace('PHISHING', 'LEGITIMATE', 1))
    with pytest.raises(ValueError, match='recomputed'):
        rc.approved_consensus(source, vetted, hashlib.sha256(source.read_bytes()).hexdigest(), now=NOW)


def test_private_path_rejects_checkout_and_symlink(tmp_path):
    with pytest.raises(ValueError, match='outside the repository'):
        private_path(ROOT / 'data' / 'new.csv')
    link = tmp_path / 'link'
    link.symlink_to(ROOT, target_is_directory=True)
    with pytest.raises(ValueError, match='outside the repository'):
        private_path(link / 'private.csv')


def test_private_path_rejects_another_checkout(tmp_path):
    checkout = tmp_path / 'other'
    checkout.mkdir()
    (checkout / '.git').write_text('gitdir: elsewhere')
    with pytest.raises(ValueError, match='outside Git'):
        private_path(checkout / 'reviews.csv')


def test_consensus_cli_rejects_private_output_in_checkout(reviews, monkeypatch, tmp_path):
    source, _, _ = reviews
    output = ROOT / 'data' / 'forbidden-private-review.csv'
    summary = tmp_path / 'summary.json'
    monkeypatch.setattr(sys, 'argv', ['consensus', '--reviews', str(source), '--out', str(output),
                                    '--summary', str(summary)])
    with pytest.raises(ValueError, match='outside the repository'):
        rc.main()
    assert not output.exists() and not summary.exists()


def test_consensus_cli_exports_canonical_bytes(reviews, monkeypatch, tmp_path):
    source, vetted, _ = reviews
    output, summary = tmp_path / 'agreed.csv', tmp_path / 'summary.json'
    monkeypatch.setattr(rc, 'evaluation_time', lambda now=None: NOW)
    monkeypatch.setattr(sys, 'argv', ['consensus', '--reviews', str(source), '--out', str(output),
                                    '--summary', str(summary)])
    rc.main()
    assert output.read_bytes() == vetted.read_bytes()
    assert 'https://' not in summary.read_text()
    with pytest.raises(SystemExit):
        rc.main()


def test_cli_rejects_unapproved_corpus_before_model_load(reviews, monkeypatch, tmp_path):
    source, vetted, _ = reviews
    output = tmp_path / 'report.json'
    monkeypatch.setattr(audit, 'evaluation_time', lambda now=None: NOW)
    monkeypatch.setattr(audit, 'load_verified_model', lambda *args: pytest.fail('Model must not load'))
    monkeypatch.setattr(sys, 'argv', ['evaluate', '--reviews', str(source), '--reviews-sha256', '0' * 64,
        '--vetted-csv', str(vetted), '--uci-csv', 'unused.csv', '--manifest', 'unused.json',
        '--manifest-sha256', '0' * 64, '--out', str(output)])
    with pytest.raises(ValueError, match='review digest mismatch'):
        audit.main()
    assert not output.exists()


def test_cli_requires_original_reviews_not_just_manifest(monkeypatch, tmp_path):
    output = tmp_path / 'report.json'
    monkeypatch.setattr(sys, 'argv', ['evaluate', '--vetted-csv', 'unused.csv', '--uci-csv', 'unused.csv',
        '--manifest', 'unused.json', '--manifest-sha256', '0' * 64, '--out', str(output)])
    with pytest.raises(SystemExit) as error:
        audit.main()
    assert error.value.code == 2 and not output.exists()


@pytest.mark.parametrize('reason', ['vetted_tamper', 'single_review', 'too_few', 'overwrite'])
def test_cli_rejects_invalid_corpus_before_scoring(reviews, monkeypatch, tmp_path, reason):
    source, vetted, digest = reviews
    output = tmp_path / 'report.json'
    minimum = '1'
    if reason == 'vetted_tamper':
        vetted.write_bytes(vetted.read_bytes() + b'\n')
    elif reason == 'single_review':
        lines = source.read_text().splitlines(keepends=True)
        source.write_text(lines[0] + ''.join(line for line in lines[1:] if 'analyst-b' not in line))
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
    elif reason == 'too_few':
        minimum = '100'
    else:
        output.write_text('preserve-existing-report')
    monkeypatch.setattr(audit, 'evaluation_time', lambda now=None: NOW)
    monkeypatch.setattr(audit, 'load_verified_model', lambda *args: pytest.fail('Model must not load'))
    import prospective_holdout
    monkeypatch.setattr(prospective_holdout, 'uci_groups', lambda path: set())
    monkeypatch.setattr(sys, 'argv', ['evaluate', '--reviews', str(source), '--reviews-sha256', digest,
        '--vetted-csv', str(vetted), '--uci-csv', 'unused.csv', '--manifest', 'unused.json',
        '--manifest-sha256', '0' * 64, '--min-per-class', minimum, '--out', str(output)])
    with pytest.raises((ValueError, SystemExit)):
        audit.main()
    assert not output.exists() if reason != 'overwrite' else output.read_text() == 'preserve-existing-report'

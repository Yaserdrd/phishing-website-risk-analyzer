"""Evaluate a frozen model on a separately reviewed, dated two-class URL corpus.

This utility never visits submitted URLs and exports aggregates only.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from phishing_analyzer.model import predict
from phishing_analyzer.provenance import evaluation_code_identity, load_verified_model
from phishing_analyzer.protocol import CUTOFF, evaluation_time, parse_time, valid_window
from phishing_analyzer.urls import domain_group, normalize_url
from phishing_analyzer.private_files import read_private
from review_consensus import approved_consensus

CLASSES = ('PHISHING', 'UNCERTAIN', 'LEGITIMATE')
REQUIRED = {'url', 'label', 'observed_at_utc', 'verified_at_utc', 'evidence_ref', 'reviewer_id'}


def load_vetted(path, excluded_domains, *, cutoff=CUTOFF, min_per_class=100, now=None):
    """Low-level schema check; the evaluation CLI additionally requires approved consensus."""
    return load_vetted_bytes(read_private(path), excluded_domains, cutoff=cutoff,
                             min_per_class=min_per_class, now=now)


def load_vetted_bytes(data, excluded_domains, *, cutoff=CUTOFF, min_per_class=100, now=None):
    """Reject missing evidence, untrusted labels, duplicates, and domain overlap.

    Never silently discard invalid evidence: a broken corpus is not a valid holdout.
    """
    if min_per_class < 1:
        raise ValueError('min_per_class must be positive')
    current = evaluation_time(now)
    if current < cutoff:
        raise ValueError('Prospective cutoff has not yet arrived')
    rows = []
    seen_urls = set()
    domain_labels = {}
    if len(data) > 20_000_000:
        raise ValueError('Vetted corpus too large')
    from io import StringIO
    reader = csv.DictReader(StringIO(data.decode('utf-8-sig')))
    if not REQUIRED.issubset(set(reader.fieldnames or [])):
        raise ValueError('Required evidence columns missing')
    for i, record in enumerate(reader, start=2):
        if None in record or any(record.get(key) is None for key in REQUIRED):
            raise ValueError(f'Row {i}: malformed evidence columns')
        label = record['label'].strip().upper()
        if label not in ('PHISHING', 'LEGITIMATE'):
            raise ValueError(f'Row {i}: unsupported label')
        if not record['evidence_ref'].strip() or not record['reviewer_id'].strip():
            raise ValueError(f'Row {i}: missing verification evidence')
        observed = parse_time(record['observed_at_utc'])
        verified = parse_time(record['verified_at_utc'])
        if not valid_window(observed, verified, current, cutoff):
            raise ValueError(f'Row {i}: timestamp violates prospective protocol')
        try:
            url = normalize_url(record['url'])
        except (ValueError, TypeError) as exc:
            raise ValueError(f'Row {i}: invalid URL') from exc
        group = domain_group(url)
        if group in excluded_domains:
            raise ValueError(f'Row {i}: UCI registrable-domain overlap')
        if url in seen_urls:
            raise ValueError(f'Row {i}: duplicate normalized URL')
        seen_urls.add(url)
        if group in domain_labels and domain_labels[group] != label:
            raise ValueError(f'Row {i}: contradictory labels on same registrable domain')
        domain_labels[group] = label
        rows.append((url, label))
    distribution = Counter(label for _, label in rows)
    if any(distribution[label] < min_per_class for label in ('PHISHING', 'LEGITIMATE')):
        raise ValueError('Insufficient reviewed samples per class; no metrics produced')
    return rows, {'sha256': hashlib.sha256(data).hexdigest(), 'rows': len(rows),
                  'domains': len(domain_labels), 'source_labels': dict(distribution)}


def evaluate(records, model, meta):
    confusion = {truth: {p: 0 for p in CLASSES} for truth in ('PHISHING', 'LEGITIMATE')}
    for url, truth in records:
        decision = predict(url, model, meta)['label']
        if decision not in CLASSES:
            raise ValueError('Unexpected model decision')
        confusion[truth][decision] += 1
    phishing_n = sum(confusion['PHISHING'].values())
    legitimate_n = sum(confusion['LEGITIMATE'].values())
    total = phishing_n + legitimate_n
    definite = total - sum(confusion[t]['UNCERTAIN'] for t in confusion)
    correct = confusion['PHISHING']['PHISHING'] + confusion['LEGITIMATE']['LEGITIMATE']
    return {
        'counts': confusion,
        'total': total,
        'coverage': definite / total,
        'accuracy_among_decided': correct / definite if definite else None,
        'phishing_detection_rate_all_phishing': confusion['PHISHING']['PHISHING'] / phishing_n,
        'phishing_false_clear_rate_all_phishing': confusion['PHISHING']['LEGITIMATE'] / phishing_n,
        'legitimate_false_alarm_rate_all_legitimate': confusion['LEGITIMATE']['PHISHING'] / legitimate_n,
        'uncertain_rate_all_samples': (total - definite) / total,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vetted-csv', required=True)
    parser.add_argument('--reviews', required=True, help='Private individual-review CSV used to build consensus')
    parser.add_argument('--reviews-sha256', required=True, help='Review digest approved independently before model scoring')
    parser.add_argument('--uci-csv', required=True)
    parser.add_argument('--model-dir', default='models')
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--manifest-sha256', required=True, help='Digest approved through a trusted build/review channel')
    parser.add_argument('--min-per-class', type=int, default=100)
    parser.add_argument('--out', default='reports/vetted_holdout.json')
    args = parser.parse_args()
    from prospective_holdout import uci_groups
    current = evaluation_time()
    if current < CUTOFF:
        parser.error('Prospective cutoff has not yet arrived')
    destination = Path(args.out).resolve()
    inputs = [args.vetted_csv, args.reviews, args.uci_csv, args.manifest,
              Path(args.model_dir) / 'url_phishing_model.pkl', Path(args.model_dir) / 'url_model_meta.json']
    if destination.exists() or destination in [Path(path).resolve() for path in inputs]:
        parser.error('Report must be new and must not overwrite an input')
    data, review_provenance = approved_consensus(
        args.reviews, args.vetted_csv, args.reviews_sha256, now=current)
    records, provenance = load_vetted_bytes(data, uci_groups(args.uci_csv), min_per_class=args.min_per_class, now=current)
    model, meta, identity = load_verified_model(args.model_dir, args.uci_csv, args.manifest, args.manifest_sha256)
    result = {
        'protocol': 'prospective-vetted-two-class-v2',
        'preregistered_cutoff_utc': CUTOFF.isoformat(),
        'model_version': meta['version'],
        'frozen_training_commit': identity['training_commit'],
        'model_provenance': identity,
        'evaluation_code': evaluation_code_identity(ROOT),
        'evaluated_at_utc': current.isoformat(),
        'corpus': provenance,
        'review_provenance': review_provenance,
        'metrics': evaluate(records, model, meta),
        'limitations': [
            'Labels require evidence-backed human review. Script validates metadata presence, NOT truth of reviewer claims.',
            'Reviewed labels may still be wrong; report reviewer methodology and adjudication separately.',
            'This file contains aggregate outputs only; raw potentially malicious URLs are not published.',
            'Never tune the frozen model on this final holdout.',
        ],
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

"""Snapshot-aware external URL audit. Never makes HTTP requests to URLs from feeds.

PhishTank entries are *reported* verified phishing; Tranco ranks are unlabeled.
The latter cannot be used to estimate specificity or a legitimate-site false-positive rate.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from phishing_analyzer.model import load_model, predict
from phishing_analyzer.urls import domain_group, normalize_url

MAX_FEED_BYTES = 100_000_000


def read_urls(path, kind, limit):
    """Read a bounded number of URLs from downloaded snapshots, never visiting them."""
    raw = Path(path).read_bytes()
    fingerprint = hashlib.sha256(raw).hexdigest()
    limit = int(limit)
    if limit <= 0:
        raise ValueError('Sample limit must be positive')
    if kind == 'phishing':
        if raw[:2] == b'\x1f\x8b':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as z:
                decoded = z.read(MAX_FEED_BYTES + 1)
            if len(decoded) > MAX_FEED_BYTES:
                raise ValueError('Decompressed phishing feed too large')
        else:
            if len(raw) > MAX_FEED_BYTES:
                raise ValueError('Phishing feed too large')
            decoded = raw
        reader = csv.DictReader(io.StringIO(decoded.decode('utf-8-sig')))
        if not {'url', 'verified', 'online'}.issubset(reader.fieldnames or []):
            raise ValueError('Expected verified, online, url PhishTank CSV fields')
        urls = []
        for row in reader:
            if (row.get('verified') or '').lower() == 'yes' and (row.get('online') or '').lower() == 'yes':
                urls.append(row['url'])
                if len(urls) >= limit * 5:
                    break
    elif kind == 'popular':
        urls = []
        with zipfile.ZipFile(path) as z:
            files = [x for x in z.infolist() if x.filename.endswith('.csv') and not x.is_dir()]
            if len(files) != 1 or files[0].file_size > 35_000_000:
                raise ValueError('Unexpected Tranco ZIP contents')
            with z.open(files[0]) as handle:
                for row in csv.reader(io.TextIOWrapper(handle, encoding='utf-8')):
                    if len(row) >= 2:
                        urls.append('https://' + row[1].strip() + '/')
                        if len(urls) >= limit * 5:
                            break
    else:
        raise ValueError('Unknown dataset kind')
    return urls, fingerprint


def normalize_or_none(url):
    try:
        return normalize_url(url)
    except (ValueError, TypeError):
        return None


def original_domains(path):
    with open(path, newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        column = next((x for x in (reader.fieldnames or []) if x.lower() == 'url'), None)
        if column is None:
            raise ValueError('UCI file requires URL column')
        return {domain_group(normalized) for row in reader if (normalized := normalize_or_none(row[column]))}


def filter_novel(urls, blocked, limit):
    """Select first novel entries and account only for actually examined rows."""
    counts = {'examined': 0, 'invalid': 0, 'duplicates': 0, 'overlap_with_uci_domains': 0}
    found, seen = [], set()
    for item in urls:
        counts['examined'] += 1
        normalized = normalize_or_none(item)
        if normalized is None:
            counts['invalid'] += 1
            continue
        if normalized in seen:
            counts['duplicates'] += 1
            continue
        seen.add(normalized)
        if domain_group(normalized) in blocked:
            counts['overlap_with_uci_domains'] += 1
            continue
        found.append(normalized)
        if len(found) >= limit:
            break
    counts['retained'] = len(found)
    counts['selection_method'] = 'first valid novel-domain entries in source order (not a random sample)'
    return found, counts


def _bucket(url):
    length = len(url)
    return 'short_le_50' if length <= 50 else ('medium_51_100' if length <= 100 else 'long_gt_100')


def audit_predictions(urls, model, meta):
    if not urls:
        raise ValueError('At least one URL required')
    labels = Counter()
    by_structure = {'root_only': Counter(), 'with_path_or_query': Counter()}
    by_length = {k: Counter() for k in ('short_le_50', 'medium_51_100', 'long_gt_100')}
    probs = []
    for url in urls:
        result = predict(url, model, meta)
        decision = result['label']
        labels[decision] += 1
        probs.append(result['probability'])
        parts = urlsplit(url)
        structure = 'root_only' if parts.path in ('', '/') and not parts.query else 'with_path_or_query'
        by_structure[structure][decision] += 1
        by_length[_bucket(url)][decision] += 1

    classes = ('PHISHING', 'UNCERTAIN', 'LEGITIMATE')
    def complete(counter):
        return {label: int(counter[label]) for label in classes}
    def breakdown(block):
        return {key: {'count': sum(ct.values()), 'decisions': complete(ct)} for key, ct in block.items()}
    scores = np.asarray(probs, dtype=float)
    return {
        'count': len(urls),
        'decisions': complete(labels),
        'fraction': {k: round(labels[k] / len(urls), 6) for k in classes},
        'diagnostics': {
            'url_structure': breakdown(by_structure),
            'url_length': breakdown(by_length),
            'model_phishing_score_quantiles': {
                str(percentile): round(float(np.quantile(scores, percentile / 100)), 6)
                for percentile in (0, 10, 25, 50, 75, 90, 100)
            },
        },
    }



def paired_root_diagnostic(urls, model, meta):
    """Paired URL-shape diagnostic; synthetic roots have no phishing/legitimate labels."""
    if not urls:
        raise ValueError('At least one URL required')
    full_scores, root_scores = [], []
    transitions = Counter()
    changed = 0
    for url in urls:
        parts = urlsplit(url)
        root = normalize_url(f'{parts.scheme}://{parts.netloc}/')
        before = predict(url, model, meta)
        after = predict(root, model, meta)
        full_scores.append(before['probability'])
        root_scores.append(after['probability'])
        transitions[f"{before['label']} -> {after['label']}"] += 1
        changed += int(root != url)
    diffs = np.asarray(root_scores) - np.asarray(full_scores)
    return {
        'count': len(urls),
        'urls_changed_by_root_transform': changed,
        'root_minus_full_score': {
            'mean': round(float(np.mean(diffs)), 6),
            'median': round(float(np.median(diffs)), 6),
            'fraction_increased': round(float(np.mean(diffs > 0)), 6),
            'fraction_decreased': round(float(np.mean(diffs < 0)), 6),
        },
        'decision_transitions': dict(sorted(transitions.items())),
        'warning': 'Synthetic root input-shape perturbation ONLY. Root URL has no inherited ground truth label.',
    }

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model-dir', default='models')
    parser.add_argument('--uci-csv', required=True)
    parser.add_argument('--phishing-csv', required=True)
    parser.add_argument('--popular-zip', required=True)
    parser.add_argument('--sample', type=int, default=2000)
    parser.add_argument('--out', default='reports/external_audit.json')
    args = parser.parse_args()
    if not 1 <= args.sample <= 10000:
        parser.error('sample must be 1..10000')
    model, meta = load_model(args.model_dir)
    if model is None:
        parser.error('No trusted trained model found')
    excluded_domains = original_domains(args.uci_csv)
    raw_p, hash_p = read_urls(args.phishing_csv, 'phishing', args.sample)
    raw_t, hash_t = read_urls(args.popular_zip, 'popular', args.sample)
    phish, p_count = filter_novel(raw_p, excluded_domains, args.sample)
    popular, t_count = filter_novel(raw_t, excluded_domains, args.sample)
    if not phish or not popular:
        parser.error('Novel-domain samples are empty')
    phish_result = audit_predictions(phish, model, meta)
    popular_result = audit_predictions(popular, model, meta)
    popular_alert = popular_result['fraction']['PHISHING']
    # This is a signal to investigate, NOT a false-positive metric or acceptance guarantee.
    result = {
        'audit_schema_version': 2,
        'snapshot_evaluated_at_utc': datetime.now(timezone.utc).isoformat(),
        'model_version': meta['version'],
        'source_fingerprints': {'phishtank_sha256': hash_p, 'tranco_sha256': hash_t},
        'selection': {'phishing': p_count, 'popular': t_count},
        'phishing_verified_online': phish_result,
        'popular_domains_unverified': popular_result,
        'paired_phishing_root_perturbation': paired_root_diagnostic(phish, model, meta),
        'research_warning': (
            'SEVERE_POPULAR_DOMAIN_ALERT_SKEW: Investigate domain-only input shift before any deployment.'
            if popular_alert > 0.5 else None
        ),
        'limitations': [
            'Tranco popularity is NOT legitimate ground truth; its alerts are NOT confirmed false positives.',
            'Popular-domain inputs are reconstructed HTTPS roots; phishing feed contains full URLs. Input-format shift may dominate.',
            'Selection is source-order first available after domain filtering, not an unbiased random sample.',
            'No training/threshold tuning can use these exploratory outputs as final untouched evaluation.',
            'No suspicious URL was visited. URLs are not exported to the report.',
            'Only registrable-domain overlap with the UCI corpus was excluded; campaign overlap and label errors remain possible.',
            'Feed snapshots change; SHA256 and UTC acquisition time are recorded.',
        ],
    }
    dest = Path(args.out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

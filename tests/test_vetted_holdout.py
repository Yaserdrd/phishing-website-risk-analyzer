"""Review provenance and evaluation math without touching live URLs."""
import sys
from datetime import datetime, timezone
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evaluate_vetted_holdout as audit

HEADER = 'url,label,observed_at_utc,verified_at_utc,evidence_ref,reviewer_id\n'
DATE = '2026-10-24T08:00:00Z,2026-10-24T09:00:00Z'
NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)

def write(tmp_path, rows):
    path = tmp_path / 'data.csv'
    path.write_text(HEADER + ''.join(rows), encoding='utf-8')
    return path

def sample():
    return [f'https://one.example,PHISHING,{DATE},review-1,analyst-a\n', f'https://two.example,LEGITIMATE,{DATE},review-2,analyst-b\n']

def test_valid_evidence_and_sha(tmp_path):
    rows, meta = audit.load_vetted(write(tmp_path, sample()), set(), min_per_class=1, now=NOW)
    assert len(rows) == 2 and meta['domains'] == 2 and len(meta['sha256']) == 64

def test_missing_evidence_rejected(tmp_path):
    bad = [sample()[0].replace('review-1', ''), sample()[1]]
    with pytest.raises(ValueError, match='evidence'):
        audit.load_vetted(write(tmp_path, bad), set(), min_per_class=1, now=NOW)

def test_pre_cutoff_rejected(tmp_path):
    bad = [sample()[0].replace('2026-10-24T08:00:00Z', '2026-10-22T08:00:00Z'), sample()[1]]
    with pytest.raises(ValueError, match='timestamp'):
        audit.load_vetted(write(tmp_path, bad), set(), min_per_class=1, now=NOW)

def test_domain_overlap_rejected(tmp_path):
    with pytest.raises(ValueError, match='overlap'):
        audit.load_vetted(write(tmp_path, sample()), {'one.example'}, min_per_class=1, now=NOW)

def test_minimum_per_class_fail_closed(tmp_path):
    with pytest.raises(ValueError, match='Insufficient'):
        audit.load_vetted(write(tmp_path, sample()), set(), min_per_class=2, now=NOW)

def test_duplicate_url_rejected(tmp_path):
    with pytest.raises(ValueError, match='duplicate'):
        audit.load_vetted(write(tmp_path, sample()+[sample()[0]]), set(), min_per_class=1, now=NOW)

def test_reject_mixed_labels_one_domain(tmp_path):
    rows=[f'https://one.example.co.uk,PHISHING,{DATE},review-1,analyst-a\n',f'https://sub.one.example.co.uk,LEGITIMATE,{DATE},review-2,analyst-b\n']
    with pytest.raises(ValueError, match='contradictory'):
        audit.load_vetted(write(tmp_path, rows), set(), min_per_class=1, now=NOW)

def test_metrics_have_correct_denominators(monkeypatch):
    def predict(url, model, meta):
        return {'label': 'UNCERTAIN' if 'two' in url else 'PHISHING'}
    monkeypatch.setattr(audit, 'predict', predict)
    m = audit.evaluate([('https://one.example/', 'PHISHING'), ('https://two.example/', 'LEGITIMATE')], None, {})
    assert m['coverage'] == .5
    assert m['accuracy_among_decided'] == 1.
    assert m['legitimate_false_alarm_rate_all_legitimate'] == 0.
    assert m['phishing_detection_rate_all_phishing'] == 1.

def test_naive_timestamp_rejected():
    with pytest.raises(ValueError, match='UTC'):
        audit.parse_time('2026-10-24T09:00:00')


@pytest.mark.parametrize('date', [
    '2026-10-24T10:00:00Z,2026-10-24T09:00:00Z',
    '2026-10-24T08:00:00Z,2099-01-01T00:00:00Z',
    '2026-10-24T08:00:00+03:00,2026-10-24T09:00:00Z',
])
def test_shared_temporal_rules_reject_invalid_review_windows(tmp_path, date):
    bad = [sample()[0].replace(DATE, date), sample()[1]]
    with pytest.raises(ValueError, match='timestamp|UTC'):
        audit.load_vetted(write(tmp_path, bad), set(), min_per_class=1, now=NOW)

"""Prospective holdout uses no remote URLs; fail closed on time/source contamination."""
import sys
from pathlib import Path
from datetime import datetime, timezone
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import prospective_holdout as holdout

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)

def _csv(tmp_path,text):
    p=tmp_path/"feed.csv"
    p.write_text("url,verified,online,submission_time,verification_time\n"+text,encoding="utf8")
    return p

def test_both_dates_must_be_new(tmp_path):
    path=_csv(tmp_path,
      "https://new.example.xyz,yes,yes,2026-10-23T08:00:00Z,2026-10-23T09:00:00Z\n"
      "https://old.example.xyz,yes,yes,2026-10-22T08:00:00Z,2026-10-23T09:00:00Z\n"
      "https://missing.example.xyz,yes,yes,2026-10-23T08:00:00Z,\n")
    urls,counts,_=holdout.select_phishing(path,set(),min_count=1,now=NOW)
    assert urls==["https://new.example.xyz/"]
    assert counts["predates_cutoff"]==1 and counts["missing_dates"]==1

def test_overlap_excluded_and_minimum_enforced(tmp_path):
    path=_csv(tmp_path,
      "https://a.example.co.uk,yes,yes,2026-10-24T08:00:00Z,2026-10-24T09:00:00Z\n"
      "https://newer.example.net,yes,yes,2026-10-24T08:00:00Z,2026-10-24T09:00:00Z\n")
    with pytest.raises(ValueError,match="Insufficient"):
        holdout.select_phishing(path,{"example.co.uk"},min_count=2,now=NOW)
    urls,counts,_=holdout.select_phishing(path,{"example.co.uk"},min_count=1,now=NOW)
    assert len(urls)==1 and counts["overlap_with_uci"]==1

def test_missing_timestamp_columns_rejected(tmp_path):
    p=tmp_path/"undated.csv";p.write_text("url,verified,online\nhttps://test.xyz,yes,yes\n")
    with pytest.raises(ValueError,match="Timestamp"):
        holdout.select_phishing(p,set(),min_count=1,now=NOW)

def test_timestamp_parser():
    assert holdout.date_utc("2026-10-23T00:00:00Z")==holdout.CUTOFF
    assert holdout.date_utc("bad") is None


@pytest.mark.parametrize('value', ['2026-10-24T09:00:00', '2026-10-24T09:00:00+03:00', None])
def test_non_utc_or_naive_dates_rejected(value):
    assert holdout.date_utc(value) is None


@pytest.mark.parametrize('submitted,verified', [
    ('2099-01-01T00:00:00Z', '2099-01-02T00:00:00Z'),
    ('2026-10-24T09:00:00Z', '2026-10-24T08:00:00Z'),
    ('2026-10-24T09:00:00Z', '2099-01-01T00:00:00Z'),
])
def test_invalid_order_and_future_rows_are_excluded(tmp_path, submitted, verified):
    path = _csv(tmp_path,
        f'https://invalid.test,yes,yes,{submitted},{verified}\n'
        'https://valid.test,yes,yes,2026-10-23T00:00:00Z,2026-10-26T00:00:00Z\n')
    urls, counts, _ = holdout.select_phishing(path, set(), min_count=1, now=NOW)
    assert urls == ['https://valid.test/']
    assert counts['invalid_time_order_or_future'] == 1


def test_temporal_filter_cannot_satisfy_minimum_with_invalid_records(tmp_path):
    path = _csv(tmp_path, 'https://future.test,yes,yes,2099-01-01T00:00:00Z,2099-01-02T00:00:00Z\n')
    with pytest.raises(ValueError, match='Insufficient'):
        holdout.select_phishing(path, set(), min_count=1, now=NOW)


def test_pre_cutoff_or_naive_evaluation_time_rejected(tmp_path):
    path = _csv(tmp_path, '')
    with pytest.raises(ValueError, match='cutoff'):
        holdout.select_phishing(path, set(), now=datetime(2026, 10, 22, tzinfo=timezone.utc))
    with pytest.raises(ValueError, match='UTC'):
        holdout.select_phishing(path, set(), now=datetime(2026, 10, 26))

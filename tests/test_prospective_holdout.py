"""Prospective holdout uses no remote URLs; fail closed on time/source contamination."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import prospective_holdout as holdout

def _csv(tmp_path,text):
    p=tmp_path/"feed.csv"
    p.write_text("url,verified,online,submission_time,verification_time\n"+text,encoding="utf8")
    return p

def test_both_dates_must_be_new(tmp_path):
    path=_csv(tmp_path,
      "https://new.example.xyz,yes,yes,2026-10-23T08:00:00Z,2026-10-23T09:00:00Z\n"
      "https://old.example.xyz,yes,yes,2026-10-22T08:00:00Z,2026-10-23T09:00:00Z\n"
      "https://missing.example.xyz,yes,yes,2026-10-23T08:00:00Z,\n")
    urls,counts,_=holdout.select_phishing(path,set(),min_count=1)
    assert urls==["https://new.example.xyz/"]
    assert counts["predates_cutoff"]==1 and counts["missing_dates"]==1

def test_overlap_excluded_and_minimum_enforced(tmp_path):
    path=_csv(tmp_path,
      "https://a.example.co.uk,yes,yes,2026-10-24T08:00:00Z,2026-10-24T09:00:00Z\n"
      "https://newer.example.net,yes,yes,2026-10-24T08:00:00Z,2026-10-24T09:00:00Z\n")
    with pytest.raises(ValueError,match="Insufficient"):
        holdout.select_phishing(path,{"example.co.uk"},min_count=2)
    urls,counts,_=holdout.select_phishing(path,{"example.co.uk"},min_count=1)
    assert len(urls)==1 and counts["overlap_with_uci"]==1

def test_missing_timestamp_columns_rejected(tmp_path):
    p=tmp_path/"undated.csv";p.write_text("url,verified,online\nhttps://test.xyz,yes,yes\n")
    with pytest.raises(ValueError,match="Timestamp"):
        holdout.select_phishing(p,set(),min_count=1)

def test_timestamp_parser():
    assert holdout.date_utc("2026-10-23T00:00:00Z")==holdout.CUTOFF
    assert holdout.date_utc("bad") is None

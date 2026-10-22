"""Deterministic tests for two-reviewer consensus; no URL visits."""
from datetime import datetime, timezone
from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import review_consensus as rc

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
HEAD = "url,label,observed_at_utc,verified_at_utc,evidence_ref,reviewer_id\n"
DATES = "2026-10-24T08:00:00Z,2026-10-24T09:00:00Z"


def row(url, label, reviewer, evidence):
    return f"{url},{label},{DATES},{evidence},{reviewer}\n"


def data(tmp_path, *rows):
    p = tmp_path / "reviews.csv"
    p.write_text(HEAD + "".join(rows), encoding="utf-8")
    return p


def test_agreement_exports_one_row_with_both_evidences(tmp_path):
    p = data(tmp_path, row("https://one.example/login", "PHISHING", "a", "r1"),
             row("https://one.example/login", "PHISHING", "b", "r2"))
    result, summary = rc.adjudicate(p, now=NOW)
    assert len(result) == 1
    assert result[0]["evidence_ref"] == "r1|r2"
    assert summary["counts"]["accepted_phishing"] == 1


def test_disagreement_cannot_become_ground_truth(tmp_path):
    p = data(tmp_path, row("https://one.example/login", "PHISHING", "a", "r1"),
             row("https://one.example/login", "LEGITIMATE", "b", "r2"))
    result, summary = rc.adjudicate(p, now=NOW)
    assert result == []
    assert summary["counts"]["disputed"] == 1


def test_one_review_insufficient(tmp_path):
    result, summary = rc.adjudicate(
        data(tmp_path, row("https://one.example/", "LEGITIMATE", "a", "r1")), now=NOW)
    assert result == []
    assert summary["counts"]["needs_second_review"] == 1


def test_same_reviewer_cannot_review_twice(tmp_path):
    p = data(tmp_path, row("https://one.example/", "LEGITIMATE", "a", "r1"),
             row("https://one.example/", "LEGITIMATE", "a", "r2"))
    with pytest.raises(ValueError, match="duplicate reviewer"):
        rc.adjudicate(p, now=NOW)


def test_pre_cutoff_rejected(tmp_path):
    p = data(tmp_path, row("https://one.example/", "LEGITIMATE", "a", "r1")
             .replace("2026-10-24T08:00:00Z", "2026-10-22T08:00:00Z"))
    with pytest.raises(ValueError, match="timestamps"):
        rc.adjudicate(p, now=NOW)


def test_cross_url_domain_conflict_excluded(tmp_path):
    p = data(tmp_path,
             row("https://site.example.co.uk/a", "PHISHING", "a", "r1"),
             row("https://site.example.co.uk/a", "PHISHING", "b", "r2"),
             row("https://other.example.co.uk/b", "LEGITIMATE", "a", "r3"),
             row("https://other.example.co.uk/b", "LEGITIMATE", "b", "r4"))
    result, summary = rc.adjudicate(p, now=NOW)
    assert result == []
    assert summary["counts"]["domain_conflict_excluded"] == 2


def test_missing_provenance_columns_rejected(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("url,label\nhttps://foo.example,PHISHING\n")
    with pytest.raises(ValueError, match="columns"):
        rc.adjudicate(p, now=NOW)


def test_no_future_dates(tmp_path):
    p = data(tmp_path, row("https://one.example/", "LEGITIMATE", "a", "r1")
             .replace("2026-10-24T09:00:00Z", "2027-10-24T09:00:00Z"))
    with pytest.raises(ValueError, match="timestamps"):
        rc.adjudicate(p, now=NOW)

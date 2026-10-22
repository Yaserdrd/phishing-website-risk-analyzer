"""No requests to suspicious URLs. Focus on aggregates and guardrails."""
import sys
import zipfile
from pathlib import Path

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import evaluate_external as external


def test_novel_counts_are_actually_examined():
    urls = [
        'https://login.example.co.uk/',
        'https://shop.elsewhere.org',
        'https://shop.elsewhere.org',
        'javascript:alert(1)',
        'https://unused.other.org',
    ]
    result, counts = external.filter_novel(urls, {'example.co.uk'}, 1)
    assert result == ['https://shop.elsewhere.org/']
    assert counts['examined'] == 2
    assert counts['overlap_with_uci_domains'] == 1
    assert counts['duplicates'] == 0


def test_filter_deduplicates_and_discards_invalid():
    urls = ['https://shop.elsewhere.org/', 'https://shop.elsewhere.org', 'file:///x', 'https://other.net/path']
    selected, counts = external.filter_novel(urls, set(), 2)
    assert len(selected) == 2
    assert counts['examined'] == 4
    assert counts['invalid'] == 1
    assert counts['duplicates'] == 1


def test_phishtank_only_verified_online(tmp_path):
    path = tmp_path / 'feed.csv'
    path.write_text('url,verified,online\nhttps://a.example,yes,yes\nhttps://b.example,no,yes\nhttps://c.example,yes,no\n')
    urls, digest = external.read_urls(path, 'phishing', 20)
    assert urls == ['https://a.example'] and len(digest) == 64


def test_tranco_root_urls_and_zip_guard(tmp_path):
    path = tmp_path / 'tranco.zip'
    with zipfile.ZipFile(path, 'w') as z:
        z.writestr('top-1m.csv', '1,example.com\n2,github.com\n')
    urls, digest = external.read_urls(path, 'popular', 20)
    assert urls == ['https://example.com/', 'https://github.com/']
    assert len(digest) == 64
    with zipfile.ZipFile(path, 'a') as z:
        z.writestr('extra.csv', '1,evil.example\n')
    with pytest.raises(ValueError, match='Unexpected Tranco ZIP'):
        external.read_urls(path, 'popular', 2)


def test_diagnostics_split_root_and_full_url(monkeypatch):
    def fake_predict(url, model, meta):
        if '/login' in url:
            return {'label': 'PHISHING', 'probability': .94}
        return {'label': 'LEGITIMATE', 'probability': .02}
    monkeypatch.setattr(external, 'predict', fake_predict)
    result = external.audit_predictions(['https://example.com/', 'https://other.org/login'], object(), {})
    assert result['count'] == 2
    assert result['diagnostics']['url_structure']['root_only']['count'] == 1
    assert result['diagnostics']['url_structure']['with_path_or_query']['decisions']['PHISHING'] == 1
    assert result['diagnostics']['model_phishing_score_quantiles']['50'] == .48
    assert sum(result['decisions'].values()) == 2


def test_no_empty_diagnostics():
    with pytest.raises(ValueError, match='At least one'):
        external.audit_predictions([], object(), {})

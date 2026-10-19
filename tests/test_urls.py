import pytest
from phishing_analyzer.urls import normalize_url, host_group


def test_normalizes_plain_url_and_host():
    assert normalize_url(' Example.COM/login?x=1 ') == 'https://example.com/login?x=1'
    assert host_group('https://www.Example.com/login') == 'example.com'


def test_preserves_path_case_and_strips_fragment():
    assert normalize_url('HTTP://Example.com/Login#secret') == 'http://example.com/Login'


@pytest.mark.parametrize('url', [
    '', 'javascript:alert(1)', 'ftp://example.com', 'http://user:pass@example.com',
    'https://example.com:8080/', 'https://example.com:80/', 'http://localhost\r\nHost:evil.com/',
    'https://bad..example/', 'https://evil.-example/',
])
def test_rejects_invalid(url):
    with pytest.raises(ValueError):
        normalize_url(url)


def test_long_url_rejected():
    with pytest.raises(ValueError):
        normalize_url('https://example.org/' + 'a' * 2050)

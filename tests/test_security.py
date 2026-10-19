import socket
import pytest
from phishing_analyzer.security import passive_check, public_ips, html_check, read_html


def test_passive_url_signals():
    score, reasons = passive_check('http://192.0.2.10/login')
    assert score > 0
    assert any('HTTPS' in r for r in reasons)


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '192.168.1.10', '169.254.169.254',
                                '::1', 'fc00::1', '0.0.0.0', '192.0.2.5'])
def test_public_ips_blocks_reserved_ranges(monkeypatch, ip):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(None, None, None, None, (ip, 443))])
    with pytest.raises(ValueError, match='Private/reserved'):
        public_ips('localhost', 443)


def test_public_ips_can_return_public_address(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(None, None, None, None, ('8.8.8.8', 443))])
    assert public_ips('example.org', 443) == ['8.8.8.8']


def test_html_form_cross_host_and_password():
    code = '<form action="https://elsewhere.example/submit"><input type="password"></form><iframe></iframe>'
    score, findings, summary = html_check(code, 'https://example.org/login')
    assert score >= 11
    assert summary['forms'] == 1
    assert summary['password_fields'] == 1
    assert len(findings) > 0


def test_html_active_fetch_blocks_private_host(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(None, None, None, None, ('127.0.0.1', 443))])
    with pytest.raises(ValueError, match='blocked'):
        read_html('https://some.example/')

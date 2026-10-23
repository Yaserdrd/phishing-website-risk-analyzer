from phishing_analyzer.analyzer import analyze
import http.client
import pytest


def test_heuristic_only_mode_without_model():
    result = analyze('https://example.org')
    assert result['ml'] is None
    assert result['active'] is False
    assert result['risk_score'] >= 0
    assert 'not a probability' in result['disclaimer']


def test_active_checks_are_not_called_by_default(monkeypatch):
    import phishing_analyzer.analyzer as module
    def unexpected(*args):
        raise AssertionError('Network access must be opt-in')
    monkeypatch.setattr(module, 'read_html', unexpected)
    monkeypatch.setattr(module, 'rdap_check', unexpected)
    monkeypatch.setattr(module, 'tls_check', unexpected)
    assert module.analyze('example.com')['risk_level'] == 'LOW'


@pytest.mark.parametrize('error', [TimeoutError('deadline'), http.client.BadStatusLine('bad response')])
def test_active_network_failures_do_not_add_risk_and_share_budget(monkeypatch, error):
    import phishing_analyzer.analyzer as module
    budgets = []
    def tls(url, *, deadline):
        budgets.append(deadline)
        return {'status': 'unavailable_or_unverified', 'valid': False, 'days_to_expiry': None}
    def rdap(url, *, deadline):
        budgets.append(deadline)
        return 0, ['RDAP unavailable; no risk assigned'], {'age_days': None}
    def html(url, *, deadline):
        budgets.append(deadline)
        raise error
    monkeypatch.setattr(module, 'tls_check', tls)
    monkeypatch.setattr(module, 'rdap_check', rdap)
    monkeypatch.setattr(module, 'read_html', html)
    result = module.analyze('https://example.org/', active=True)
    assert result['risk_score'] == module.analyze('https://example.org/')['risk_score']
    assert result['score_parts']['tls'] == 0
    assert result['checks']['html']['status'] == 'unavailable'
    assert len(budgets) == 3 and all(b is budgets[0] for b in budgets)

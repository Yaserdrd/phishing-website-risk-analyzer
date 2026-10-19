from phishing_analyzer.analyzer import analyze


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

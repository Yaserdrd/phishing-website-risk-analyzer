import pandas as pd
import pytest
from phishing_analyzer.model import load_csv, load_model, train, predict


def sample_frame(n=100):
    # Clearly SYNTHETIC data for pipeline smoke tests — NOT a performance benchmark.
    rows = []
    for index in range(n):
        phishing = index % 2 == 0
        host = f"{'verify-account' if phishing else 'shop'}{index}.example.org"
        rows.append((f"https://{host}/{'login-check' if phishing else 'catalog'}", 0 if phishing else 1))
    return pd.DataFrame(rows, columns=['URL', 'label'])


def test_csv_requires_labels(tmp_path):
    file = tmp_path / 'bad.csv'
    pd.DataFrame({'URL':['https://example.org'],'label':[3]}).to_csv(file, index=False)
    with pytest.raises(ValueError):
        load_csv(file)


def test_csv_rejects_conflicting_url_labels(tmp_path):
    file = tmp_path / 'conflict.csv'
    pd.DataFrame({'URL':['https://example.org','https://example.org'],'label':[0,1]}).to_csv(file,index=False)
    with pytest.raises(ValueError, match='contradictory'):
        load_csv(file)


def test_train_and_load_smoke(tmp_path):
    file = tmp_path / 'synthetic.csv'
    sample_frame().to_csv(file,index=False)
    frame = load_csv(file)
    meta = train(frame, tmp_path/'models', url_features=500, host_features=300)
    model, loaded = load_model(tmp_path/'models')
    assert model is not None
    assert meta['phishing_threshold'] <= 0.95
    assert 0 < meta['legitimate_threshold'] < meta['phishing_threshold']
    assert set(loaded['metrics']) >= {'accuracy','precision_phishing','test_rows'}
    result = predict('https://example.net', model, loaded)
    assert result['label'] in {'PHISHING','LEGITIMATE','UNCERTAIN'}
    assert 0 <= result['probability'] <= 1

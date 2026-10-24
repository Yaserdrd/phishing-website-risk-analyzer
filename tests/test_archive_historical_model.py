"""Archive identity and token boundaries; all remote operations are mocked."""
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import archive_historical_model as archive


@pytest.fixture
def raw(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr('url_model_meta.json', json.dumps({'version': '2.1.0'}))
        z.writestr('url_phishing_model.pkl', b'never-execute-this-fixture')
    data = buffer.getvalue()
    monkeypatch.setattr(archive, 'DIGEST', hashlib.sha256(data).hexdigest())
    return data


def test_archive_check_records_hashes_not_serving_approval(raw):
    result = archive.inspect_archive(raw, {'version': '2.1.0'})
    assert result['deserialized'] is False and result['approval_manifest_present'] is False
    assert result['members']['url_phishing_model.pkl']['bytes'] == 26
    assert result['metadata_matches_committed_report'] is True


def test_modified_zip_rejected_before_inspection(raw):
    with pytest.raises(ValueError, match='digest'):
        archive.inspect_archive(raw + b'changed', {'version': '2.1.0'})


def test_metadata_must_equal_historical_report(raw):
    with pytest.raises(ValueError, match='metadata'):
        archive.inspect_archive(raw, {'version': 'different'})


def test_duplicate_archive_members_rejected(monkeypatch):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr('url_model_meta.json', '{}')
        z.writestr('url_phishing_model.pkl', b'x')
        z.writestr('unexpected.txt', b'x')
    raw = buffer.getvalue()
    monkeypatch.setattr(archive, 'DIGEST', hashlib.sha256(raw).hexdigest())
    with pytest.raises(ValueError, match='members'):
        archive.inspect_archive(raw, {})


def test_redirect_strips_token_from_artifact_storage():
    req = urllib.request.Request('https://api.github.com/archive', headers={'Authorization': 'Bearer sentinel'})
    redirected = archive.SafeRedirect().redirect_request(req, None, 302, 'Found', {},
                                                        'https://storage.example/archive')
    assert not redirected.has_header('Authorization')
    with pytest.raises(ValueError, match='HTTPS'):
        archive.SafeRedirect().redirect_request(req, None, 302, 'Found', {}, 'http://storage.example/archive')


@pytest.mark.parametrize('url', ['http://uploads.github.com/x', 'https://evil.example/x',
                               'https://uploads.github.com:444/x', 'https://user@api.github.com/x'])
def test_credentials_never_sent_to_unapproved_origins(url):
    with pytest.raises(ValueError, match='Credentials'):
        archive.request(url, 'sentinel')


@pytest.mark.parametrize('condition', ['good', 'expired', 'source', 'published', 'wrong_asset', 'readback'])
def test_preserve_draft_and_fail_closed(raw, monkeypatch, condition):
    assets, uploads, stored = [], [], {}
    release = {'id': 1, 'draft': condition != 'published', 'tag_name': archive.TAG,
               'upload_url': 'https://uploads.github.com/assets{?name}', 'assets': assets}
    if condition == 'wrong_asset':
        assets.append({'name': 'uci-v21-original.zip', 'digest': 'sha256:wrong', 'size': 0})
    def request(url, token, *, data=None, media=None, accept=None):
        assert token == 'sentinel'
        if url.endswith(f'/actions/artifacts/{archive.ARTIFACT}'):
            return json.dumps({'expired': condition == 'expired', 'digest': 'sha256:' + archive.DIGEST,
                'workflow_run': {'id': archive.RUN, 'head_sha': 'wrong' if condition == 'source' else archive.COMMIT}}).encode()
        if url.endswith('/zip'): return raw
        if '/releases?per_page=' in url: return json.dumps([release]).encode()
        if url.startswith('https://uploads.github.com'):
            uploads.append(url)
            asset = {'name': url.split('?name=')[1], 'size': len(data),
                     'digest': 'sha256:' + hashlib.sha256(data).hexdigest(), 'id': len(assets) + 1}
            assets.append(asset)
            stored[asset['id']] = data
            return json.dumps(asset).encode()
        if url.endswith('/releases/1'): return json.dumps(release).encode()
        if '/releases/assets/' in url:
            assert accept == 'application/octet-stream'
            return b'corrupt readback' if condition == 'readback' else stored[int(url.rsplit('/', 1)[1])]
        pytest.fail('Unexpected URL')
    monkeypatch.setattr(archive, 'request', request)
    if condition == 'good':
        result = archive.preserve('sentinel', {'version': '2.1.0'})
        assert len(uploads) == 2 and result['draft'] and not result['serving_approved']
        archive.preserve('sentinel', {'version': '2.1.0'})
        assert len(uploads) == 2  # exact matching assets are retained without replacement
    else:
        with pytest.raises(ValueError): archive.preserve('sentinel', {'version': '2.1.0'})
        assert len(uploads) == 2 if condition == 'readback' else not uploads

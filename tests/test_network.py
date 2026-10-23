"""Adversarial transport tests with fake DNS, sockets and monotonic time only."""
import http.client
import socket
import ssl
import threading

import pytest

from phishing_analyzer import network as net
from phishing_analyzer import security


class WireSocket:
    def __init__(self, wire=b'', *, clock=None, step=0, chunk=8192, slow_after=0):
        self.wire = bytearray(wire)
        self.clock, self.step, self.chunk = clock, step, chunk
        self.slow_after = slow_after
        self.closed = False
        self.sent = b''
        self.timeouts = []
        self.connected = None

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, endpoint):
        self.connected = endpoint

    def sendall(self, value):
        self.sent += value

    def recv_into(self, target):
        if self.clock is not None and self.slow_after <= 0:
            self.clock[0] += self.step
        count = min(len(target), len(self.wire), self.slow_after if self.slow_after > 0 else self.chunk)
        self.slow_after -= count
        target[:count] = self.wire[:count]
        del self.wire[:count]
        return count

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('Unexpected real network operation')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)


def wire(body=b'OK', *, status='200 OK', content_type='text/html', headers=()):
    items = [f'Content-Type: {content_type}', *headers]
    return (f'HTTP/1.1 {status}\r\n' + '\r\n'.join(items) + '\r\n\r\n').encode() + body


def transport(monkeypatch, *wires, clock=None, step=0, chunk=8192, slow_after=0):
    sockets = [WireSocket(w, clock=clock, step=step, chunk=chunk, slow_after=slow_after) for w in wires]
    contacted = []
    def connect(url, **kwargs):
        contacted.append((url, kwargs['deadline']))
        return sockets[len(contacted) - 1]
    monkeypatch.setattr(net, 'connect_pinned', connect)
    return sockets, contacted


def fetch(url='https://example.org/', **kwargs):
    return net.fetch(url, max_bytes=kwargs.pop('max_bytes', 100),
                     content_types=('text/html',), max_redirects=kwargs.pop('max_redirects', 3), **kwargs)


def test_successful_fetch_preserves_path_host_and_closes(monkeypatch):
    socks, contacted = transport(monkeypatch, wire(b'<p>ok</p>', headers=['Content-Length: 9']))
    assert fetch('https://example.org/path?x=1') == (b'<p>ok</p>', 'https://example.org/path?x=1', 0)
    assert b'GET /path?x=1 HTTP/1.1\r\nHost: example.org\r\n' in socks[0].sent
    assert b'Accept-Encoding: identity' in socks[0].sent
    assert socks[0].closed


def test_relative_redirect_reuses_deadline_and_closes_each_hop(monkeypatch):
    socks, contacted = transport(monkeypatch, wire(status='302 Found', headers=['Location: /next']), wire())
    deadline = net.Deadline()
    assert fetch(deadline=deadline)[1:] == ('https://example.org/next', 1)
    assert all(sock.closed for sock in socks)
    assert [d for _, d in contacted] == [deadline, deadline]


@pytest.mark.parametrize('location', ['http://other.example/', 'file:///tmp/x',
    'https://user:pass@other.example/', 'https://other.example:8443/'])
def test_unsafe_redirect_never_contacts_second_target(monkeypatch, location):
    socks, contacted = transport(monkeypatch, wire(status='302 Found', headers=[f'Location: {location}']))
    with pytest.raises(ValueError):
        fetch()
    assert len(contacted) == 1
    assert socks[0].closed


def test_html_redirect_to_private_ip_is_blocked_before_connect(monkeypatch):
    first = WireSocket(wire(status='302 Found', headers=['Location: https://private.example/']))
    connected = []
    monkeypatch.setattr(socket, 'getaddrinfo', lambda host, *a, **kw: [
        (None, None, None, None, ('8.8.8.8' if host == 'example.org' else '127.0.0.1', 443))])
    def create(*args):
        connected.append(args)
        return first
    monkeypatch.setattr(socket, 'socket', create)
    class Context:
        def wrap_socket(self, sock, **kwargs): return sock
    monkeypatch.setattr(net.ssl, 'create_default_context', Context)
    with pytest.raises(ValueError, match='blocked'):
        security.read_html('https://example.org/')
    assert len(connected) == 1
    assert first.connected == ('8.8.8.8', 443)
    assert first.closed


def test_redirect_limit_stops_before_extra_target(monkeypatch):
    socks, contacted = transport(monkeypatch, *[
        wire(status='302 Found', headers=['Location: /again']) for _ in range(4)])
    with pytest.raises(ValueError, match='Redirect policy'):
        fetch()
    assert len(contacted) == 4
    assert all(sock.closed for sock in socks)


@pytest.mark.parametrize('response', [
    wire(status='302 Found'),
    wire(status='404 Not Found'),
    wire(content_type='text/plain'),
    wire(headers=['Content-Encoding: gzip']),
    wire(headers=['Content-Length: 101']),
    wire(headers=['Content-Length: -1']),
    wire(headers=['Content-Length: 10']),
    wire(headers=['Content-Length: 2', 'Transfer-Encoding: chunked']),
    wire(headers=['Transfer-Encoding: gzip']),
    b'not-an-http-response\r\n\r\n',
])
def test_bad_responses_fail_closed_and_close_socket(monkeypatch, response):
    socks, _ = transport(monkeypatch, response)
    with pytest.raises((ValueError, http.client.HTTPException)):
        fetch()
    assert socks[0].closed


def test_unannounced_oversized_body_rejected(monkeypatch):
    socks, _ = transport(monkeypatch, wire(b'x' * 101))
    with pytest.raises(ValueError, match='size limit'):
        fetch()
    assert socks[0].closed


def test_chunked_body_decodes_within_budget(monkeypatch):
    transport(monkeypatch, wire(b'2\r\nOK\r\n0\r\n\r\n', headers=['Transfer-Encoding: chunked']))
    assert fetch()[0] == b'OK'


def test_chunk_framing_cannot_bypass_wire_budget(monkeypatch):
    monkeypatch.setattr(net, 'MAX_WIRE_OVERHEAD', 100)
    socks, _ = transport(monkeypatch, wire(b'1;pad=' + b'x' * 200 + b'\r\nx\r\n0\r\n\r\n',
                                        headers=['Transfer-Encoding: chunked']))
    with pytest.raises(ValueError, match='wire size'):
        fetch()
    assert socks[0].closed


@pytest.mark.parametrize('stage', ['headers', 'body', 'chunk_framing'])
def test_slow_headers_body_or_chunk_framing_cannot_reset_deadline(monkeypatch, stage):
    prefix = (b'HTTP/1.1 200 OK\r\nX-Slow: ' if stage == 'headers' else
              wire(b'x' * 30) if stage == 'body' else
              wire(b'1\r\nx\r\n' * 30, headers=['Transfer-Encoding: chunked']))
    header_length = 0 if stage == 'headers' else prefix.index(b'\r\n\r\n') + 4
    clock = [0.0]
    monkeypatch.setattr(net.time, 'monotonic', lambda: clock[0])
    socks, _ = transport(monkeypatch, prefix, clock=clock, step=1, chunk=1, slow_after=header_length)
    with pytest.raises(TimeoutError, match='deadline'):
        fetch(deadline=net.Deadline(3))
    assert clock[0] == 3
    assert socks[0].closed


def test_pin_uses_validated_ip_and_tls_hostname(monkeypatch):
    sock = WireSocket()
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
        (None, None, None, None, ('8.8.8.8', 443))])
    monkeypatch.setattr(socket, 'socket', lambda *a: sock)
    names = []
    class Context:
        def wrap_socket(self, s, *, server_hostname):
            names.append(server_hostname)
            return s
    monkeypatch.setattr(net.ssl, 'create_default_context', Context)
    assert net.connect_pinned('https://example.org/') is sock
    assert sock.connected == ('8.8.8.8', 443)
    assert names == ['example.org']


def test_certificate_failure_closes_socket_without_disabling_verification(monkeypatch):
    sock = WireSocket()
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
        (None, None, None, None, ('8.8.8.8', 443))])
    monkeypatch.setattr(socket, 'socket', lambda *a: sock)
    class Context:
        def wrap_socket(self, *args, **kwargs):
            raise ssl.SSLCertVerificationError('test failure')
    monkeypatch.setattr(net.ssl, 'create_default_context', Context)
    with pytest.raises(ssl.SSLCertVerificationError):
        net.connect_pinned('https://example.org/')
    assert sock.closed


@pytest.mark.parametrize('ip', ['224.0.0.1', 'ff02::1', '::ffff:127.0.0.1',
    '2002:7f00:1::', '64:ff9b::7f00:1'])
def test_non_unicast_or_transition_addresses_are_blocked(monkeypatch, ip):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [(None, None, None, None, (ip, 443))])
    with pytest.raises(ValueError, match='blocked'):
        net.public_ips('example.org', 443)


def test_mixed_dns_answer_blocks_all_connections(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
        (None, None, None, None, (ip, 443)) for ip in ['8.8.8.8', '10.0.0.1']])
    with pytest.raises(ValueError, match='blocked'):
        net.connect_pinned('https://example.org/')


def test_dns_wait_is_bounded_and_lingering_workers_are_capped(monkeypatch):
    release = threading.Event()
    started = threading.Event()
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(net, '_DNS_SLOTS', slots)
    def stalled(*args, **kwargs):
        started.set()
        release.wait(2)
        return []
    monkeypatch.setattr(socket, 'getaddrinfo', stalled)
    try:
        with pytest.raises(TimeoutError, match='DNS resolution deadline'):
            net.public_ips('example.org', 443, deadline=net.Deadline(.1))
        assert started.is_set()
        with pytest.raises(ValueError, match='capacity'):
            net.public_ips('example.org', 443)
    finally:
        release.set()
        assert slots.acquire(timeout=1)
        slots.release()


def test_rdap_redirect_is_never_followed(monkeypatch):
    socks, contacted = transport(monkeypatch,
        wire(status='302 Found', content_type='application/json', headers=['Location: https://127.0.0.1/']))
    score, findings, details = security.rdap_check('https://example.org/')
    assert score == 0 and details['age_days'] is None
    assert len(contacted) == 1
    assert contacted[0][0] == 'https://rdap.org/domain/example.org'
    assert socks[0].closed


@pytest.mark.parametrize('body', [b'[]', b'{"events": {}}', b'invalid json',
    b'{"events":[{"eventAction":"registration","eventDate":"2099-01-01T00:00:00Z"}]}',
    b'{"events":[{"eventAction":"registration","eventDate":"2026-01-01T00:00:00"}]}'])
def test_invalid_rdap_payload_is_missing_evidence(monkeypatch, body):
    transport(monkeypatch, wire(body, content_type='application/rdap+json'))
    assert security.rdap_check('https://example.org/')[0] == 0


def test_valid_rdap_payload_is_parsed_without_following_input_url(monkeypatch):
    transport(monkeypatch, wire(b'{"events":[{"eventAction":"registration",'
        b'"eventDate":"2000-01-01T00:00:00Z"}]}', content_type='application/rdap+json'))
    score, _, details = security.rdap_check('https://example.org/login')
    assert score == 0 and details['age_days'] > 180


def test_rdap_body_limit_failure_is_missing_evidence(monkeypatch):
    socks, _ = transport(monkeypatch, wire(content_type='application/rdap+json',
                                         headers=[f'Content-Length: {security.MAX_RDAP_BYTES + 1}']))
    assert security.rdap_check('https://example.org/')[0] == 0
    assert socks[0].closed


def test_expired_shared_budget_prevents_later_network_checks():
    expired = net.Deadline(0)
    assert security.tls_check('https://example.org/', deadline=expired)['status'] == 'unavailable_or_unverified'
    assert security.rdap_check('https://example.org/', deadline=expired)[0] == 0
    with pytest.raises(TimeoutError):
        security.read_html('https://example.org/', deadline=expired)


@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_connection_time_counts_against_shared_deadline_and_closes(monkeypatch, scheme):
    clock = [0.0]
    monkeypatch.setattr(net.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **kw: [
        (None, None, None, None, ('8.8.8.8', 443))])
    sock = WireSocket()
    def slow_connect(endpoint):
        clock[0] += 5
    sock.connect = slow_connect
    monkeypatch.setattr(socket, 'socket', lambda *a: sock)
    with pytest.raises(TimeoutError, match='deadline'):
        net.connect_pinned(f'{scheme}://example.org/', deadline=net.Deadline(3))
    assert sock.closed


def test_request_target_encodes_spaces_and_unicode(monkeypatch):
    socks, _ = transport(monkeypatch, wire())
    fetch('https://example.org/café?q=a b')
    assert b'GET /caf%C3%A9?q=a%20b HTTP/1.1' in socks[0].sent

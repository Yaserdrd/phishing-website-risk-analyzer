"""Bounded opt-in HTTP transport with public-IP pinning and shared deadlines."""
from concurrent.futures import Future, TimeoutError as FutureTimeout
import http.client
import io
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import quote, urljoin, urlsplit

from .urls import normalize_url

SOCKET_TIMEOUT = 4
INSPECTION_SECONDS = 12
MAX_WIRE_OVERHEAD = 64_000
_DNS_SLOTS = threading.BoundedSemaphore(4)


class Deadline:
    def __init__(self, seconds=INSPECTION_SECONDS):
        self.end = time.monotonic() + seconds

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Live inspection deadline exceeded")
        return remaining


def public_ips(host, port, *, deadline=None):
    """Bound caller DNS wait and reject the entire mixed public/private answer."""
    deadline = deadline if deadline is not None else Deadline()
    deadline.remaining()
    if not _DNS_SLOTS.acquire(blocking=False):
        raise ValueError("DNS resolver capacity exhausted")
    result = Future()

    def resolve():
        try:
            result.set_result(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except Exception as exc:
            result.set_exception(exc)
        finally:
            _DNS_SLOTS.release()

    try:
        threading.Thread(target=resolve, daemon=True).start()
    except BaseException:
        _DNS_SLOTS.release()
        raise
    try:
        answers = result.result(timeout=deadline.remaining())
    except FutureTimeout as exc:
        raise TimeoutError("DNS resolution deadline exceeded") from exc
    except (OSError, ValueError) as exc:
        raise ValueError("DNS resolution unavailable") from exc
    deadline.remaining()
    addresses = sorted({item[4][0] for item in answers})
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                or (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo))
                or ip in ipaddress.ip_network("64:ff9b::/96")
                or ip in ipaddress.ip_network("64:ff9b:1::/48")):
            raise ValueError("Private/reserved IP or non-public-unicast DNS result; connection blocked")
    if not addresses:
        raise ValueError("Private/reserved IP or missing public DNS result; connection blocked")
    return addresses


def connect_pinned(url, *, deadline=None, timeout=SOCKET_TIMEOUT):
    deadline = deadline if deadline is not None else Deadline()
    parts = urlsplit(normalize_url(url))
    host = parts.hostname
    port = 443 if parts.scheme == "https" else 80
    address = public_ips(host, port, deadline=deadline)[0]
    family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(min(timeout, deadline.remaining()))
        sock.connect((address, port))
        if parts.scheme == "https":
            sock.settimeout(min(timeout, deadline.remaining()))
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        deadline.remaining()
        return sock
    except BaseException:
        sock.close()
        raise


class _DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline, wire_limit):
        super().__init__()
        self.sock, self.deadline, self.left = sock, deadline, wire_limit

    def readable(self):
        return True

    def readinto(self, buffer):
        self.sock.settimeout(min(SOCKET_TIMEOUT, self.deadline.remaining()))
        count = self.sock.recv_into(memoryview(buffer)[:min(len(buffer), self.left + 1)])
        self.deadline.remaining()
        self.left -= count
        if self.left < 0:
            raise ValueError("HTTP wire size limit exceeded")
        return count


class _ResponseSocket:
    def __init__(self, sock, deadline, wire_limit):
        self.sock, self.deadline, self.wire_limit = sock, deadline, wire_limit

    def makefile(self, mode):
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline, self.wire_limit))


def fetch(url, *, max_bytes, content_types, max_redirects, deadline=None):
    """No proxy cookies/auth, no decompression, and a new validated IP each hop.

    The wire budget also bounds response headers and chunk framing. Reader-level
    deadline checks cover slow headers, chunk framing and trickled body bytes.
    """
    deadline = deadline if deadline is not None else Deadline()
    current = normalize_url(url)
    for redirects in range(max_redirects + 1):
        parts = urlsplit(current)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        path = quote(path, safe="/%?=&;:+,@!$'()*-._~")
        with connect_pinned(current, deadline=deadline) as sock:
            request = (f"GET {path} HTTP/1.1\r\nHost: {parts.netloc}\r\n"
                       "User-Agent: PhishingRiskResearch/1.0\r\n"
                       "Accept: " + ", ".join(content_types) + "\r\n"
                       "Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
            sock.settimeout(min(SOCKET_TIMEOUT, deadline.remaining()))
            sock.sendall(request.encode("utf-8"))
            deadline.remaining()
            response = http.client.HTTPResponse(
                _ResponseSocket(sock, deadline, max_bytes + MAX_WIRE_OVERHEAD))
            try:
                response.begin()
                if response.status in {301, 302, 303, 307, 308}:
                    if redirects >= max_redirects:
                        raise ValueError("Redirect policy limit exceeded")
                    location = response.getheader("Location")
                    if not location:
                        raise ValueError("Redirect lacks Location header")
                    target = normalize_url(urljoin(current, location))
                    if parts.scheme == "https" and urlsplit(target).scheme != "https":
                        raise ValueError("HTTPS downgrade blocked")
                    current = target
                    continue
                if response.status != 200:
                    raise ValueError("HTTP response is not successful")
                if response.getheader("Content-Encoding", "identity").strip().lower() != "identity":
                    raise ValueError("Encoded responses are not supported")
                media = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
                if media not in content_types:
                    raise ValueError("Unexpected response content type")
                size = response.getheader("Content-Length")
                transfer = response.getheader("Transfer-Encoding", "").strip().lower()
                if transfer not in ("", "chunked") or (transfer and size is not None):
                    raise ValueError("Unsupported or ambiguous HTTP framing")
                if size is not None and (int(size) < 0 or int(size) > max_bytes):
                    raise ValueError("Response body size limit exceeded")
                data = response.read(max_bytes + 1)
                deadline.remaining()
                if len(data) > max_bytes:
                    raise ValueError("Response body size limit exceeded")
                if size is not None and len(data) != int(size):
                    raise ValueError("Truncated HTTP response body")
                return data, current, redirects
            finally:
                response.close()
    raise ValueError("Redirect policy limit exceeded")

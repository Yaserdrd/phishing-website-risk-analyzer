"""URL heuristics and optional opt-in active checks.

Active checks use DNS validation + PINNED PUBLIC IP connections for every hop.
No requests library call is made to untrusted URL hosts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from .urls import MAX_URL_LENGTH, normalize_url

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
KEYWORDS = ("login", "verify", "account", "secure", "update", "signin", "confirm", "password", "bank")
MAX_HTML_BYTES = 512_000
MAX_REDIRECTS = 3


def passive_check(url: str):
    u = normalize_url(url)
    parts = urlsplit(u)
    host = parts.hostname or ""
    score, findings = 0, []
    try:
        ipaddress.ip_address(host)
        score += 20
        findings.append("URL uses an IP address instead of a hostname")
    except ValueError:
        pass
    if len(u) > 75:
        score += 10
        findings.append("Unusually long URL")
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        score += 15
        findings.append("URL shortening service detected")
    if "@" in u:
        score += 15
        findings.append("@ character in URL")
    if "-" in host:
        score += 8
        findings.append("Hyphen in hostname")
    if parts.scheme != "https":
        score += 12
        findings.append("HTTPS is not used")
    if any(word in u.lower() for word in KEYWORDS):
        score += 8
        findings.append("URL contains security-sensitive words")
    return min(score, 30), findings


def public_ips(host: str, port: int):
    """Only public unicast IPs are allowed. No implicit DNS lookup by the HTTP client."""
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM)})
    except (OSError, ValueError) as exc:
        raise ValueError("DNS resolution unavailable") from exc
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Private/reserved IP or missing public DNS result; connection blocked")
    return addresses


def _connect_pinned(url: str, *, timeout=4):
    """Connect to a pre-validated IP, retaining Host header and TLS SNI."""
    parts = urlsplit(normalize_url(url))
    host = parts.hostname or ""
    port = 443 if parts.scheme == "https" else 80
    ips = public_ips(host, port)
    sock = socket.create_connection((ips[0], port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        if parts.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        return sock
    except BaseException:
        sock.close()
        raise


def tls_check(url: str):
    normalized = normalize_url(url)
    if urlsplit(normalized).scheme != "https":
        return {"status": "not_https", "valid": False, "days_to_expiry": None}
    try:
        with _connect_pinned(normalized) as sock:
            cert = sock.getpeercert()
            expiry = cert.get("notAfter")
            remaining = None
            if expiry:
                end = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                remaining = (end - datetime.now(timezone.utc)).days
            return {"status": "verified", "valid": True, "days_to_expiry": remaining}
    except (OSError, ValueError, ssl.SSLError):
        return {"status": "unavailable_or_unverified", "valid": False, "days_to_expiry": None}


def read_html(url: str):
    """Opt-in fetch, limited to HTTP(S) port 80/443, 3 redirects, 512 KB.

    DNS is checked on EACH hop and the socket is explicitly connected to that
    checked IP (eliminating DNS rebinding between validation and connection).
    """
    current = normalize_url(url)
    for redirects in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        with _connect_pinned(current) as sock:
            # Header injection is rejected by normalize_url (control characters).
            host = parts.netloc
            request = (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: PhishingRiskResearch/1.0\r\n"
                "Accept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
            )
            sock.sendall(request.encode("utf-8"))
            response = http.client.HTTPResponse(sock)
            response.begin()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Redirect lacks Location header")
                current = normalize_url(urljoin(current, location))
                continue
            if "text/html" not in (response.getheader("Content-Type", "").lower()):
                raise ValueError("The response is not HTML")
            data = response.read(MAX_HTML_BYTES + 1)
            if len(data) > MAX_HTML_BYTES:
                raise ValueError("HTML response exceeds 512 KB")
            return data.decode("utf-8", errors="replace"), current, redirects
    raise ValueError("Too many redirects")


def html_check(html: str, page_url: str):
    soup = BeautifulSoup(html, "html.parser")
    root_host = urlsplit(normalize_url(page_url)).hostname or ""
    forms = soup.find_all("form")
    password_fields = soup.find_all("input", attrs={"type": lambda v: isinstance(v, str) and v.lower() == "password"})
    iframes = soup.find_all("iframe")
    links, external, cross_forms = [], 0, 0
    for form in forms:
        action = (form.get("action") or "").strip()
        if action:
            try:
                dest = urlsplit(normalize_url(urljoin(page_url, action))).hostname
                if dest != root_host:
                    cross_forms += 1
            except ValueError:
                cross_forms += 1
    for link in soup.find_all("a", href=True):
        href = link.get("href", "").strip()
        if href.startswith(("http://", "https://", "/")):
            try:
                dest = normalize_url(urljoin(page_url, href))
            except ValueError:
                continue
            links.append(dest)
            if urlsplit(dest).hostname != root_host:
                external += 1
    risk, findings = 0, []
    if cross_forms:
        risk += min(15, cross_forms * 8)
        findings.append(f"{cross_forms} form(s) submit to a different hostname")
    if password_fields:
        risk += 3
    if iframes:
        risk += min(5, len(iframes) * 2)
    if len(links) >= 5 and external / len(links) > .80:
        risk += 5
        findings.append("More than 80% of links point to other hostnames")
    summary = {"forms": len(forms), "password_fields": len(password_fields), "iframes": len(iframes),
               "links": len(links), "external_links": external}
    return min(20, risk), findings, summary


def rdap_check(url: str):
    """Query only a fixed RDAP endpoint; do not contact arbitrary input hosts."""
    import requests
    import tldextract

    host = urlsplit(normalize_url(url)).hostname or ""
    extract = tldextract.TLDExtract(suffix_list_urls=())(host)
    domain = f"{extract.domain}.{extract.suffix}" if extract.domain and extract.suffix else None
    if not domain:
        return 0, ["No registrable domain"], {"domain": None, "age_days": None}
    try:
        response = requests.get("https://rdap.org/domain/" + domain, timeout=4,
                                headers={"User-Agent": "PhishingRiskResearch/1.0"})
        response.raise_for_status()
        registration = next((event["eventDate"] for event in response.json().get("events", [])
                             if event.get("eventAction") == "registration" and event.get("eventDate")), None)
        age_days = None
        if registration:
            created = datetime.fromisoformat(registration.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created).days
        if age_days is None:
            return 0, ["Domain age unavailable"], {"domain": domain, "age_days": None}
        if age_days < 30:
            return 10, ["Domain is less than 30 days old"], {"domain": domain, "age_days": age_days}
        if age_days < 180:
            return 5, ["Domain is less than 180 days old"], {"domain": domain, "age_days": age_days}
        return 0, [], {"domain": domain, "age_days": age_days}
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return 0, ["RDAP unavailable; no risk assigned"], {"domain": domain, "age_days": None}

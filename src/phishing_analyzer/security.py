"""URL heuristics and optional opt-in active checks.

Active checks use DNS validation + PINNED PUBLIC IP connections for every hop.
No requests library call is made to untrusted URL hosts.
"""
from __future__ import annotations

from datetime import datetime, timezone
import http.client
import ipaddress
import json
import ssl
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from .urls import normalize_url
from .network import Deadline, connect_pinned as _connect_pinned, fetch, public_ips

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
KEYWORDS = ("login", "verify", "account", "secure", "update", "signin", "confirm", "password", "bank")
MAX_HTML_BYTES = 512_000
MAX_REDIRECTS = 3
MAX_RDAP_BYTES = 128_000


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


def tls_check(url: str, *, deadline=None):
    normalized = normalize_url(url)
    if urlsplit(normalized).scheme != "https":
        return {"status": "not_https", "valid": False, "days_to_expiry": None}
    try:
        budget = deadline if deadline is not None else Deadline()
        with _connect_pinned(normalized, deadline=budget) as sock:
            cert = sock.getpeercert()
            budget.remaining()
            expiry = cert.get("notAfter")
            remaining = None
            if expiry:
                end = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                remaining = (end - datetime.now(timezone.utc)).days
            return {"status": "verified", "valid": True, "days_to_expiry": remaining}
    except (OSError, ValueError, ssl.SSLError):
        return {"status": "unavailable_or_unverified", "valid": False, "days_to_expiry": None}


def read_html(url: str, *, deadline=None):
    """Opt-in fetch, limited to HTTP(S) port 80/443, 3 redirects, 512 KB.

    DNS is checked on EACH hop and the socket is explicitly connected to that
    checked IP (eliminating DNS rebinding between validation and connection).
    """
    data, final_url, redirects = fetch(url, max_bytes=MAX_HTML_BYTES,
        content_types=("text/html",), max_redirects=MAX_REDIRECTS, deadline=deadline)
    return data.decode("utf-8", errors="replace"), final_url, redirects


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


def rdap_check(url: str, *, deadline=None):
    """Query pinned HTTPS rdap.org only; do not follow registry redirects."""
    import tldextract

    host = urlsplit(normalize_url(url)).hostname or ""
    extract = tldextract.TLDExtract(suffix_list_urls=())(host)
    domain = f"{extract.domain}.{extract.suffix}" if extract.domain and extract.suffix else None
    if not domain:
        return 0, ["No registrable domain"], {"domain": None, "age_days": None}
    try:
        data, _, _ = fetch("https://rdap.org/domain/" + domain, max_bytes=MAX_RDAP_BYTES,
            content_types=("application/rdap+json", "application/json"), max_redirects=0, deadline=deadline)
        document = json.loads(data)
        if not isinstance(document, dict) or not isinstance(document.get("events", []), list):
            raise ValueError("Invalid RDAP event structure")
        registration = next((event["eventDate"] for event in document.get("events", [])
                             if isinstance(event, dict) and event.get("eventAction") == "registration"
                             and isinstance(event.get("eventDate"), str)), None)
        age_days = None
        if registration:
            created = datetime.fromisoformat(registration.replace("Z", "+00:00"))
            current = datetime.now(timezone.utc)
            if created.tzinfo is None or created > current:
                raise ValueError("Invalid RDAP registration time")
            age_days = (current - created).days
        if age_days is None:
            return 0, ["Domain age unavailable"], {"domain": domain, "age_days": None}
        if age_days < 30:
            return 10, ["Domain is less than 30 days old"], {"domain": domain, "age_days": age_days}
        if age_days < 180:
            return 5, ["Domain is less than 180 days old"], {"domain": domain, "age_days": age_days}
        return 0, [], {"domain": domain, "age_days": age_days}
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        return 0, ["RDAP unavailable; no risk assigned"], {"domain": domain, "age_days": None}

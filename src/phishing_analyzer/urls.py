"""Deterministic URL normalization and validation, without network I/O."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def normalize_url(value: str) -> str:
    """Return a canonical HTTP(S) URL; reject unsafe/malformed input.

    Normalization is shared by the training pipeline and application.
    Case in path/query is intentionally preserved.
    """
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    raw = value.strip()
    if not raw or len(raw) > MAX_URL_LENGTH or any(ord(ch) < 32 for ch in raw):
        raise ValueError("Invalid or oversized URL")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
        if p.scheme.lower() not in {"http", "https"} or not p.hostname:
            raise ValueError("Only http:// and https:// URLs are supported")
        if p.username is not None or p.password is not None:
            raise ValueError("Credentials embedded in URLs are not supported")
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not host or len(host) > 253:
            raise ValueError("Invalid hostname")
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if not _HOST_RE.fullmatch(host) or host.startswith("-") or ".." in host:
                raise ValueError("Invalid hostname") from None
            labels = host.split(".")
            if any(not label or label.startswith("-") or label.endswith("-") or len(label) > 63 for label in labels):
                raise ValueError("Invalid hostname")
        port = p.port
        expected_port = 80 if p.scheme.lower() == "http" else 443
        if port is not None and port != expected_port:
            raise ValueError("Only the standard port for this URL scheme is supported")
        port = None
        displayed_host = f"[{host}]" if ip and ip.version == 6 else host
        netloc = displayed_host + (f":{port}" if port else "")
        return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc) or "Invalid URL") from exc


def hostname(value: str) -> str:
    return urlsplit(normalize_url(value)).hostname or ""


def host_group(value: str) -> str:
    """Group by hostname; distinct subdomains remain separate groups."""
    return hostname(value).removeprefix("www.")


def urls_for_vectorizer(values):
    return [normalize_url(str(url)) for url in values]


def hosts_for_vectorizer(values):
    return [host_group(str(url)) for url in values]


def root_url(value: str) -> str:
    host = host_group(value)
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    return "https://" + host + "/"

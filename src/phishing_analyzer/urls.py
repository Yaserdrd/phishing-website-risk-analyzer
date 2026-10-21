"""Deterministic URL validation and public-suffix-aware grouping."""
from __future__ import annotations

from functools import lru_cache
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
_HOST_RE = re.compile(r"^[a-z0-9.-]+$")


def normalize_url(value: str) -> str:
    """Canonicalize HTTP(S) URLs consistently at train and inference time."""
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
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
            if not _HOST_RE.fullmatch(host) or host.startswith("-") or ".." in host:
                raise ValueError("Invalid hostname")
            labels = host.split(".")
            if any(not label or label.startswith("-") or label.endswith("-") or len(label) > 63 for label in labels):
                raise ValueError("Invalid hostname")
        port = p.port
        expected_port = 80 if p.scheme.lower() == "http" else 443
        if port is not None and port != expected_port:
            raise ValueError("Only the standard port for this URL scheme is supported")
        displayed_host = f"[{host}]" if ip and ip.version == 6 else host
        return urlunsplit((p.scheme.lower(), displayed_host, p.path or "/", p.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(str(exc) or "Invalid URL") from exc


def hostname(value: str) -> str:
    return urlsplit(normalize_url(value)).hostname or ""


def host_group(value: str) -> str:
    return hostname(value).removeprefix("www.")


@lru_cache(maxsize=1)
def _extractor():
    import tldextract
    return tldextract.TLDExtract(suffix_list_urls=())


@lru_cache(maxsize=100_000)
def _registrable_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    # Use the bundled Public Suffix List snapshot: no runtime HTTP requests.
    try:
        import tldextract
    except ImportError:
        # libpsl is an offline fallback for test environments without optional
        # Python dependencies; on normal installations tldextract is preferred.
        import ctypes
        import ctypes.util
        library = ctypes.util.find_library("psl")
        if not library:
            raise RuntimeError("Install tldextract: pip install -r requirements-train.txt") from None
        psl = ctypes.CDLL(library)
        psl.psl_builtin.restype = ctypes.c_void_p
        psl.psl_registrable_domain.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        psl.psl_registrable_domain.restype = ctypes.c_char_p
        result = psl.psl_registrable_domain(psl.psl_builtin(), host.encode("ascii"))
        return result.decode("ascii") if result else host
    parts = _extractor()(host)
    return parts.top_domain_under_public_suffix or host


def domain_group(value: str) -> str:
    """Registrable domain / eTLD+1. All sibling subdomains share a group."""
    return _registrable_host(hostname(value))


def urls_for_vectorizer(values):
    return [normalize_url(str(url)) for url in values]


def hosts_for_vectorizer(values):
    return [host_group(str(url)) for url in values]

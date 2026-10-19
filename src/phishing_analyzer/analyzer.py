"""Orchestrates passive-only default and explicit opt-in active checks."""
from __future__ import annotations
from .model import predict
from .security import html_check, passive_check, rdap_check, read_html, tls_check
from .urls import normalize_url


def analyze(url, model=None, meta=None, *, active=False):
    url = normalize_url(url)
    passive, findings = passive_check(url)
    scores = {"url_heuristics": passive}
    checks = {}
    ml = None
    if model is not None and meta is not None:
        ml = predict(url, model, meta)
        scores["url_ml"] = round(ml["contribution"], 2)
    if active:
        tls = tls_check(url)
        checks["tls"] = tls
        if tls["status"] == "unavailable_or_unverified":
            scores["tls"] = 15
            findings.append("TLS certificate could not be verified (also may be a network failure)")
        rdap_score, rdap_findings, rdap_details = rdap_check(url)
        scores["rdap"] = rdap_score
        findings.extend(rdap_findings)
        checks["rdap"] = rdap_details
        try:
            html, final_url, redirects = read_html(url)
            html_score, html_findings, html_details = html_check(html, final_url)
            scores["html"] = min(20, html_score + (3 if redirects > 2 else 0))
            findings.extend(html_findings)
            checks["html"] = {**html_details, "redirects": redirects}
        except (OSError, ValueError, TimeoutError) as exc:
            checks["html"] = {"status": "unavailable", "reason": str(exc)}
            # Missing data is not counted as evidence of maliciousness.
    score = min(100, round(sum(scores.values())))
    return {
        "url": url, "risk_score": score,
        "risk_level": "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW",
        "score_parts": scores, "ml": ml, "findings": findings,
        "checks": checks, "active": active,
        "disclaimer": "Educational heuristic risk score, not a probability or a safety guarantee.",
    }

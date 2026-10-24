"""Preserve the known historical ZIP in a draft release; never execute pickle.

Designed for GitHub Actions' repository-scoped GITHUB_TOKEN. No approval manifest
is fabricated. Only the fixed original artifact can be archived by this utility.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = "Yaserdrd/phishing-website-risk-analyzer"
API = f"https://api.github.com/repos/{REPO}"
ARTIFACT = 12385851453
RUN = 39684966827
COMMIT = "09e52d9772aaaa863157f8db405302a89dfa1e89"
DIGEST = "380622aa45ab410cf6ae499e5c271c271f05c1329f0f9c0066404b1262f45fda"
TAG = "archive-v2.1-2026-10-21"
MAX_ZIP = 20_000_000


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise ValueError("Non-HTTPS archive redirect rejected")
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if target.hostname != urllib.parse.urlsplit(request.full_url).hostname:
            redirected.remove_header("Authorization")
        return redirected


def request(url, token, *, data=None, media="application/json"):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443)
            or host not in {"api.github.com", "uploads.github.com"}):
        raise ValueError("Credentials may only be sent to GitHub API/upload hosts")
    req = urllib.request.Request(url, data=data, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "Content-Type": media, "User-Agent": "PhishingResearchArchive/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.build_opener(SafeRedirect()).open(req, timeout=90) as response:
        body = response.read(MAX_ZIP + 1)
    if len(body) > MAX_ZIP:
        raise ValueError("GitHub response exceeds archive budget")
    return body


def inspect_archive(raw, metadata_reference):
    if len(raw) > MAX_ZIP or hashlib.sha256(raw).hexdigest() != DIGEST:
        raise ValueError("Original archive digest mismatch")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        expected = {"url_model_meta.json": 1_000_000, "url_phishing_model.pkl": 256 * 1024 * 1024}
        if len(members) != 2 or {x.filename for x in members} != set(expected):
            raise ValueError("Unexpected or duplicate archive members")
        entries = {}
        for item in members:
            if item.file_size > expected[item.filename] or item.flag_bits & 1:
                raise ValueError("Oversized or encrypted archive member")
            data = archive.read(item)
            entries[item.filename] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            if item.filename == "url_model_meta.json" and json.loads(data) != metadata_reference:
                raise ValueError("Archived metadata differs from committed historical evidence")
    return {"status": "historical-archive-not-serving-approved", "source_run": RUN,
            "source_commit": COMMIT, "artifact_id": ARTIFACT, "archive_sha256": DIGEST,
            "members": entries, "deserialized": False, "approval_manifest_present": False,
            "metadata_matches_committed_report": True}


def preserve(token, metadata_reference):
    def api(path):
        return json.loads(request(API + path, token))
    artifact = api(f"/actions/artifacts/{ARTIFACT}")
    if (artifact.get("expired") or artifact.get("digest") != "sha256:" + DIGEST
            or artifact.get("workflow_run", {}).get("id") != RUN
            or artifact.get("workflow_run", {}).get("head_sha") != COMMIT):
        raise ValueError("Original artifact source identity mismatch")
    raw = request(API + f"/actions/artifacts/{ARTIFACT}/zip", token)
    identity = inspect_archive(raw, metadata_reference)
    matches = [r for r in api("/releases?per_page=100") if r["tag_name"] == TAG]
    if len(matches) != 1 or not matches[0]["draft"]:
        raise ValueError("Exactly one existing draft archive release is required")
    release = matches[0]
    assets = {a["name"]: a for a in release["assets"]}
    expected_assets = {}
    for name, data in [("uci-v21-original.zip", raw),
                       ("archive-identity.json", (json.dumps(identity, indent=2) + "\n").encode())]:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        expected_assets[name] = (digest, len(data))
        if name in assets:
            if assets[name].get("digest") != digest or assets[name]["size"] != len(data):
                raise ValueError("Existing archive asset differs; never overwrite")
            continue
        url = release["upload_url"].split("{", 1)[0] + "?name=" + urllib.parse.quote(name)
        result = json.loads(request(url, token, data=data,
                                    media="application/zip" if name.endswith(".zip") else "application/json"))
        if result.get("digest") != digest or result.get("size") != len(data):
            raise ValueError("Uploaded asset digest/size mismatch")
    final = api(f'/releases/{release["id"]}')
    if not final["draft"]:
        raise ValueError("Archive must remain a draft")
    retained = {a["name"]: a for a in final["assets"]}
    for name, (digest, size) in expected_assets.items():
        if name not in retained or retained[name].get("digest") != digest or retained[name]["size"] != size:
            raise ValueError("Final release does not retain the verified asset")
    return {"release_id": final["id"], "draft": True, "archive_sha256": DIGEST,
            "deserialized": False, "serving_approved": False}


def main():
    root = Path(__file__).resolve().parents[1]
    reference = json.loads((root / "reports/uci_phiusiil_selective_v21_2026-10-21.json").read_text())
    print(json.dumps(preserve(os.environ["GITHUB_TOKEN"], reference), indent=2))


if __name__ == "__main__":
    main()

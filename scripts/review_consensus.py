"""Build a prospective vetted CSV from two independent offline reviews.

Never fetches reviewed URLs. The resulting vetted CSV contains sensitive URLs:
store it outside the Git working tree, never commit it.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phishing_analyzer.protocol import CUTOFF, evaluation_time, parse_time, valid_window
from phishing_analyzer.urls import normalize_url, domain_group
from phishing_analyzer.private_files import private_path, read_private

REQUIRED = {
    "url", "label", "observed_at_utc", "verified_at_utc",
    "evidence_ref", "reviewer_id",
}
MAX_BYTES = 20_000_000


def adjudicate(csv_path, *, now=None, cutoff=CUTOFF):
    return adjudicate_bytes(read_private(csv_path, MAX_BYTES), now=now, cutoff=cutoff)


def adjudicate_bytes(data, *, now=None, cutoff=CUTOFF):
    """Return agreed vetted rows and aggregate quality audit; refuse invalid review metadata.

    Each distinct URL requires two independent reviewer IDs, both agreeing on label.
    Disagreements are excluded, not silently decided. Dates may not precede cutoff.
    """
    current = evaluation_time(now)
    if len(data) > MAX_BYTES:
        raise ValueError("Review file exceeds size limit")
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    if not REQUIRED.issubset(reader.fieldnames or []):
        raise ValueError("Missing required review columns")
    reviews = defaultdict(list)
    for line, item in enumerate(reader, 2):
        if None in item:
            raise ValueError(f"Row {line}: unexpected extra columns")
        try:
            url = normalize_url(item["url"])
            label = item["label"].strip().upper()
            reviewer = item["reviewer_id"].strip()
            evidence = item["evidence_ref"].strip()
            observed = parse_time(item["observed_at_utc"])
            verified = parse_time(item["verified_at_utc"])
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError(f"Row {line}: invalid review") from error
        if label not in {"PHISHING", "LEGITIMATE"}:
            raise ValueError(f"Row {line}: invalid label")
        if not reviewer or not evidence or "\n" in reviewer or "\n" in evidence or "|" in reviewer or "|" in evidence:
            raise ValueError(f"Row {line}: missing or unsafe reviewer/evidence")
        if not valid_window(observed, verified, current, cutoff):
            raise ValueError(f"Row {line}: invalid review timestamps")
        if any(old["reviewer"] == reviewer for old in reviews[url]):
            raise ValueError(f"Row {line}: duplicate reviewer for URL")
        reviews[url].append({
            "label": label, "reviewer": reviewer, "evidence": evidence,
            "observed": observed, "verified": verified,
        })

    output = []
    counts = Counter()
    domain_decisions = defaultdict(set)
    for url, items in sorted(reviews.items()):
        if len(items) != 2:
            counts["needs_second_review"] += 1
            continue
        if items[0]["label"] != items[1]["label"]:
            counts["disputed"] += 1
            continue
        label = items[0]["label"]
        counts["agreed"] += 1
        domain_decisions[domain_group(url)].add(label)
        output.append({
            "url": url, "label": label,
            "observed_at_utc": max(x["observed"] for x in items).isoformat(),
            "verified_at_utc": max(x["verified"] for x in items).isoformat(),
            "evidence_ref": "|".join(x["evidence"] for x in items),
            "reviewer_id": "|".join(x["reviewer"] for x in items),
        })
    conflict_domains = {g for g, labels in domain_decisions.items() if len(labels) > 1}
    accepted = [row for row in output if domain_group(row["url"]) not in conflict_domains]
    counts["domain_conflict_excluded"] = len(output) - len(accepted)
    counts["accepted"] = len(accepted)
    counts["accepted_phishing"] = sum(row["label"] == "PHISHING" for row in accepted)
    counts["accepted_legitimate"] = sum(row["label"] == "LEGITIMATE" for row in accepted)
    return accepted, {
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "distinct_reviewed_urls": len(reviews),
        "review_rows": sum(map(len, reviews.values())),
        "counts": dict(counts),
        "warning": "Agreement and metadata do not prove truth or reviewer independence; verify evidence outside this script.",
    }


def vetted_bytes(records):
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=[
        "url", "label", "observed_at_utc", "verified_at_utc", "evidence_ref", "reviewer_id"
    ])
    writer.writeheader()
    writer.writerows(records)
    return buffer.getvalue().encode("utf-8")


def approved_consensus(reviews_path, vetted_path, approved_sha256, *, now=None):
    """Recompute consensus from the exact review bytes approved out of band.

    A self-supplied digest cannot authenticate reviewers or their evidence.
    Neither source nor vetted input is reread after verification.
    """
    if not isinstance(approved_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", approved_sha256):
        raise ValueError("An approved review SHA-256 is required")
    data = read_private(reviews_path, MAX_BYTES)
    if hashlib.sha256(data).hexdigest() != approved_sha256:
        raise ValueError("Approved review digest mismatch")
    records, summary = adjudicate_bytes(data, now=now)
    vetted = read_private(vetted_path, MAX_BYTES)
    if vetted != vetted_bytes(records):
        raise ValueError("Vetted CSV does not match recomputed dual-review consensus")
    return vetted, {"protocol": "dual-review-consensus-v1", **summary}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviews", required=True, help="Private individual-review CSV")
    parser.add_argument("--out", required=True, help="Private agreed-vetted CSV, outside git checkout")
    parser.add_argument("--summary", required=True, help="Aggregate JSON without URLs")
    args = parser.parse_args()
    source = private_path(args.reviews)
    destination = private_path(args.out)
    summary = Path(args.summary).resolve()
    if source == destination or destination == summary or source == summary:
        parser.error("Input, output, and summary paths must differ")
    if destination.exists() or summary.exists():
        parser.error("Refusing to overwrite an output")
    records, meta = adjudicate(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as handle:
        handle.write(vetted_bytes(records))
    summary.parent.mkdir(parents=True, exist_ok=True)
    with summary.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(meta, indent=2) + "\n")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()

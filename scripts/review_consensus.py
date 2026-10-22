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
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from evaluate_vetted_holdout import CUTOFF, parse_time
from phishing_analyzer.urls import normalize_url, domain_group

REQUIRED = {
    "url", "label", "observed_at_utc", "verified_at_utc",
    "evidence_ref", "reviewer_id",
}
MAX_BYTES = 20_000_000


def adjudicate(csv_path, *, now=None, cutoff=CUTOFF):
    """Return agreed vetted rows and aggregate quality audit; refuse invalid review metadata.

    Each distinct URL requires two independent reviewer IDs, both agreeing on label.
    Disagreements are excluded, not silently decided. Dates may not precede cutoff.
    """
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    data = Path(csv_path).read_bytes()
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
        if not (cutoff <= observed <= verified <= current):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviews", required=True, help="Private individual-review CSV")
    parser.add_argument("--out", required=True, help="Private agreed-vetted CSV, outside git checkout")
    parser.add_argument("--summary", required=True, help="Aggregate JSON without URLs")
    args = parser.parse_args()
    source = Path(args.reviews).resolve()
    destination = Path(args.out).resolve()
    summary = Path(args.summary).resolve()
    if source == destination or destination == summary or source == summary:
        parser.error("Input, output, and summary paths must differ")
    if destination.exists():
        parser.error("Refusing to overwrite a vetted file")
    records, meta = adjudicate(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "url", "label", "observed_at_utc", "verified_at_utc", "evidence_ref", "reviewer_id"
        ])
        writer.writeheader()
        writer.writerows(records)
    summary.parent.mkdir(parents=True, exist_ok=True)
    summary.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()

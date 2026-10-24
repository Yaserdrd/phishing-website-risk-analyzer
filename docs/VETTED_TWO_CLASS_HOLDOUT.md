# Future-dated, evidence-reviewed two-class holdout

**Status: validation tool only, no independently vetted corpus collected.** This is not a reported model benchmark.

The existing PhishTank holdout covers positives; **Tranco popularity is not a substitute for verified legitimate labels**. This protocol requires explicitly reviewed `PHISHING` and `LEGITIMATE` URL strings, each associated with its own contemporaneous evidence and a reviewer identifier. One unverifiable source list must never be mass-labelled legitimate. Only records first observed **and** verified at or after **2026-10-23 00:00 UTC** are eligible. The dataset should be assembled prospectively, and the v2.1 model must remain frozen. This cutoff was registered on 2026-10-22 and is not adjusted based on outcomes.

## Review requirements (outside the code)

1. Independently select sources without inspecting v2.1 model scores. Prefer separate evaluators for adjudication and evaluation; retain review logs in access-controlled storage rather than Git.
2. For each URL, record the actual URL, reviewer-confirmed `PHISHING` or `LEGITIMATE`, UTC first observation and verification timestamps, a concrete `evidence_ref` into your review register, and a `reviewer_id`. For phishing, use an appropriately verified threat intelligence record; for legitimate, verify site/domain ownership and actual page context at the *exact URL* rather than asserting domain popularity means safety. Avoid interacting with suspected phishing sites; rely on authorized evidence, feeds, and controlled inspection.
3. Resolve conflicting reviews outside the test utility. The utility rejects contradictory labels within a registrable domain as a conservative evidence-quality guard, which can exclude genuine compromised websites sharing a legitimate domain. Document that bias.
4. Do not inspect this holdout to tune the current model. Keep it confidential until a single pre-registered final evaluation. Document selection strategy, sampling frame, geographic/language coverage, prevalence, adjudication and possible reviewer errors.
5. Keep raw URLs and evidence records outside the public repository. The program exports only aggregate numbers and SHA-256 of the input file. The file hash does not validate truth of labels.

Required CSV schema:

```text
url,label,observed_at_utc,verified_at_utc,evidence_ref,reviewer_id
```

All timestamps must be offset-aware UTC (`Z` or `+00:00`). A non-empty evidence reference and reviewer ID are **necessary, not sufficient** for label validity. The schema checker does not verify that the evidence reference resolves or that the reviewer is independent.

## Run (after collecting vetted data)

```bash
python -m pip install -r requirements-dev.txt
python scripts/download_uci.py
# Rebuild trusted v2.1 model from fixed commit 9a3ced00... in an isolated folder;
# put its model + metadata under models/ (never load untrusted pickles).
PYTHONPATH=src python scripts/evaluate_vetted_holdout.py \
  --vetted-csv /secure/reviewed_urls.csv \
  --reviews /secure/reviews.csv \
  --reviews-sha256 "$APPROVED_REVIEWS_SHA256" \
  --uci-csv data/phiusiil_urls.csv \
  --model-dir models \
  --manifest /secure/frozen_manifest.json \
  --manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --min-per-class 100 \
  --out reports/vetted_holdout.json
```

Fails with **no metric** if either class has fewer than 100 reviewed samples (or if metadata is invalid). Outputs abstention-aware three-way confusion counts, coverage, accuracy among decided, phishing detection and false-clear rates, legitimate false-alarm rate. The script does **not** visit URLs.

The manifest and its approved digest are now required. Follow
[frozen model identity](FROZEN_MODEL_IDENTITY.md) to bind the exact trusted model,
metadata, UCI input and runtime before evaluation. Creating a new hash around an
untrusted pickle does not make it trusted. Version `2.1.0` alone is insufficient.
The UCI CSV and model paths above must match the approved manifest. Reviewers and
evaluation input must use the shared explicit-UTC ordering rule through the fixed
cutoff and captured evaluation time. The original private reviews and independently
approved review digest are also mandatory. The evaluator recomputes dual-review
consensus and requires the vetted CSV's exact bytes to match before loading the
model. Generate that CSV with `review_consensus.py`; single-review CSVs alone
are no longer accepted. See the [approval and private-storage workflow](INDEPENDENT_REVIEW_PROTOCOL.md).
Digests bind bytes, not evidence truth or authenticated human independence.
Reports refuse to overwrite existing files or inputs.

**Limitations:** minimum class count is an engineering gate, not a confidence guarantee. Curated selection cannot by itself establish real-world prevalence or predictive calibration. This evaluator must not be used repeatedly to choose a new model; collect another independent holdout for subsequent versions.

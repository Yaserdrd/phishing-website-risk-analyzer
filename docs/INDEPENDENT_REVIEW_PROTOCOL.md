# Independent dual-review evidence workflow

**Status: evidence collection and adjudication tool; NO vetted real-world sample corpus collected.**

This offline utility converts *two independent reviewer decisions per exact URL* into the CSV format expected by `evaluate_vetted_holdout.py`. The evaluator now requires the original review file and its independently approved SHA-256, recomputes consensus and compares the exact CSV bytes before model loading/scoring. No suspicious URLs are visited. This addresses reviewer agreement, but **does not establish whether reviewers' statements are true**.

## Privacy and workflow

1. Maintain the raw review CSV in encrypted/private storage **outside this repository**. Do not commit URL lists or evidence artifacts. Reviewers must not see the frozen model's predictions.
2. Use one row per reviewer and URL, with header `url,label,observed_at_utc,verified_at_utc,evidence_ref,reviewer_id`. `label` must be `PHISHING` or `LEGITIMATE`, timestamps must be explicit UTC and at least 2026-10-23 00:00 UTC. `evidence_ref` should identify an actual evidence record in an access-controlled register.
3. Require **two distinct reviewer IDs** per URL; the code excludes ties/disagreements, unreviewed examples, and consensus rows at domains carrying contradictory labels. This conservative domain-level exclusion introduces selection bias; document excluded examples.
4. Run:
   ```bash
   PYTHONPATH=src python scripts/review_consensus.py \
     --reviews /secure/reviews.csv \
     --out /secure/approved_urls.csv \
     --summary /secure/consensus_counts.json
   ```
5. Before evaluation and before exposing model scores, an independent lead must manually verify evidence references, reviewer identities, and actual website context at the **exact URL**. Metadata agreement is not proof of legitimacy; avoid unsafe visits to suspect phishing links. Sampling, reviewer training, label definitions and disagreements must be documented. Record approval of the exact raw review file's SHA-256 through a trusted, access-controlled channel. Do not accept a file and its claimed approval digest from an untrusted submitter.
6. Only after evidence checks, use `evaluate_vetted_holdout.py` on the **frozen v2.1 model**, supplying `--reviews /secure/reviews.csv --reviews-sha256 "$APPROVED_REVIEWS_SHA256"` along with the approved model identity and `--vetted-csv /secure/approved_urls.csv`. Keep both CSVs private and require at least 100 vetted records per class. The cutoff is unchanged. Publish only aggregate metrics after disclosure review.

The evaluator consumes the exact buffers it verified, so it does not reread a
changed CSV after approval. Hand edits, reordering or newline changes to the
generated vetted CSV fail the byte comparison; regenerate it from the approved
reviews instead. Single-review, disputed and conflicting-domain examples cannot
be added to the accepted corpus. The aggregate report records the review digest,
consensus protocol and exclusion counts, without raw URLs, evidence references
or reviewer IDs. The evaluation report protocol is now
`prospective-vetted-two-class-v2`.

Private input and vetted-output paths are resolved before use and rejected inside
this repository or detected Git checkouts, including symlink destinations. Output
files are created exclusively, refusing overwrites. These checks prevent routine
storage mistakes; they are not filesystem isolation against concurrent hostile
path changes, hard-link aliases or a later manual copy/commit. Use private storage
with appropriate permissions. Aggregate summaries still need disclosure review.

## Known limitations

- This tool checks distinct reviewer IDs, not actual independence; it cannot authenticate reviewers or evidence references.
- Two reviews are necessary, not sufficient. A legitimate hostname may host a compromised path; entire-domain label exclusions can bias the set.
- Missing reviews and disagreements are excluded, so results might not represent the live web population.
- Never optimize thresholds using this future holdout and call it an untouched test.

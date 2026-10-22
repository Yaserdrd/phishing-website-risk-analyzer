# Independent dual-review evidence workflow

**Status: evidence collection and adjudication tool; NO vetted real-world sample corpus collected.**

This offline utility converts *two independent reviewer decisions per exact URL* into the CSV format expected by `evaluate_vetted_holdout.py`. No suspicious URLs are visited. This addresses reviewer agreement, but **does not establish whether reviewers' statements are true**.

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
5. Before evaluation, an independent lead must manually verify evidence references, reviewer identities, and actual website context at the **exact URL**. Metadata agreement is not proof of legitimacy; avoid unsafe visits to suspect phishing links. Sampling, reviewer training, label definitions and disagreements must be documented.
6. Only after evidence checks, use `evaluate_vetted_holdout.py` on the **frozen v2.1 model**, keeping the accepted URL CSV private and requiring at least 100 vetted records per class. The cutoff is unchanged. Publish only aggregate metrics.

## Known limitations

- This tool checks distinct reviewer IDs, not actual independence; it cannot authenticate reviewers or evidence references.
- Two reviews are necessary, not sufficient. A legitimate hostname may host a compromised path; entire-domain label exclusions can bias the set.
- Missing reviews and disagreements are excluded, so results might not represent the live web population.
- Never optimize thresholds using this future holdout and call it an untouched test.

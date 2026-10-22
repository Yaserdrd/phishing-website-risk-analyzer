# Independent-source URL evaluation and diagnostics (v2)

External audit uses **two different sources**, which must never be merged into a single classification accuracy number:

- **PhishTank** verified + online phishing URL feed: a positive-class signal, though confirmation and feed recency are not perfect.
- **Tranco** list: popular domains, **without any benign ground-truth claim**. They are transformed to HTTPS root URLs for scoring. A model alert on a ranked domain is not a proven false positive.

No submitted or feed URL is visited. Only supplied dataset archives are downloaded. UCI 967 data are used for train and exclusion of registrable domains shared across corpora; no external labels are used for training/threshold updates. Tranco sites and phishing feed URLs differ in input type; analysis must control for this shift.

## Verified first snapshot — 2026-10-22 (v1 audit)

- [Successful GitHub Actions run 39792461394](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39792461394).
- 2,000 PhishTank samples after domain exclusion: **1,982 PHISHING, 3 UNCERTAIN, 15 LEGITIMATE**. Thus the detected fraction of feed-confirmed phishing was **99.1%**. The 15 cleared items are potential misses needing manual review.
- 2,000 ranked Tranco roots after domain exclusion: **1,996 PHISHING, 0 UNCERTAIN, 4 LEGITIMATE**. **99.8% of popular-domain roots triggered phishing alerts**, an extremely worrying distribution. This **is not an empirically measured false-positive rate** because Tranco is not legitimate ground truth.
- Source SHA-256: PhishTank `dfae6d6d5a707502a5df1ccbf94e57d633e2481d8027d27dde9824cbde2b07b5`, Tranco `0ab0fa09d91361b5281aad70baec395600a28cd4c3b6619b9ad21fe16443ef3e`.
- The original v1 report displayed a `seen=10000` count reflecting the prefetched candidates, **not the number actually examined before finding the first 2,000 qualifying URLs**. This is corrected in v2 as `examined`.

**Research decision:** The external audit *pipeline* passed, but model acceptance **failed the qualitative generalization sanity check**. Do not deploy the model as an automatic website trust/safety authority based on these results.

## v2 diagnostics and methodology

The follow-up audit records for each source:

- Actual `examined`, excluded UCI registrable-domain overlaps, invalids, duplicates, and retained sample count.
- Decisions by **root-only URL** vs URL with path or query, and by URL-length bin.
- Quantiles of the model's phishing score (not calibrated probability).
- UTC run timestamp and SHA-256 of each raw downloaded snapshot.
- A warning when more than half of unlabeled popular domain roots trigger phishing alerts. This **exploratory threshold** is diagnostic, not a validated quality gate.

## Run and interpretation

1. `pip install -r requirements-dev.txt`
2. `python scripts/download_uci.py`
3. `python scripts/train_model.py --csv data/phiusiil_urls.csv`
4. Fetch the *public feed archives*, subject to their terms, into `data/external/`.
5. `PYTHONPATH=src python scripts/evaluate_external.py --uci-csv data/phiusiil_urls.csv --phishing-csv data/external/online-valid.csv.gz --popular-zip data/external/tranco.zip --sample 2000 --out reports/external_audit.json`.

Or use **Actions → Independent URL source audit → Run workflow**. The GitHub workflow **trains a trusted model in the same run**, avoiding dependence on a short-lived model pickle artifact from past workflow runs. Only report and model metadata are retained as workflow artifacts.

**Do not tune a model using these exploratory results and then report performance on the same external snapshot as an untouched test.** A subsequent independent source/time snapshot must be reserved for final acceptance. A more conclusive negative-class benchmark needs sites **actually vetted and labelled legitimate**, not merely a popularity ranking. Robustness checks should compare full URL and root-only input formats within the same labelled source.

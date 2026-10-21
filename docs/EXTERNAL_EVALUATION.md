# Independent source-shift URL audit

The original UCI PhiUSIIL (dataset 967) holdout benchmark, though domain-disjoint, is still **from the same dataset**. A stronger research prototype must also report what happens on independently collected URLs.

## Inputs
- **PhishTank online-valid verified CSV (phishing signal):** https://phishtank.org/developer_info.php . Provider may require a key or impose a rate limit. The source is a changing snapshot, not infallible ground truth.
- **Tranco top-sites CSV ZIP (popularity proxy, not legitimate labels):** https://tranco-list.eu/ . A ranked domain must **not** automatically be treated as confirmed benign.

The program is intentionally offline and never requests any URLs found inside these files. You download only the named source datasets under their respective terms; never fetch the phishing URLs themselves.

## Run

Install requirements, load the **trusted** UCI v2.1 model artifact (not included in Git), and download the UCI dataset. Place provider snapshots in a local `data/external/` directory.

```bash
python -m pip install -r requirements-dev.txt
python scripts/download_uci.py
PYTHONPATH=src python scripts/evaluate_external.py \
  --model-dir models \
  --uci-csv data/phiusiil_urls.csv \
  --phishing-csv data/external/online-valid.csv.gz \
  --popular-zip data/external/tranco-top-1m.zip \
  --sample 2000 --out reports/external_audit.json
```

The checker filters all external URLs sharing **registrable domains with any URL in the original UCI dataset**, including the original test set. This prevents simple exact-domain overlap. It does **not** establish campaign or labeling independence.

## Reporting rules
- Report the three-way outcomes (PHISHING, UNCERTAIN, LEGITIMATE) separately for each source.
- For PhishTank, `LEGITIMATE` predictions indicate a dangerous potential missed threat, but snapshots change over time.
- For Tranco, `PHISHING` predictions are **alerts on popular domains**, not measured false positives: popularity does not prove legitimacy.
- Never compute combined accuracy/F1 from these different sources. Dates, snapshot hashes, sampling limits and exclusions should be preserved.
- Only publish a real metrics JSON after running on actual downloaded provider snapshots; never invent an external score.
- Further decisions about model selection require a **new untouched external set**.

## Status
The external-evaluation harness and its synthetic unit tests are committed. **No verified independent-source numerical benchmark has been produced in this change.** Full evaluation requires the trusted saved v2.1 model and the original source snapshots.

# Verified UCI PhiUSIIL selective-decision benchmark — v2.1

**Date:** 2026-10-21 · **Status:** UCI dataset-specific research benchmark, **not** a production phishing detector.

## Evidence

- [Successful UCI evaluation run #39684966827](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39684966827), on commit `09e52d9772aaaa863157f8db405302a89dfa1e89`.
- [Saved GitHub artifact #12385851453](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39684966827/artifacts/12385851453) includes `url_model_meta.json` and the trained `url_phishing_model.pkl`; configured for **7-day** retention (expires 2026-10-28). The trained pickle is **not in git**.
- GitHub artifact SHA-256 digest: `380622aa45ab410cf6ae499e5c271c271f05c1329f0f9c0066404b1262f45fda`.
- [Permanent metrics-only JSON](../reports/uci_phiusiil_selective_v21_2026-10-21.json).
- The last source change after the successful training run was an `app.py` warning-message change; the training/model implementation did not change.

## Dataset protocol

235,795 original rows; 34 missing/invalid removed, 2 conflicting-label rows quarantined, 1,106 exact normalized-URL duplicates removed. **234,653 unique URLs** retained.

Fit / validation / test contain **153,043 / 29,920 / 51,690 URLs**, respectively. There is no registrable-domain overlap (groups use the Public Suffix List). Model TF-IDF + Logistic Regression is fit on fit only, confidence cutoffs are chosen only using validation, and the reserved UCI test set is used for reporting.

## Why three labels matter

Version 2.1 expands a validation-derived undecided band around the original thresholds. Validation requested approximately **5% abstention** and achieved 1,496 / 29,920 = 5%. Lower/upper score boundaries: `0.03768347266841587` and `0.08012717594132758`.

| Metric on held-out UCI test (51,690 URLs) | v2.0 | v2.1 |
|---|---:|---:|
| Coverage (definite decisions) | 100.000% | **96.067%** |
| Accuracy **among decided URLs only** | 98.203% | **99.074%** |
| False-clear (phishing labelled LEGITIMATE), all true phishing | 0.312% (77/24,672) | **0.239% (59/24,672)** |
| False alert (legitimate labelled PHISHING), all true legitimate | 3.153% (852/27,018) | **1.484% (401/27,018)** |
| UNDECIDED (UNCERTAIN) | 0 | **2,033** |
| Detected phishing among all true phishing | 24,595 | 24,585 |
| PR average precision (URL model) | 99.927% | 99.927% |

**Selective v2.1 decisions breakdown:**

| True class | PHISHING | LEGITIMATE | UNCERTAIN | Total |
|---|---:|---:|---:|---:|
| Phishing | 24,585 | 59 | 28 | 24,672 |
| Legitimate | 401 | 24,612 | 2,005 | 27,018 |
| Total | 24,986 | 24,671 | 2,033 | 51,690 |

Counts marked LEGITIMATE/PHISHING and the total UNCERTAIN are from the saved metrics; uncertain counts by true class are derived from the logged forced-binary confusion matrix plus the logged selective fractions (which are rounded). They must not be mistaken for a separately exported per-URL prediction file.

The **forced-binary** comparison (which forcibly treats every UNCERTAIN as LEGITIMATE) is reported for completeness: accuracy 99.056%, phishing precision 98.395%, recall 99.647%, F1 99.017%, confusion matrix `[[24585,87],[401,26617]]` with class order phishing=0, legitimate=1. **Do not present forced-binary accuracy as v2.1's true 3-way accuracy.**

## Research acceptance

- **Pass (UCI validation):** 3% target false-alert, 1% target phishing false-clear, and 5% abstention.
- **Pass (UCI holdout):** ~1.484% false alerts, ~0.239% false clears; the three-way classifier demonstrably returns UNCERTAIN for some inputs.
- **Not established:** Generalization to new time periods, independent URL sources, low phishing-prevalence populations, or actual web protection.

The v2.0 and v2.1 reports reuse the **same** held-out UCI test set; inspecting both introduces model-selection pressure on that dataset. **Any further tuning or official claimed improvement must use a fresh untouched external holdout**, not this reported test split. Confidence thresholds represent scores, **not calibrated chances of phishing**.

Next experiments: evaluation on newer independently collected URLs, error category distribution (especially false-positive brand terms and hosted-subdomain edge cases), split and TLD cohort reporting, and model calibration separate from decision thresholds.

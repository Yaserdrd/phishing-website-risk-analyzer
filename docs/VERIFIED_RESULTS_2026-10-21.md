# Verified UCI PhiUSIIL URL model: 2026-10-21

**Scope:** Held-out evaluation on UCI PhiUSIIL Phishing URL (ID 967), **not** a time-separated external dataset and **not** evidence of production security.

## Verification evidence

- [Successful GitHub Actions run 39682789730](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39682789730), completed **2026-10-21 21:58:47 UTC**.
- [Training artifact 12384732771](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39682789730/artifacts/12384732771), containing `url_model_meta.json` and `url_phishing_model.pkl`. Artifact retention: 7 days (until **2026-10-28**).
- Downloaded artifact SHA-256: `c0884995caa0cd0b66f2488aa186d3d9257b2fea1fefce33f9a0a10434910596`; matched the GitHub-generated digest.
- Permanent copy of the **JSON metrics only**, excluding the pickle and dataset: [reports/uci_phiusiil_holdout_2026-10-21.json](../reports/uci_phiusiil_holdout_2026-10-21.json).

## Dataset and split

| Check | Actual result |
|---|---:|
| Input rows | 235,795 |
| Missing/invalid removed | 34 |
| Contradictory URLs quarantined (rows) | 1 URL (2 rows) |
| Duplicate rows removed | 1,106 |
| Unique URLs retained | 234,653 |
| Fit / validation / test URL rows | 153,043 / 29,920 / 51,690 |
| Fit / validation / test registrable domains | 115,118 / 25,271 / 35,098 |

Training only used URL text; label 0 means phishing and label 1 legitimate. The three sets were isolated by registrable domain (eTLD+1). The fit set trained the model; the validation set selected thresholds; the test set was not used to select thresholds. Groups are disjoint but samples all come from the **same UCI dataset**.

## Held-out test set

| Metric | Value |
|---|---:|
| Accuracy | 98.203% |
| Phishing precision | 96.652% |
| Phishing recall | 99.688% |
| Phishing F1 | 98.146% |
| Average precision (phishing) | 99.927% |
| Phishing false-clear rate | 0.312% (77 / 24,672) |
| Legitimate false-alarm rate | **3.153% (852 / 27,018)** |
| Selective coverage | 100.0% |
| UNCERTAIN decisions | **0 / 51,690** |

Confusion matrix (true rows, predicted columns, phishing class first):

| | Predicted phishing | Predicted legitimate |
|---|---:|---:|
| True phishing | 24,595 | 77 |
| True legitimate | 852 | 26,166 |

In this evaluation no samples were labeled UNCERTAIN; therefore the forced-binary report and the actual three-way decisions have identical outcomes on this test sample. **Do not generalize this equality to new data.**

## Threshold analysis and research-release decision

**Predeclared validation targets:** false-alarm rate <= 3%; phishing false-clear rate <= 1%. Observed **validation** rates: 2.996% and 0.734% (both inside their respective targets). On the untouched **test** sample:

- Phishing false-clear 0.312%: **passes** 1% target.
- Legitimate false-alarm 3.153%: **misses** 3% target by 0.153 percentage points.
- Confidence/abstention mechanism: **not demonstrated** in the held-out test. The lower and upper cutoffs are `0.06019114787624524` and `0.06019217975664415`, respectively, only `0.00000103188` apart. Thus no test URL received UNCERTAIN, despite support for that label.

Approximate 95% Wilson intervals (simple binomial framing, **not accounting for domain clustering**):
- False-clear: 0.250%–0.390%.
- False-alarm: 2.952%–3.369%.

**Decision: PASS for a reproducible *research* benchmark; NOT READY as a deployed phishing safety product.** Neither deployment safety nor a strictly below-3% held-out false-alarm target has been established. A low score must not be represented as a safety guarantee.

## Mandatory next experiments before any production claim

1. Check performance on independently sourced, contemporary, time-separated URLs with domain-disjoint labeling and no tuning on the final external test set.
2. Investigate the near-identical cutoffs and design a meaningful *validation-only* abstention or conservative warning policy. Do not tune the current test-set threshold to improve these numbers.
3. Evaluate rates across domains, TLDs, website types, and label prevalence. Measure false-positive alert burden at realistically low phishing prevalence.
4. Document score calibration separately. The `predict_proba` score at a `0.06019` threshold **is not** a real-world 6.019% chance of phishing.
5. Train/validate the final policy on a new split or external validation corpus; reserve a new untouched test corpus for final claims.

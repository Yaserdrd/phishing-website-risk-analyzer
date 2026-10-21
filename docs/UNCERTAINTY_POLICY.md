# Validation-only uncertainty policy (v2.1)

**Research status:** Implementation and synthetic unit tests are available; full UCI retraining must complete before claiming held-out v2.1 results. [Previously verified v2.0 metrics](VERIFIED_RESULTS_2026-10-21.md) are **not** v2.1 metrics.

## Why change?

The v2.0 model produced no `UNCERTAIN` decisions among 51,690 held-out UCI URLs. Its two cutoffs were almost identical (0.060191147876 versus 0.060192179757). Legitimate false alarms were 852 / 27,018 (3.153%), slightly exceeding the 3% target.

## Conservative change

1. Fit TF-IDF + logistic regression **only on fit**, leaving validation and test held out by registrable domain.
2. Select baseline cutoffs from **validation only** under the existing validation false-alert and phishing-clearance targets.
3. Rank validation URLs by closeness to the midpoint of those cutoffs, then expand the uncertain band around that midpoint until at least **5% of validation URLs** are abstained. Existing uncertain URLs remain uncertain.
4. Expand, never shrink: no previously uncertain URL becomes a confident decision and no confident decision is reversed. Some previously confident URLs become uncertain.
5. Freeze model and cutoffs before checking UCI test. The 5% target is **not** a guarantee about test coverage or safety.

The new training metadata records target validation abstention, validation coverage, uncertain count, and original thresholds. Always report **coverage together with accuracy on decided examples**, plus phishing clearance and legitimate false-alert rates. The score is **not** a calibrated real-world phishing probability.

## Acceptance gates

- Synthetic tests and GitHub CI pass.
- UCI workflow successfully trains v2.1 and publishes a fresh `url_model_meta.json`.
- Verify no increase in confidently wrong decisions relative to v2.0 on the same split. This property follows from expanding the cutoffs but must still be checked for implementation regressions.
- Use a new external, time-separated, independently labelled corpus before claiming real-world production performance. Do **not** repeatedly tune on the old UCI test set.

## Operational caution

An `UNCERTAIN` outcome is not a safe URL. The app must display uncertainty explicitly and should not silently downgrade it to LOW risk.

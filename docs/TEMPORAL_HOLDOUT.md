# Prospective positive-class holdout protocol (registered 2026-10-22)

**Status: registered, not yet executed.** Holdout cutoff **2026-10-23 00:00 UTC**. Both PhishTank `submission_time` and `verification_time` must be at or after the cutoff. Only `verified=yes`, `online=yes` URLs qualify. Require at least **200** previously unseen URLs whose registrable domains are absent from all UCI 967 records; otherwise fail closed with **no metric**. Deduplicate, log exclusion counts, UTC acquisition time and source SHA-256.

Both timestamps must carry explicit UTC, and submission <= verification <= the
single captured evaluation time. Naive, non-UTC, reversed and future timestamps
do not qualify. Both holdout CLIs require an approved manifest and SHA-256 trust
anchor before model loading; see [frozen identity requirements](FROZEN_MODEL_IDENTITY.md).
The workflow pins its same-run build identity before acquiring the feed. This is
not retrospective verification of the historical v2.1 artifact.

Freeze v2.1 training implementation to commit `9a3ced00d98a40773837e0f52aa236c9c1b3c45f`, preserving the existing validation-selected thresholds. Neither model choice nor thresholds may be modified using this prospective data. The October 22 PhishTank/Tranco audits have already been inspected and are **exploratory**, not pristine future test data. A new feed download date alone does not prove record recency.

Only report phishing **detected**, **wrongly cleared**, and **UNCERTAIN** fractions with a positive-only denominator. **Do not report accuracy, precision, specificity or legitimate false-positive rate** from PhishTank alone. Tranco is an unlabeled popularity proxy and must not be used as verified benign ground truth. A separate vetted and dated legitimate URL set is required for a negative-class benchmark.

No phishing URLs are visited, and individual URLs are not exported. Run manually via **Actions → Prospective phishing holdout** when the cutoff has passed and enough post-cutoff verified records exist. The workflow should fail without publishing a score if the threshold is not met. This protocol is not permission to claim production-grade protection.

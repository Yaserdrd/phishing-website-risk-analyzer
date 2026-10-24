# Product quality review and acceptance plan

Reviewed 2026-10-23 against application baseline `374633c`. The current work
builds on PRs #9–#12; `main` was still `b5b5df7` when inspected. Passing development
tests does not establish model quality, safety or production readiness.

## Purpose, users and product boundary

The product helps a person inspect a URL string without opening the target site,
understand lexical/model signals and optionally request bounded live evidence.
The implementation is Python/scikit-learn with a Streamlit UI, local URL/hostname
character TF-IDF + Logistic Regression, selective three-way model decisions,
an additive signal score and optional TLS/RDAP/HTML checks. It uses no generative
AI API, has no token billing and ships no trained model.

The initial user hypothesis is a supervised analyst/education cohort. Public
consumer deployment is a product-direction decision requested from the owner;
it requires additional controls and independent performance evidence. A research
label is not a license to imply that LEGITIMATE or a small score means safe.

## Review across the eight quality areas

| Area | Observed evidence at baseline | Gap / required evidence |
| --- | --- | --- |
| 1. Core correctness | `tests/test_app.py`, `tests/test_network.py`; all 164 tests pass on Python 3.10/3.11/3.12 | Runtime model loader bypasses evaluator integrity gate; malformed metadata can fail inference. Independent real-world quality unverified. |
| 2. Usability and mobile design | `app.py` has a labelled URL input, explicit live-check checkbox, separate model/score metrics and textual notices | Operator paths/training instructions in user flow; no previously recorded real-browser mobile or keyboard evidence. |
| 3. Empty/loading/error/disconnect states | Invalid input is caught; no-model demo exists; network checks have bounded missing-evidence results | Model load happens outside error recovery; inference exceptions beyond ValueError escape; model absence is cached without a file revision key. Explicit empty/loading/retry guidance needs verification. Browser/server disconnect recovery not yet tested. |
| 4. Security and personal data | `network.py` pins public IPs with size/time limits; `.gitignore` excludes secrets; no AI API key requirement | `model.load_model` deserializes before metadata validation. No public-deployment isolation/rate-limit configuration; raw input must not enter error logs or reports. |
| 5. Performance and accessibility | Local inference; network budget 12s; named controls and textual decisions | No representative p95 latency/concurrency measurements, screen-reader audit or comprehensive WCAG evidence; UI tests do not establish any of these. |
| 6. Maintenance and tests | Modules separate URL, ML, evidence and network concerns; three-version CI | Serving and experimental model loading need distinct trust contracts with shared verification logic. Test damaged/mismatched artifacts and recovery as well as happy paths. |
| 7. Setup and publication | README quick start, security/protocol documents, Actions workflows | `PUBLISHING.md` still describes creating an empty repository and pushing directly to main. No reproducible deployment/runbook for a trusted model package. |
| 8. AI failures and cost | No external AI inference service or API spend; selective abstention; external audit records severe alert skew | No external two-class acceptance result, mandatory dual-review input gate or inference resource isolation. Missing/invalid model output must never look like a legitimate prediction. |

## Prioritized acceptance backlog

| Priority / impact | Evidence and problem | Concrete completion criterion | Initial implementation scope |
| --- | --- | --- | --- |
| P0 / misleading decisions | `docs/EXTERNAL_EVALUATION.md`: 1,996/2,000 unlabelled popular roots alerted; no vetted external two-class report | Preregister population-specific alert/miss/coverage criteria before evaluating a fresh blind, evidence-reviewed two-class holdout; publish denominators, uncertainty and exclusions | Remains a release blocker. No training, threshold changes or final-set inspection in this task. |
| P0 / unsafe or broken startup | `app.py` -> `model.load_model` -> joblib before metadata checks; unsupported metadata accepted in the prior audit | Serving verifies an independently approved manifest and exact artifact/environment identity before deserialization, validates model/output contract, and handles missing/partial/corrupt/incompatible packages without a traceback | Implement first; preserve research loader and evaluator protocols. |
| P0 / user-facing failure | Startup is outside try/except; inference only catches ValueError; cached model has no revision key | Empty input gives actionable guidance; loading is visible; model errors disable that prediction and allow explicit URL-only fallback; no exception text/private URL leaks; file/config changes invalidate cached model state | Implement with offline unit/UI regressions. |
| P0 for public exposure / abuse | `SECURITY.md` documents missing deployment egress isolation and global rate limits | Demonstrate isolated network workers, global concurrency/quotas, egress enforcement and secret-safe operational monitoring in the chosen hosting environment, including abuse/load tests | Deployment decision pending; do not declare a public release ready. |
| P1 / invalid scientific evidence | `evaluate_vetted_holdout.load_vetted` accepts a single reviewer ID; review files not mechanically linked to consensus | Evaluator requires verifiable consensus provenance and private output locations; independent evidence/identity audit documented outside code | Separate focused change; no private corpus created here. |
| P1 / non-reproducible releases | Dependency ranges and 7-day training artifact retention; same-run manifest is not a historical trust anchor | Recreate approved source/data/environment identities and retain immutable artifacts + approval records across releases | Separate reproducibility milestone; do not regenerate a trust anchor to bypass mismatches. |
| P1 / usability and accessibility | Raw JSON and operator setup details in default UI; mobile evidence missing | Real-browser 390px and desktop form flows without horizontal overflow; keyboard submission and labelled controls; safe empty/error states. Screen-reader/contrast/disconnect audit tracked separately | Improve first-stage user messages and verify available browser flows; avoid claiming full accessibility compliance. |
| P1 / installation mistakes | `PUBLISHING.md` outdated initial-publication commands | Document clean installation, intentional demo vs blocked model states, trusted operator configuration, smoke checks, recovery and release gates without direct main pushes | Update operator runbook with serving change. |

## Verification limits and staged reporting

Baseline: 164 tests passed on each of Python 3.10.22, 3.11.17 and 3.12.14. Source
and documentation inspection and the prior synthetic reproduction support the
findings. Current PR/remote main state was checked read-only. No real phishing
URL, external feed, model training or private data was used in this review.

The first delivery addresses trusted serving and recoverable UI states. Record
its exact checks below when completed; remaining backlog items must stay open.
Public hosting, real-world model acceptance, screen-reader behavior, representative
performance/load, full disconnect recovery and API key/vault configuration are
not established by unit/AppTest checks.

## First delivery: trusted serving and recoverable states

Implemented on `feature/trusted-serving-and-recovery`:

- `serving.load_app_model` uses shared manifest/artifact/environment verification
  before unpickling and validates the estimator and finite normalized two-class
  output contract at startup and each prediction. The UCI corpus is not copied
  into serving; evaluation still requires it. Model/metadata file-size prechecks
  are not CPU/decompression/process isolation.
- Missing unconfigured installation is intentional demo. Configured missing,
  partial, unapproved, mismatched and corrupt packages disable model predictions
  with a recoverable notice. They never become a LEGITIMATE decision.
- Model file revisions and approved configuration participate in cache keys.
  Installing/replacing files takes effect on the next rerun; operator environment
  changes require a service restart. No silent training or artifact approval.
- Empty input gets guidance; model checking/analysis have loading indicators;
  invalid model output/exceptions cause explicit URL-only fallback; other analysis
  failures give retry guidance without a verdict. Opted-in live checks run once
  on model fallback. Fixed event codes exclude raw error/URL/path text.
- Operator-only file/training details were removed from ordinary user messages.
  `PUBLISHING.md` now documents serving states, approval, recovery and release
  gates rather than creating a new repository and pushing to main.

Verification results:

| Check | Observed outcome |
| --- | --- |
| Python 3.10.22 / 3.11.17 / 3.12.14 | 191 tests passed on each, up from 164; compileall and pip check passed on all three |
| Guard regressions | Invalid identity rejected before unpickling; safe temporary fake packages exercise valid/corrupt/wrong-contract cases; evaluator cannot omit UCI verification |
| UI regressions | Empty/error/demo and all ML labels; cache invalidation; sanitized failures; fallback does not duplicate network checks |
| Chromium 154.0.8037.57, 390×844 and 1440×1000 | Empty and invalid input handled, labelled textbox usable, Enter submits valid reserved URL, expected UNAVAILABLE / 8-of-100 demo metrics, no horizontal document overflow; mobile result container also checked |
| Local service interruption | Visible connection notice after stopping the owned test service; after restart and explicit browser reload the form recovered without a stale result |
| Scope safety | External browser requests blocked; live checkbox remained off; no submitted/feed URL, model training, external AI API or private data used |

The loading indicators are implemented; their timing under real inference/network
load was not measured. Mobile checks are browser viewports, not physical iOS/
Android devices. Automatic reconnect/session restoration, full keyboard traversal,
screen-reader/contrast compliance, Windows/macOS setup, production hosting and
representative latency/concurrency remain unverified. A real approved v2.1 serving
artifact was not loaded; model checks used safe fake artifacts. Remaining scientific,
review-provenance, reproducibility and public-exposure acceptance gates stay open.

## Subsequent delivery: mandatory review provenance

PRs #9–#13 have since been merged into `main` at `4647825`; that merged
commit passed the three-version CI. The next focused change addresses the
review-provenance acceptance item above:

- The vetted evaluation CLI requires original private reviews and a digest
  approved independently before scoring, recomputes two-reviewer consensus,
  and matches the exact vetted bytes before loading/scoring the model.
- The verified buffers are used directly. A fabricated joined reviewer field,
  single reviewer, disagreement or modified accepted CSV cannot substitute
  for the approved individual records. Reports include aggregate provenance.
- Review inputs and private CSV outputs reject checkout/symlink destinations;
  outputs are exclusively created and cannot overwrite inputs or prior files.
- This gate does not prove evidence truth, authenticate reviewers, collect a
  real corpus or establish model performance. External approval and independent
  evidence checks remain necessary. No training/threshold/UI change is included.

The prior 191-test baseline is retained at the unchanged merged commit; a fresh
pre-edit Python 3.12 run also passed 191 tests. Regression tests cover approved
end-to-end CLI output, missing/wrong approval, changed review/CSV bytes, single
reviews, disputes, early failure before model loading, private paths/symlinks,
and overwrite prevention. Three-version final results are recorded in project status.

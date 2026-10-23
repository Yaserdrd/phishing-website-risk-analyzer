# Project status and technical roadmap

Last reviewed: **2026-10-23**. Application baseline:
`b5b5df71ae39ca3b3d2c213dfab93d4f12a0fb20` is the audited baseline. The subsequent
`feature/model-decision-presentation` change separates UI decisions from scores
as described below. Model implementation and thresholds remain **v2.1.0**.

**Development prototype; not accepted for production website safety decisions.**
The environment supports development and testing. This does not establish
real-world detection quality or deployment security. See [agent instructions](../AGENTS.md).

PRs #9–#13 were merged in order into `main` at `4647825` on 2026-10-23.
The merged tree equals the tested `12ee238` delivery. All 191 tests, source
compilation and pip check passed locally on Python 3.10/3.11/3.12; the
[merged-main CI](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39996330597)
also passed all three versions. That completed integration acceptance; no model
training, threshold changes or production deployment occurred.

The subsequent `feature/trusted-serving-and-recovery` delivery implements a
verified serving entry point, guarded probability contract and recoverable UI
states. It does not retrain/change v2.1, approve a real model artifact or remove
external-validation/deployment blockers. See the eight-area
[product quality review and acceptance plan](PRODUCT_QUALITY_REVIEW.md).

## Architecture and implemented capabilities

| Component | Responsibility | Current boundary |
| --- | --- | --- |
| `app.py` | Streamlit input, results, warnings | Separate decision/score; missing/blocked/verified model states, empty/loading/retry guidance and explicit inference fallback; live checks off by default |
| `src/phishing_analyzer/urls.py` | Normalization, validation, registrable-domain grouping | Shared train/inference normalization; bundled offline PSL |
| `src/phishing_analyzer/model.py` | URL/hostname character TF-IDF + Logistic Regression | Exact binary labels checked before conversion; fit/split/threshold algorithms unchanged |
| `src/phishing_analyzer/serving.py` | Approved serving package and inference output contract | Missing installation is demo; invalid/configured-missing package blocks predictions; trusted manifest required before unpickling |
| `src/phishing_analyzer/protocol.py`, `provenance.py` | Shared UTC policy and frozen artifact verification | Approved manifest trust anchor required; a digest does not authenticate its supplier |
| `src/phishing_analyzer/analyzer.py` | Combine ML, heuristics, optional checks | Legacy `risk_level` retained for callers as a score band; UI does not present it as a verdict |
| `src/phishing_analyzer/security.py` | Lexical, TLS, RDAP, bounded HTML signals | Opt-in network code; hardening gaps listed below |
| `src/phishing_analyzer/network.py` | Public-IP-pinned transport, resource bounds and shared deadlines | Direct sockets; no RDAP redirects; bounded DNS workers may outlive caller timeouts |
| `scripts/evaluate_external.py` | Separate-source audit and paired URL/root diagnostics | Exploratory; no inherited ground truth for synthetic roots |
| `scripts/prospective_holdout.py` | Post-cutoff positive-only evaluation | Explicit UTC/order/current-time filtering and pre-unpickle identity gate |
| `scripts/evaluate_vetted_holdout.py` | Evidence-reviewed two-class evaluation | Requires approved original review bytes and recomputed consensus before loading/scoring; evidence truth remains a human responsibility |
| `scripts/review_consensus.py` | Offline two-reviewer agreement | Distinct IDs and agreement cannot prove actual independence |
| `notebooks/experiments.ipynb` | Historical UCI 327 numeric-feature experiments | Separate from the UCI 967 URL application |

## Evidence register

| Evidence | What it supports | What it does not establish |
| --- | --- | --- |
| [v2.1 UCI report](VERIFIED_RESULTS_V21_2026-10-21.md), [JSON](../reports/uci_phiusiil_selective_v21_2026-10-21.json), [recorded run](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39684966827) | Recorded domain-disjoint UCI benchmark: 51,690 test URLs, 96.067% coverage and 99.074% accuracy among decided URLs; 1.484% legitimate false alerts and 0.239% phishing false clears, with respective true-class denominators | Fresh external performance, calibrated probability, or protection guarantees |
| [External audit](EXTERNAL_EVALUATION.md), [v1 JSON](../reports/external_audit_v1_2026-10-22.json), [recorded run](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/39792461394) | 1,982/2,000 feed-confirmed phishing URLs alerted; 1,996/2,000 unverified popular-domain roots alerted, indicating severe distribution skew | Tranco false-positive rate, combined accuracy, or unbiased population estimates |
| Paired URL/root diagnostic implementation and synthetic tests | Tooling for same-source input-shape comparisons | A new real-data result from this documentation task |
| [Prospective protocol](TEMPORAL_HOLDOUT.md) | Registered cutoff and positive-only evaluation tooling | A completed prospective benchmark |
| [Vetted holdout](VETTED_TWO_CLASS_HOLDOUT.md), [dual review](INDEPENDENT_REVIEW_PROTOCOL.md) | Evidence schemas, adjudication tooling and synthetic tests | A collected, independently verified two-class corpus |

These are repository-recorded historical results, not models retrained or remote
workflow runs reverified during this documentation update. UCI v2.0/v2.1 reuse
the same test split; further model selection needs new untouched final data.
October 22 external snapshots have been inspected and are exploratory. Tranco
popularity is not a legitimate label. Model scores are not calibrated probabilities.

No trained pickle is committed. The historical model artifact has short retention;
the linked report records its identity, but long-term availability is not assured.
Do not retrieve and deserialize an arbitrary replacement model.

## Validation baseline

The October 22 audit ran **63 passing tests on each of Python 3.10.22, 3.11.17,
and 3.12.14**, plus successful `pip check` and source compilation on each version.
Streamlit demo/form submission and saved UCI report consistency checks passed.
The October 23 documentation change reran **63 tests successfully on each of
the same three Python versions**, with successful compilation and `pip check`.
Its pre-change Python 3.12 run also passed all 63 tests. Local Markdown links
resolve and `git diff --check` passes. The configured
[CI matrix](../.github/workflows/tests.yml) alone is not evidence of remote success.

Tests include temporary synthetic training and mocked evaluation, not a full UCI
rerun. They do not cover every network boundary or all known defects below.
No feed download, live phishing visit, final holdout evaluation, model update,
or threshold change was performed for the governance, UI or integrity changes.

The P0 integrity change started with **71 passing tests on each of Python
3.10.22, 3.11.17 and 3.12.14**. Afterwards **117 tests passed on each version**;
source compilation and `pip check` passed on all three. New offline tests cover
pre-unpickle rejection, altered model/metadata/UCI/manifest bytes, environment
mismatch, fixed source/clean-checkout guards, digest-required CLI calls, aggregate
CLI outputs, UTC boundaries and exact label handling. CLI help entry points and
local documentation links were checked. Workflow YAML parsed successfully and
the identity-pin step precedes feed acquisition; the remote workflow was not run.
Tests use temporary safe fake artifacts, not a real frozen v2.1 artifact.

The live-network hardening change started with **117 passing tests on each of
Python 3.10.22, 3.11.17 and 3.12.14**. Afterwards **164 tests passed on each
version**, with successful source compilation and `pip check`. New tests use
fake DNS/sockets/TLS/responses and clocks to cover SSRF redirects, IP pinning,
certificate failures, bounded DNS capacity, slow headers/body/chunk framing,
size/framing failures, socket cleanup, RDAP restrictions and shared budgets.
No real submitted/feed URL or RDAP endpoint was contacted. These are application
regressions, not a penetration test or deployment acceptance result.

Trusted serving/recovery started with 164 passing tests per Python version and
finished with **191 passing tests on each of Python 3.10.22, 3.11.17 and 3.12.14**;
compileall and pip check passed on all three. Shared verification still requires
the UCI CSV for evaluators while the serving UI needs only approved model/metadata
and manifest. Serving validates estimator/output shape, finite values and binary
probability sums. Package and prediction failures produce explicit unavailable/
demo states without raw error text or duplicate live checks. Cache revisions
detect package installation/replacement on rerun. Chromium mobile/desktop form
checks and explicit reload after a local server restart passed; full accessibility,
automatic reconnect, production performance and real-model acceptance remain open.
See the [quality review](PRODUCT_QUALITY_REVIEW.md) and [operator runbook](../PUBLISHING.md).

## Decision presentation change

The UI shows `Model decision` (PHISHING / UNCERTAIN / LEGITIMATE / UNAVAILABLE)
and `Combined signal score` as separate metrics. It removes the generic risk-level
metric rather than inflating scores or altering thresholds to force agreement.
PHISHING has an explicit warning, UNCERTAIN explains abstention, LEGITIMATE is
qualified as unverified, and model absence cannot look like a legitimate verdict.
Scores and threshold values are displayed as scores, not percentage probabilities.

The additive calculation and legacy `risk_level` response field are unchanged.
Python clients must treat that field as a score band, not a model decision or
safety conclusion. Migration of that legacy API is outside this UI fix.
Offline AppTest regressions exercise all model decisions, both exact threshold
boundaries, no-model mode, other signals with a LEGITIMATE prediction, and invalid
input. Models are fake, resource caches are isolated, and network/live checks
are blocked. This verifies presentation, not predictive quality.

Validation: pre-change suites passed 63 tests on each of Python 3.10.22, 3.11.17
and 3.12.14. After the UI change, **71 tests passed on each version**, including
eight AppTest cases; compilation and `pip check` passed on all three. The five
parameterized decision/threshold regressions fail against the original audited
UI and pass with this change. No model/data/threshold code was changed.

## Open risk register

R1's UI fix, R3/R4 input validation, R2's per-build identity gate and R5's
application transport hardening are implemented.
Historical artifact identity and broader reproducibility remain unverified.
Behavioral reproductions used offline synthetic inputs; network findings are
code-review observations.

| ID / priority | Finding and evidence | Required acceptance check |
| --- | --- | --- |
| R1 / P0, UI resolved | Legacy score bands can differ from model decisions; passive maximum 55 cannot reach HIGH. UI now shows model decisions with explicit notices and separate signal scores, without a generic risk verdict. | Offline UI regressions cover all decisions, missing model and threshold boundaries. Legacy Python score-band compatibility remains documented; no threshold changes. |
| R2 / P0, integrity gate implemented | Both CLIs now require an approved manifest digest, bind model/metadata/UCI bytes and runtime/PSL identity before unpickling, and record actual evaluator code hashes. The workflow pins the same-run build before feed acquisition. | Offline tampering/CLI tests pass. This does not authenticate a self-supplied manifest or establish identity with a historical model; preserve a trusted approved manifest/environment for cross-run claims. |
| R3 / P0, resolved | Shared UTC parser and cutoff <= observation/submission <= verification <= captured evaluation time rule used by both evaluators and review consensus. Invalid feed records cannot satisfy minimum counts. | Fixed-clock tests cover naive/non-UTC, future, reversed, cutoff and evaluation-time boundaries. |
| R4 / P0, resolved | CSV labels are checked with exact decimal semantics before integer conversion; fractions, infinities, underflow and near-integer rounding are rejected. | Invalid-label and valid binary cleaning tests pass; fitting, splitting and thresholds are unchanged. |
| R5 / P1, transport implemented; deployment controls pending | Shared 12-second network budget, bounded DNS wait/capacity, public-unicast pinning, revalidated HTML redirects with no HTTPS downgrade, bounded identity-only responses, and fixed RDAP endpoint without redirects. Missing network evidence adds no risk. | Offline adversarial tests cover redirect/SSRF, pinning/TLS, slow headers/body/chunks, wire/body bounds and cleanup. Registry redirects now leave age unavailable. External egress isolation, rate limits and deployment validation remain required. |
| R6 / P1, software gate implemented | Evaluator requires approved raw review digest, recomputes dual-review consensus and compares exact vetted bytes before model loading/scoring. Private review/CSV paths reject checkout and symlink destinations; outputs refuse overwrite. | Offline tampering, single-review, dispute, private-path and CLI regressions; real independent identity/evidence approval and corpus collection remain required. Digests do not authenticate reviewers. |
| R7 / P1 | Dependency ranges, changing feeds/PSL and short-lived artifacts limit repeatability. Some older documents contain pre-verification status text. | Reproducible dependency resolution and experiment manifests; reconcile status with durable aggregate evidence. |

The subsequent `feature/enforced-review-provenance` change implements R6's
software gate. The vetted evaluator requires `--reviews` and an independently
approved `--reviews-sha256`, recomputes consensus from the verified original
bytes, and compares the exact generated CSV before model loading/scoring.
Its v2 aggregate report records review/consensus provenance without reviewer IDs,
evidence references or URLs. Private CSV paths are rejected inside the checkout
and resolved symlink targets; existing outputs are not overwritten. This is a
storage-mistake guard, not a hostile-filesystem sandbox or reviewer authentication.
Human evidence approval, blind real-corpus collection and external final
evaluation remain open. No real review corpus or final model experiment was used.

R6 validation: the unchanged merged baseline already passed 191 tests on all
three Python versions locally and in CI; a fresh pre-edit Python 3.12 run passed
191 tests. After this change, **211 tests passed on each of Python 3.10.22,
3.11.17 and 3.12.14**, with successful compileall and pip check on each.
The 20 added offline regressions cover approved aggregate output, missing or
changed approval, review/CSV tampering, joined/single reviewer bypasses,
disagreement, minimum sample gates before model loading, private checkout and
symlink paths, and overwrite refusal. Both CLI help entry points passed.
Existing UI/network/model regressions remain green; no fresh browser session
was needed because their implementation was unchanged.

Domain-level conflicting-label exclusion can remove genuinely compromised paths
on otherwise legitimate domains. Report that selection bias, source-order sampling,
review disagreements, domain clustering and class prevalence in future studies.

## Prospective evaluation state

The cutoff remains **2026-10-23 00:00 UTC** (03:00 Europe/Istanbul). Calendar
eligibility does not establish enough qualifying samples or authorize repeated
inspection/tuning of the final set. No completed prospective or vetted two-class
report is recorded in the current checkout.

Keep raw URLs and review evidence outside Git, blind reviewers to model scores,
verify evidence independently, and supply a trusted approved manifest/environment
through the R2 gate before a frozen positive holdout run. The gate does not
retrospectively approve historical artifacts. R6 now enforces review-byte approval
and recomputed agreement in the evaluation CLI, not human identity or label truth.
Minimum counts are engineering gates, not statistical confidence guarantees.

## Ordered delivery plan

Each item is a focused feature branch and PR, with a baseline test run, regression
tests where behavior changes, and Python 3.10/3.11/3.12 checks.

1. **P0: governance and status (this documentation change).** Add `AGENTS.md`
   and this evidence/risk register; reconcile stale evaluation status text.
   No application or experiment behavior changes.
2. **P0: decision presentation (R1), implemented.** Separate model decision,
   signal score, uncertainty and model absence; verify rendered Streamlit results
   with fake models and no network. Model parameters and thresholds are preserved.
3. **P0: evaluation integrity (R2/R3/R4), implemented with explicit trust limits.**
   Require approved experiment identities before model loading, shared strict
   temporal validation and exact label checks. The registered cutoff and final
   data remain untouched. See [frozen identity](FROZEN_MODEL_IDENTITY.md);
   historical artifact approval and cross-run reproducibility are not claimed.
4. **P1: network hardening (R5), application layer implemented.** Deterministic
   tests and bounded public-IP-pinned transport cover opt-in live checks. See
   [security notes](../SECURITY.md) for RDAP availability, DNS cancellation,
   direct-socket and deployment-isolation limitations. No live site was visited.
5. **P1: reproducibility (R7).** Record dependency, PSL, source and artifact
   identities; version report schemas and preserve aggregate evidence durably.
6. **P1: reviewed holdout process (R6), software gate implemented.** Approved
   review bytes, recomputed consensus and private-path checks are enforced;
   collect and verify data under a blind, preregistered protocol, then
   conduct a separately scoped final evaluation without tuning on its outcomes.
7. **P2: next model research.** Investigate input-shape, source and temporal
   shift on separate development/validation corpora. Pre-register hypotheses
   and acceptance criteria; reserve a fresh final holdout for any new claims.

## Maintaining this record

For each material change, record its commit/PR, test evidence, experiment inputs
and status, resolved risks and remaining limitations. Distinguish local tests,
remote CI, historical reports and fresh experiments. Never promote planned work
or a passing test suite into a production-readiness or performance claim.

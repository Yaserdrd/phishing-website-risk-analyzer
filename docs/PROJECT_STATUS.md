# Project status and technical roadmap

Last reviewed: **2026-10-23**. Application baseline:
`b5b5df71ae39ca3b3d2c213dfab93d4f12a0fb20`. This documentation update does not
change that application baseline. Model implementation: **v2.1.0**.

**Development prototype; not accepted for production website safety decisions.**
The environment supports development and testing. This does not establish
real-world detection quality or deployment security. See [agent instructions](../AGENTS.md).

## Architecture and implemented capabilities

| Component | Responsibility | Current boundary |
| --- | --- | --- |
| `app.py` | Streamlit input, results, warnings | Heuristic demo without a trusted local model; live checks off by default |
| `src/phishing_analyzer/urls.py` | Normalization, validation, registrable-domain grouping | Shared train/inference normalization; bundled offline PSL |
| `src/phishing_analyzer/model.py` | URL/hostname character TF-IDF + Logistic Regression | Domain-disjoint fit/validation/test; validation-only selective thresholds |
| `src/phishing_analyzer/analyzer.py` | Combine ML, heuristics, optional checks | Combined score and ML decisions currently have conflicting semantics |
| `src/phishing_analyzer/security.py` | Lexical, TLS, RDAP, bounded HTML signals | Opt-in network code; hardening gaps listed below |
| `scripts/evaluate_external.py` | Separate-source audit and paired URL/root diagnostics | Exploratory; no inherited ground truth for synthetic roots |
| `scripts/prospective_holdout.py` | Post-cutoff positive-only evaluation | Protocol implemented; timestamp/provenance gaps remain |
| `scripts/evaluate_vetted_holdout.py` | Evidence-reviewed two-class evaluation | Metadata validation does not verify evidence truth or mandatory dual review |
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
or threshold change was performed for this documentation task.

## Open risk register

These are open findings, not completed fixes. Behavioral reproductions used
offline synthetic inputs; network findings are code-review observations.

| ID / priority | Finding and evidence | Required acceptance check |
| --- | --- | --- |
| R1 / P0 | `analyzer.py` and `model.predict`: a synthetic PHISHING decision can accompany 25/100 LOW; passive maximum 55 cannot reach HIGH. UNCERTAIN can also accompany LOW. | Define coherent presentation semantics; cover all ML outcomes and missing model without changing v2.1 thresholds. |
| R2 / P0 | Holdout CLIs check version `2.1.0` and write a fixed training commit without verifying model identity. Frozen source checkout does not freeze dependencies or dataset bytes. | Verify trusted model/metadata/data/code identities and record the actual environment before claiming frozen evaluation. |
| R3 / P0 | `prospective_holdout.date_utc/select_phishing` accepts naive timestamps, future records and reversed submission/verification ordering. | Require explicit UTC and cutoff <= submission <= verification <= evaluation time; test boundaries deterministically. |
| R4 / P0 | `model.load_csv` casts labels to int before checking membership; synthetic 0.5/1.5 become 0/1. | Reject non-binary labels before lossy conversion; retain valid cleaning behavior. |
| R5 / P1, deployment blocker | RDAP follows redirects outside the pinned HTML/TLS path. Per-socket timeouts do not bound total operation time. Redirect, pinning, body and TLS tests are incomplete. | Mocked adversarial tests; explicit destination policy, response bounds and overall deadlines; external egress isolation before deployment. |
| R6 / P1, evaluation prerequisite | Evaluator accepts nonempty single reviewer IDs; consensus output is not a mandatory input gate. Private output location is a documented convention. | Bind evaluation to reviewed consensus provenance and prevent private outputs in the checkout; retain independent human evidence verification. |
| R7 / P1 | Dependency ranges, changing feeds/PSL and short-lived artifacts limit repeatability. Some older documents contain pre-verification status text. | Reproducible dependency resolution and experiment manifests; reconcile status with durable aggregate evidence. |

Domain-level conflicting-label exclusion can remove genuinely compromised paths
on otherwise legitimate domains. Report that selection bias, source-order sampling,
review disagreements, domain clustering and class prevalence in future studies.

## Prospective evaluation state

The cutoff remains **2026-10-23 00:00 UTC** (03:00 Europe/Istanbul). Calendar
eligibility does not establish enough qualifying samples or authorize repeated
inspection/tuning of the final set. No completed prospective or vetted two-class
report is recorded in the current checkout.

Keep raw URLs and review evidence outside Git, blind reviewers to model scores,
verify evidence independently, and fix R2/R3 before relying on a frozen positive
holdout claim. Resolve R6 before claiming an enforced dual-review evaluation.
Minimum counts are engineering gates, not statistical confidence guarantees.

## Ordered delivery plan

Each item is a focused feature branch and PR, with a baseline test run, regression
tests where behavior changes, and Python 3.10/3.11/3.12 checks.

1. **P0: governance and status (this documentation change).** Add `AGENTS.md`
   and this evidence/risk register; reconcile stale evaluation status text.
   No application or experiment behavior changes.
2. **P0: decision presentation (R1).** Separate model decision, heuristic score,
   uncertainty and missing evidence clearly; verify rendered Streamlit results
   with fake models and no network. Preserve model parameters and thresholds.
3. **P0: evaluation integrity (R2/R3/R4).** Introduce verified experiment
   identities, strict temporal validation and lossless label checks. Preserve
   the registered cutoff and keep independent final data untouched.
4. **P1: network hardening (R5).** Add deterministic tests and bounded,
   policy-controlled network adapters. Document deployment isolation requirements.
5. **P1: reproducibility (R7).** Record dependency, PSL, source and artifact
   identities; version report schemas and preserve aggregate evidence durably.
6. **P1: reviewed holdout process (R6).** Enforce consensus provenance and private
   outputs; collect and verify data under a blind, preregistered protocol, then
   conduct a separately scoped final evaluation without tuning on its outcomes.
7. **P2: next model research.** Investigate input-shape, source and temporal
   shift on separate development/validation corpora. Pre-register hypotheses
   and acceptance criteria; reserve a fresh final holdout for any new claims.

## Maintaining this record

For each material change, record its commit/PR, test evidence, experiment inputs
and status, resolved risks and remaining limitations. Distinguish local tests,
remote CI, historical reports and fresh experiments. Never promote planned work
or a passing test suite into a production-readiness or performance claim.

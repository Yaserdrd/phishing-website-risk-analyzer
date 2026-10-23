# Contributor and agent instructions

## Purpose and evidence

This is an educational AI/cybersecurity research prototype, not a website safety
authority. Read `README.md`, `SECURITY.md`, `docs/PROJECT_STATUS.md`, and the
documentation for the affected component before changing it. Inspect current
code and tests; distinguish implemented tools from experiments actually run.

- Never claim predictive performance without a traceable completed evaluation.
  Report selective accuracy together with coverage and explicit denominators.
- `PHISHING`, `UNCERTAIN`, and `LEGITIMATE` are model decisions, not safety
  guarantees. Model scores and the combined heuristic score are not calibrated
  real-world probabilities.
- UCI 327 notebook results do not describe the UCI 967 URL-text application.
  Tranco popularity is not verified legitimate ground truth. Positive-only
  PhishTank results cannot establish accuracy, precision, or false-positive rate.

## Change workflow

1. Inspect Git status and preserve existing user changes. Read affected source,
   tests, manifests, workflows, and documentation before editing.
2. Run the existing tests before changes and record failures before proceeding.
3. Use a focused `feature/*` branch and a pull request targeting `main`. Never
   commit directly to `main`, force-push shared history, or merge without the
   user's instruction. Each cloud task is already isolated; use the existing
   checkout and do not create a worktree unless explicitly requested.
4. Keep each PR reviewable. Add regression tests for changed behavior and keep
   documentation consistent with the final implementation.
5. After changes, check Python 3.10, 3.11, and 3.12. Report unavailable or failed
   checks explicitly; a configured CI matrix is not evidence that it passed.
6. Before committing, inspect the diff and untracked files for private data,
   generated datasets, model artifacts, credentials, and unintended changes.

## Development and validation

Use Python 3.10–3.12 and an isolated virtual environment. From the repository root:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q src app.py scripts
.venv/bin/python -m pip check
```

Use the corresponding interpreter/environment for each matrix version. Match
`.github/workflows/tests.yml`; do not overwrite a working environment merely to
test another version. Existing tests train small synthetic models in temporary
directories; they do not establish real-world predictive performance.

For UI changes, exercise Streamlit form submission with
`streamlit.testing.v1.AppTest`, including model absence and all three model
decisions as applicable. Keep live checks disabled and mock network boundaries.
The application starts with `.venv/bin/python -m streamlit run app.py
--server.headless=true --browser.gatherUsageStats=false` from the repository root.
Without trusted local model artifacts it intentionally uses heuristic-only demo
mode. Check exceptions and expected rendered behavior, not just an open port.

## Experimental boundaries

- Do not change v2.1 training, model artifacts, decision thresholds, or the
  preregistered cutoff as a side effect of maintenance or UI changes. Such work
  requires an explicitly scoped experiment and separate review.
- Never use independent final test data to choose models, features, thresholds,
  calibration, or acceptance criteria. Inspected external snapshots are
  exploratory; reserve fresh untouched data for subsequent final claims.
- Preserve domain-disjoint fit/validation/test splits and fit transformations
  only on fit data. Select thresholds on validation only. Do not refit after
  selecting thresholds or inherit labels for synthetic root URLs.
- Preserve the prospective cutoff `2026-10-23T00:00:00Z`. Its arrival does not
  establish sample eligibility or authorize an unplanned final evaluation.
- Follow `docs/TEMPORAL_HOLDOUT.md`, `docs/VETTED_TWO_CLASS_HOLDOUT.md`, and
  `docs/INDEPENDENT_REVIEW_PROTOCOL.md`. Keep reviewers blind to predictions;
  verify evidence outside the schema checker. Distinct IDs alone do not prove
  reviewer independence or label truth.
- Record source/code/model/data identities, dependency versions, selection and
  exclusion counts, UTC timestamps, limitations, and exact metric denominators.
  Clearly identify provenance checks that the current code does not enforce.

## Security and privacy

- Do not visit phishing URLs or enable live checks during routine development.
  Use offline fixtures, synthetic reserved domains, and mocked DNS/HTTP/TLS.
- Never commit personal data, secrets, raw review records, private URL lists,
  evidence registers, or trained model files. Keep sensitive corpora outside the
  checkout; `.gitignore` is not a security boundary. Publish aggregates only
  after checking small cohorts and identifiers for disclosure risk.
- Load pickle/joblib files only from trusted training processes. Verify artifact
  provenance before deserialization; a version string is not an integrity check.
- Preserve TLS verification, URL validation, public-IP pinning, redirect checks,
  and resource bounds. Do not disable safeguards to make a test or download pass.
- Network failures represent missing evidence, not proof of maliciousness.
  Public deployment requires separate egress controls, isolation, request budgets,
  and abuse prevention; passing unit tests does not establish deployment safety.

## PR completion report

Describe the problem, resulting behavior, scope, and relevant risks. Include
before/after test outcomes for all three Python versions, any UI checks,
experiments deliberately not run, and remaining blockers. Update
`docs/PROJECT_STATUS.md` when a capability, risk, evidence source, or roadmap
milestone materially changes. Never mark a planned fix as completed.

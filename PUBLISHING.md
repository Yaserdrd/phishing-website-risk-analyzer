# Operator setup, model approval and release gates

The repository already exists. Use feature branches and reviewed PRs; do not
reinitialize Git, push directly to `main`, or merge automatically. A successful
test run is not approval to deploy a phishing safety product.

## Supported local workflow

Use Python 3.10, 3.11 or 3.12 and an isolated environment from the checkout root:

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH=src .venv/bin/python -m pytest -q
.venv/bin/python -m pip check
.venv/bin/python -m streamlit run app.py --server.headless=true --browser.gatherUsageStats=false
```

On Windows use `.venv\Scripts\python.exe`. For verified Linux x86_64 dependency
installation, use the [hash-locked environments](docs/REPRODUCIBLE_ENVIRONMENTS.md)
instead of the flexible range-based example above. OS/image and historical
artifact reproducibility remain open. Live checks stay off during smoke testing.

## Three model states

| State | Observable behavior | Operator action |
| --- | --- | --- |
| Intentional demo | No model, metadata or manifest installed and no explicit serving configuration; UI says heuristic-only demo, model decision UNAVAILABLE | Appropriate for exploring URL-only behavior; never represent it as model protection |
| Verified model | Approved manifest/artifact/environment checks and model-output contract pass; UI says model package verified | This establishes package identity/compatibility, not real-world label accuracy |
| Blocked model | Partial, missing explicitly configured, corrupt, incompatible or unapproved package; UI explains predictions are disabled and permits explicit URL-only checks | Fix the trusted deployment package/configuration; do not bypass checks or relabel it legitimate |

## Approved v2.1 serving package

Follow [frozen model identity](docs/FROZEN_MODEL_IDENTITY.md) to obtain the exact
trusted model pickle, metadata, manifest and independently approved manifest
SHA-256 from a reviewed build. Copying an unknown pickle and computing its hash
does not establish trust. The existing helper requires the registered clean
frozen training source; a newly trained arbitrary local model is not automatically
an approved v2.1 serving package. No model is silently trained or downloaded.

Configure these operator-controlled environment variables in the service manager
or environment settings, never via user input or an upload endpoint:

| Variable | Meaning |
| --- | --- |
| `PHISHING_MODEL_DIR` | Directory containing `url_phishing_model.pkl` and `url_model_meta.json`; default is checkout `models/` |
| `PHISHING_MODEL_MANIFEST` | Approved manifest file; default is `frozen_manifest.json` within that directory |
| `PHISHING_MODEL_MANIFEST_SHA256` | Independently approved lowercase SHA-256 trust anchor; required whenever a model package is present |

The digest is not a secret, but its approval/integrity matters. Keep files
read-only to the serving identity and preserve an immutable approved release.
Use the matching Python/platform/distribution/PSL environment recorded in the
manifest; do not regenerate the digest to suppress an environment mismatch.
Serving does not require the private/original training CSV at runtime. Its hash
remains recorded in the approved manifest; evaluators still verify the CSV itself.

Serving verifies metadata before unpickling, loads the exact verified model
buffer, and checks the two-class estimator/probability contract using a reserved
offline URL. File-size prechecks reject models over 256 MiB or metadata over 1 MiB.
These are not decompression, CPU or process-memory isolation guarantees. A trusted
pickle can still execute Python; ownership and approval remain prerequisites.

## Smoke checks and recovery

For retaining approved packages, offline smoke, atomic shell configuration and
rollback, follow the [model release lifecycle](docs/MODEL_RELEASE_LIFECYCLE.md).
These operator tools preserve package bytes and do not approve or retrain models.
The historical ZIP has been verified and retained in a draft archive with
read-back checks. Real-package serving acceptance still needs independently
approved build/environment evidence; no package is silently promoted.

- Check Streamlit's local `/_stcore/health` endpoint, then submit a reserved URL
  such as `https://example.org/login` with live checks off. A healthy HTTP endpoint
  alone does not establish model availability. In intentional demo expect model
  decision UNAVAILABLE and combined signal score 8 / 100.
- Confirm empty/invalid input gives guidance without a verdict. Confirm the
  missing/blocked model state is visible; an UNAVAILABLE result is not legitimate.
- A model inference exception or invalid output produces no ML decision and an
  explicit URL-only fallback. Opted-in live checks are not duplicated on fallback.
  Unexpected analysis failures produce retry guidance without a score or verdict.
- The application logs fixed diagnostic event codes, not raw prediction errors,
  URL strings or deployment paths. Investigate packages in an access-controlled
  operator environment. Do not put private values into issue bodies or public logs.
- File install/removal/replacement changes the model cache key on the next rerun
  or refresh. Restart the service after changing environment configuration.
  Deploy matching files as one immutable package; a partial update is blocked.
- To return deliberately to demo, use a clean checkout without model artifacts
  and without the three serving variables. Preserve/archive existing operator
  files securely; do not delete or overwrite an approved release blindly.

The UI stores form/session state in the running application/browser; the repo
adds no scan-history database. This does not establish a universal retention
guarantee: inspect hosting/proxy/browser logs and session policies before handling
private data. Do not submit passwords, access tokens or confidential links.

## Before a real-user release

Apply the acceptance criteria in [product quality review](docs/PRODUCT_QUALITY_REVIEW.md)
and [project status](docs/PROJECT_STATUS.md). In particular:

1. Complete fresh, blind, evidence-reviewed external evaluation against criteria
   chosen before inspection. Current Tranco diagnostics are not benign ground truth.
2. Enforce reviewer provenance, immutable approved artifacts and reproducible
   environment/data identities. Retain rollback packages and approval records.
3. For public exposure, demonstrate service/egress isolation, global quotas and
   concurrency bounds, abuse monitoring and secure operator configuration. The
   application network budget is not a deployment-wide rate limit.
4. Test the chosen host under representative load, model failures, browser/server
   disconnections, keyboard/screen-reader use and actual mobile devices. Browser
   viewport tests alone do not establish complete accessibility or reliability.
5. Confirm all three Python CI jobs and relevant functional checks on the exact
   release commit. Review dependent PRs in order; do not infer release approval
   from an open PR's green check alone.

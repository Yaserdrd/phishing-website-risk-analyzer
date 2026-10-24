# Candidate build evidence and historical compatibility

The historical archive is intact, but does not contain the original complete
runtime/data/approval manifest. Evidence recovered later must not be relabelled
as contemporaneous independent approval.

## Historical evidence recovered on 2026-10-24

The job-specific logs endpoint for run `39684966827`, job `119516573760`, worked.
Logs identify CPython **3.11.17**, Ubuntu 24.04 and 51 installed package versions.
Only the extracted versions and log digest are committed in
[observed environment evidence](../reports/historical_training_environment_observed_2026-10-24.json),
not the raw logs. This list omits any preinstalled distributions and does not
record the original CSV hash, wheel hashes, full OS image or approval identity.

Rebuilding a clean observed-version environment locally failed: the proxy denied
PyPI resolution (`pypi.org`), including the permitted retry. No historical lock
was produced and the attempted installation therefore did not run. It is not a
successful reconstruction. Required package hosts `pypi.org` and
`files.pythonhosted.org` were added to the saved environment draft, preserving
the existing four GitHub hosts. Saving does not apply/publish network settings.

## Actual real-model research diagnostic

The maintained Linux-only command is:

```bash
python scripts/research_model_compatibility.py --archive /secure/uci-v21-original.zip
```

It accepts only the known original ZIP checksum and exact historical metadata.
The archive comes from the project's verified successful training run; arbitrary
pickles cannot enter this diagnostic. A child process receives no inherited
credentials, a 30-second parent deadline, 20-second CPU and 2-GiB address-space
limits, and blocked network connect/DNS/bind operations. scikit-learn version
warnings are errors. The trusted original pickle is deserialized only in that
child, then the existing guarded estimator/analyzer processes a reserved URL with
live checks off. Failure emits a fixed diagnostic, not a raw model exception.
These Linux process controls are defense in depth for a trusted research test,
not a general untrusted-pickle sandbox or the application's inference isolation.

The real model **loaded and passed the reserved-URL output contract** under the
existing hash-locked CPython 3.11.17 environment. See the
[actual diagnostic report](../reports/historical_model_compatibility_v21_2026-10-24.json).
Compared with installed versions observed in training logs, certifi,
python-dateutil and soupsieve differ; the complete original environment was not
reproduced. The report records the exact diagnostic source hash and full current
runtime identity. This establishes limited compatibility, not prediction quality,
calibration, original-byte environment reproduction or serving approval.

The diagnostic intentionally uses the trusted-research boundary. It does **not**
call, weaken or replace `load_app_model`'s mandatory approved manifest gate.
No manifest was manufactured. Real UI activation and running-service rollback
remain untested until independently approved inputs are available. No model,
metadata thresholds, final holdout or training operation was changed.
The archived run's source commit is `09e52d9...`; the registered frozen gate
requires `9a3ced0...`. That source policy was not rewritten to promote the old
pickle. Any approval/source-policy decision requires separate evidence review.

## Prevent the evidence gap in future authorized builds

The normal UCI training workflow now records `models/build_evidence.json` after
training/report verification and retains it with the two model files. It captures:

- Clean actual source commit/tree and tracked source/workflow/requirements hashes.
- Exact model, metadata and input CSV hashes, with change detection during capture.
- Runtime Python/platform/distributions/PSL identity and workflow run ID.
- Explicit `approval: not-approved` and a distinct candidate-evidence protocol.

The reusable command never trains or loads a pickle:

```bash
python scripts/record_model_build.py --model-dir /secure/models \
  --uci-csv /secure/phiusiil_urls.csv --out /secure/build_evidence.json
```

Use a clean source checkout and a new output path; it refuses overwriting inputs
or existing reports. Its stdout is the report SHA-256. Capture occurs immediately
after an **authorized** build, before any final holdout inspection. This task did
not run the UCI training workflow or collect a final dataset.

Candidate evidence is deliberately incompatible with the approved frozen
serving/evaluation manifest. It does not prove training ran or authenticate a
reviewer. Preserve original data and an environment/image independently; a
hash is not a backup. Independent review and the registered-source policy in
[frozen identity](FROZEN_MODEL_IDENTITY.md) still govern approval. The original
short-lived training artifact policy is not a permanent release registry.

Validation: baseline 248 tests per Python version; final **262 tests passed on
each of Python 3.10.22, 3.11.17 and 3.12.14**, with compileall, pip check and lock
checks passing on each. Nine capture regressions cover clean source, input
mutation, safe aggregate output, no pickle load, incompatible metadata and
overwrite refusal; five diagnostic regressions reject unknown inputs and process/
timeout/result failures. Real model probing was performed on **3.11.17 only**.
The updated full training workflow was not dispatched; its evidence step is
verified through offline synthetic fixtures rather than a new trained model.

# Approved model retention, installation and rollback

The operator CLI retains exact approved package bytes outside Git, verifies them
before use, and replaces a single shell configuration atomically. It does not
train, download or approve a model, modify thresholds, deploy a service or prove
real-world predictive quality. Persistent storage and independent approval are
operator responsibilities. No real model package was accepted in this delivery.

## Acceptance boundaries

1. Obtain the model, metadata, original manifest and manifest SHA-256 from a
   trusted build and independent approval channel. Never create a fresh approval
   around an unknown/historical pickle merely to satisfy the loader.
2. Restore the manifest's exact Python/platform/package/PSL environment,
   including bootstrap distributions. The new dependency locks do not recreate
   an older training environment. Environment mismatches must fail closed.
3. Store packages on a private persistent volume outside all Git checkouts,
   owned by the operator and read-only to the serving identity. Back up that
   volume and approval records independently. A cloud workspace is not a backup.
4. Retain at least the last known-good package **and its environment/image**.
   Rollback across environment changes requires restoring the previous image
   before activation. The CLI does not change Python or install dependencies.

## Stage without deserialization

```bash
PYTHONPATH=src python scripts/model_release.py stage \
  --store /secure/model-releases \
  --model-dir /secure/incoming/models \
  --manifest /secure/incoming/frozen_manifest.json \
  --manifest-sha256 "$APPROVED_MANIFEST_SHA256"
```

Only model, metadata and manifest are copied, using bounded reads. Verification
operates on those copied bytes, not a reread of mutable input. The directory is
published by rename only after identity/environment/metadata verification.
Packages are named by the approved manifest digest. Existing destinations are
never overwritten; files/directories are marked read-only to prevent accidents.
The original manifest and thresholds are not rewritten. No pickle is loaded
during staging. UCI data is not needed for serving; evaluators still require it.

## Smoke and activate

These commands **execute trusted pickle code** after verification. Use an isolated
operator environment with no unnecessary secrets and live checks disabled.

```bash
PYTHONPATH=src python scripts/model_release.py smoke \
  --store /secure/model-releases --manifest-sha256 "$APPROVED_MANIFEST_SHA256"
PYTHONPATH=src python scripts/model_release.py activate \
  --store /secure/model-releases --manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --env-file /secure/service/model.env
```

Smoke uses only `https://example.invalid/` offline through the existing analyzer.
It checks compatibility and output contract, not predictive accuracy. Activation
repeats smoke before atomically replacing the owner-only (0600) shell file. A
failed smoke/write leaves the prior configuration in place. The file is outside
the retained store; retained symlink packages, symlink config files and unsafe
checkout paths are rejected. Values are shell-quoted, not user-supplied commands.

The resulting file contains `export` assignments for the existing three serving
variables. It is a trusted **POSIX shell** file, not a general dotenv/systemd
EnvironmentFile format. Source it in the service launcher, then restart:

```bash
. /secure/service/model.env
python -m streamlit run app.py --server.headless=true --browser.gatherUsageStats=false
```

Confirm verified model state and reserved-URL form submission with live checks
off after restart. Neither configuration creation nor a healthy HTTP endpoint
proves that a running process switched packages. No running process is changed
by this CLI; [operator smoke/recovery checks](../PUBLISHING.md) remain required.

## Rollback

Restore the previous approved environment/image, then run `activate` with the
previous independently approved digest and the same `--env-file`. Restart and
repeat the UI smoke check. Do not delete the current or previous package during
incident recovery. A corrupt/incompatible rollback target leaves configuration
untouched; investigate rather than bypassing approval or environment checks.

The store uses an exclusive `.release.lock` to refuse concurrent cooperating
writers. A crashed operator process can leave a stale lock: verify no writer is
running before an operator removes that lock. No automatic lock stealing,
retention deletion, hostile-filesystem sandbox, hardware write-once guarantee
or power-loss durability guarantee is provided. Store owners can undo read-only
modes; separate ownership, backups and access controls remain necessary.

## Historical v2.1 archive — checked 2026-10-24

GitHub reports successful training run `39684966827`, source commit
`09e52d9772aaaa863157f8db405302a89dfa1e89`, artifact `12385851453`, not expired,
with archive SHA-256
`380622aa45ab410cf6ae499e5c271c271f05c1329f0f9c0066404b1262f45fda`.
This matches the [previously recorded digest](VERIFIED_RESULTS_V21_2026-10-21.md).
Retention ends **2026-10-29 01:17 Europe/Istanbul** (2026-10-28 22:17 UTC).

Metadata access worked, but the signed artifact-download endpoint returned
HTTP 403, including the permitted retry. **No archive bytes were obtained, no
release asset was uploaded, and no historical pickle was deserialized.** Do not
treat an empty failed-download file as an archive. The archive digest records
an expected ZIP identity; it is not a serving-manifest approval.

Required follow-up: restore access to GitHub Actions artifact download storage,
download before expiry, verify the complete ZIP against the recorded digest,
inspect member paths/sizes without executing pickle, and retain the unchanged
ZIP on durable controlled storage with independent backup/approval records.
Keep a draft archive separate from a public product release. Do not publish raw
datasets, review records or model assets without the appropriate approval.
An exact approved historical environment/UCI/model manifest is still unavailable;
do not infer one from package versions in today's environment or retrain a
replacement and call it the original. Real-package serving acceptance remains blocked.

## Software validation — 2026-10-24

Baseline: 214 tests passed on each of Python 3.10.22, 3.11.17 and 3.12.14,
with successful lock-identity and pip consistency checks. After implementation,
**233 tests passed on each version**; source compilation, pip check and lock
identity checks passed on all three. No dependency or installation failure was
found, so unchanged locked environments were reused rather than reinstalled.

The 19 new offline cases use only safe temporary fake packages. They cover
exact-byte staging without deserialization, tampered/oversized/incompatible
packages, no overwrite, failed activation preserving config, A-to-B-to-A rollback,
write failure cleanup, exclusive writer locks, checkout/symlink/traversal guards,
shell quoting and the operator CLI summary. CLI help and diff whitespace checks
passed. Existing UI/model/network regressions remain green. Neither a real
approved package nor a running service/environment rollback was tested; those
remain acceptance gates after access and independently approved inputs exist.

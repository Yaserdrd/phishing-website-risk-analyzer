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

Initial download requests returned HTTP 403. After the environment was published,
the original ZIP downloaded successfully; its SHA-256 matches the recorded digest
and its metadata equals the committed historical report. Direct release uploads
then failed with HTTP 401 because local platform credentials did not authenticate
on the upload host. No credentials were extracted or requested in chat.

The repository-scoped [preservation workflow](../.github/workflows/archive-historical-model.yml)
resolved upload authorization using the native temporary `GITHUB_TOKEN` with
`actions: read` and `contents: write`. The
[successful preservation/read-back run](https://github.com/Yaserdrd/phishing-website-risk-analyzer/actions/runs/40077416315)
retained `uci-v21-original.zip` and `archive-identity.json` in
[draft archive release 422602045](https://github.com/Yaserdrd/phishing-website-risk-analyzer/releases/tag/untagged-0612355f14190d7cb760).
The ZIP is unchanged. Both assets were downloaded again and their full bytes
verified. A second run retained matching assets without replacing them. See the
[aggregate archive evidence](../reports/historical_model_archive_v21_2026-10-24.json).

This draft has no Actions artifact retention deadline, but is editable/deletable
by repository owners; retain an independent controlled backup. It is not a public
product release, hardware-immutable storage or a serving approval. No pickle was
executed and no model/threshold was changed. The workflow refuses a published
release, altered source/artifact identities, mismatched assets, unexpected ZIP
members and metadata differing from historical evidence. Cross-host download
redirects strip authorization headers; tokens are sent only to HTTPS GitHub API
and upload origins. It requires an existing draft release and never publishes it.

An exact independently approved historical environment/UCI/model manifest is
still unavailable. Archive integrity is now verified, but it cannot supply
missing build/approval evidence. Do not infer that evidence from today's package
versions or retrain a replacement and call it the original. Real-package serving
acceptance remains blocked on that separate prerequisite.

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

Archive-preservation delivery: baseline 233 tests; final **248 tests passed on
each of Python 3.10.22, 3.11.17 and 3.12.14**, plus compileall, pip check and lock
identity checks. Fifteen archive regressions cover source identity, ZIP/metadata
tampering, unexpected members, credential origin/redirect boundaries, draft-only
retention, overwrite refusal, matching-asset reuse and failed read-back. Real
preservation and remote read-back succeeded in the linked workflow; both runs
kept the same asset IDs. Subsequently the job-specific log endpoint worked;
the [build-evidence follow-up](MODEL_BUILD_EVIDENCE.md) records observed versions
and a real offline research compatibility probe. It does not establish an exact
original environment or independently approved serving manifest.

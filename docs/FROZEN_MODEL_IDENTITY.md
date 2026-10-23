# Frozen evaluation identity and temporal validation

This is an integrity mechanism for offline evaluation, not a new benchmark or
an authentication/signature scheme. No real model was rebuilt or final holdout
evaluated to implement it.

## Trust boundary

Both prospective evaluators now require `--manifest` and `--manifest-sha256`.
The SHA-256 must come from a trusted build/review channel, independent of an
untrusted artifact supplier. An attacker can replace a pickle, its manifest and
an untrusted digest together. Never approve an arbitrary pickle by hashing it.

The manifest binds:

- Schema version, v2.1.0 identity and registered training source commit
  `9a3ced00d98a40773837e0f52aa236c9c1b3c45f`.
- Exact model pickle, metadata JSON and original UCI CSV SHA-256 digests.
- Python patch version, implementation, OS/architecture, installed distribution
  versions (including transitive packages) and bundled Public Suffix List digest.

The verifier requires the runtime identity to match, validates metadata version
and finite ordered thresholds, and checks all artifact digests **before**
deserialization. It loads the verified model buffer rather than reopening its
pathname. Reports include this identity, the approved manifest digest and hashes
of the actual evaluator Python files plus its Git HEAD. Actual file hashes also
identify locally modified evaluator code; HEAD alone is not treated as proof.

This does not attest that training actually ran, authenticate the operator,
verify dependency installation contents beyond recorded versions/PSL, validate
label truth or protect files against a malicious concurrent local process. Keep
inputs immutable during evaluation and use a trusted isolated build. A clean
Git checkout plus a model version string alone cannot prove model provenance.

## Create an approved identity

Immediately after an authorized trusted build, before acquiring or inspecting
the final holdout, run the helper from the current repository. Use an existing
clean frozen-source checkout; do not create a worktree implicitly.

```bash
python scripts/freeze_manifest.py \
  --source-root /secure/frozen-source \
  --model-dir /secure/frozen-source/models \
  --uci-csv /secure/frozen-source/data/phiusiil_urls.csv \
  --out /secure/frozen-source/models/frozen_manifest.json
```

The source checkout must have the exact registered HEAD and no tracked or
unignored untracked changes. The helper never loads the pickle or trains a model,
refuses to overwrite an existing manifest, and prints only its SHA-256. Preserve
that approved digest through the trusted review/build record, not an assertion
from an unknown artifact supplier. Preserve the corresponding environment as well.

For the existing prospective workflow, a new step records the identity directly
after its frozen-source build and before feed acquisition. The digest passes
through a workflow step output. This binds the **same run's** build and evaluation;
it does not establish byte identity with a historical run or freeze future
dependency resolution. Comparing/reusing builds requires an independently retained
approved manifest and matching environment, not generating a new digest to bypass
a mismatch. A historical artifact without such evidence remains unverified.

## Evaluate approved inputs

After independent review approves the manifest digest, pass it explicitly:

```bash
PYTHONPATH=src python scripts/prospective_holdout.py \
  --model-dir /secure/frozen-source/models \
  --uci-csv /secure/frozen-source/data/phiusiil_urls.csv \
  --manifest /secure/frozen-source/models/frozen_manifest.json \
  --manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --phishing-csv /secure/online-valid.csv.gz \
  --min-count 200 --out reports/prospective_holdout.json
```

Use the same identity arguments for `evaluate_vetted_holdout.py`. A missing trust
anchor, changed artifact/UCI input, changed environment or incompatible metadata
blocks loading/evaluation. Do not disable checks or rewrite expected digests to
make a failing run pass. Keep raw evidence and URL lists outside the repository.

## Shared temporal policy

The unchanged cutoff is `2026-10-23T00:00:00Z`. All three review/evaluation paths
use the shared UTC parser and ordering rule:

```text
cutoff <= first observation/submission <= verification <= evaluation time
```

Naive and non-UTC timestamps are rejected. Equivalent explicit zero UTC offsets
are accepted. CLI evaluation time is captured once and shared by record filtering
and the report. Tests inject a fixed UTC clock; they do not depend on today's date.

The positive feed selector excludes invalid rows with aggregate counters and
still fails if fewer than the required eligible samples remain. The vetted
corpus loader and review adjudicator reject invalid review metadata. The feed's
existing `missing_dates` counter includes missing, malformed and non-UTC dates;
`invalid_time_order_or_future` accounts for post-cutoff ordering/future violations.
Neither selection policy licenses threshold tuning or repeated final-set inspection.

## Training label validation

CSV labels are read as text and checked for exact numeric equality to 0 or 1
before integer conversion. Decimal parsing prevents fractions, infinities,
near-integer rounding and tiny underflow values from silently changing classes.
Exact binary forms such as `0.0` and `1.0` remain valid. Missing rows retain the
existing cleaning policy. Fitting, splitting, threshold selection and prediction
are unchanged; the registered frozen-source workflow still trains from its fixed
commit when explicitly invoked.

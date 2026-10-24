# Locked development and research environments

The supported validation matrix is CPython 3.10, 3.11 and 3.12 on Linux x86_64.
These are the project's existing supported versions, not a claim about other
Python versions, operating systems or architectures.

`requirements/py310.lock`, `py311.lock` and `py312.lock` pin the complete
development/research dependency graph (including application and training
dependencies). Every resolved package has distribution SHA-256 hashes. The
original requirements files remain the human-maintained compatibility ranges;
installing those ranges directly is not the reproducible path.

For example, with a Python 3.11 interpreter, from the repository root:

```bash
python3.11 -m venv /private/path/phishing-311
/private/path/phishing-311/bin/python scripts/lock_dependencies.py --check
/private/path/phishing-311/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements/py311.lock
PYTHONPATH=src /private/path/phishing-311/bin/python -m pytest -q
/private/path/phishing-311/bin/python -m compileall -q src app.py scripts
/private/path/phishing-311/bin/python -m pip check
```

Use the matching lock for 3.10 or 3.12 and a new empty environment. Do not reuse
an environment containing unrelated packages: pip does not remove extra packages.
No source builds are allowed; missing compatible wheels or hash mismatches must
fail rather than falling back to an unchecked build. Do not disable hash checks
to repair a failed installation. CI uses the same installation flags, checks the
input/lock manifest offline, runs pip check and uses Ubuntu 24.04 rather than a
moving major Ubuntu label. Runner updates still occur within that label.

## Updating dependencies

Use the recorded compiler `uv==0.12.23` in separate tooling, edit the appropriate
requirements ranges, then run:

```bash
python scripts/lock_dependencies.py
python scripts/lock_dependencies.py --check
```

Review all three lock diffs and the manifest; validate fresh environments for all
three versions before submitting a PR. Existing compatible pins are retained by
the resolver; a deliberate version upgrade can be expressed by raising the
relevant input minimum. Never change only the manifest to hide stale resolution.
The manifest binds bytes; it is not a signature, vulnerability audit or proof
that the resolver was run honestly. Hashes are supplied by the package index at
resolution time and do not prove upstream code is trustworthy.

## Experiment and serving boundary

These locks make dependency selection and downloaded package bytes explicit.
They do not reproduce a historical model, pin changing external data, freeze
the OS/interpreter image, provide permanent model storage or approve artifacts.
Python patch version and all installed distributions (including bootstrap pip
and any setuptools) remain part of the runtime identity recorded in approved
model manifests. A model built in a different environment must still fail the
existing identity checks; do not regenerate an approval digest to bypass that.

No UCI training, prospective final evaluation or real model deserialization is
required for this environment validation. Training/holdout workflow dependency
installation is updated, but those expensive scientific jobs are not run merely
to test a dependency lock. Next release work must retain immutable approved
model/data/environment identities, an external approval anchor and a rollback
procedure, then validate a real trusted serving package separately.

## Validation record — 2026-10-23

The interrupted environment became available again. Three new virtual
environments were created outside the checkout with system site packages
disabled; no previous project environments were overwritten. These Python
versions cover the existing supported CI matrix. Each install used the matching
lock with `--require-hashes --only-binary=:all: --no-cache-dir` and exited zero.

| CPython / Linux x86_64 | Hash-controlled clean install | Complete test suite | Source compile | pip check |
| --- | --- | --- | --- | --- |
| 3.10.22 | Passed | 214 passed | Passed | No broken requirements |
| 3.11.17 | Passed | 214 passed | Passed | No broken requirements |
| 3.12.14 | Passed | 214 passed | Passed | No broken requirements |

The pre-lock baseline had 211 passing tests; a fresh pre-edit 3.12 run confirmed
that baseline before the interrupted implementation. Three new tests verify the
committed lock manifest and rejection of changed input/lock bytes. The offline
lock identity check passed separately in every new environment. No installation
or dependency conflict was observed; pip's non-writable shared cache warning
did not affect installation (cache explicitly disabled) or pip check.

Model/threshold implementation, model artifacts and final evaluation data were
unchanged. Tests train only temporary synthetic fixtures. No new full UCI
training, real serving-package load, Windows/macOS/ARM validation or prospective
final evaluation was performed. This is dependency/environment acceptance,
not predictive-performance or production-release acceptance.

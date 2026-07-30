# Working on btclib_libsecp256k1

Python bindings to a vendored [libsecp256k1](secp256k1/), built from
source. The package is thin: the cryptography is upstream, and what lives
here is the wrapping, the argument validation at the cffi boundary, and
the packaging of eleven kinds of wheel.

This file is for what is not written down elsewhere. The documentation is,
and stays, in:

- [README.md](README.md) — design, wrapped modules, build, and the
  static/dynamic/sdist distinction
- [CONTRIBUTING.md](CONTRIBUTING.md) — what a change has to satisfy
- [RELEASING.md](RELEASING.md) — the release, and the rehearsal
- [scripts/README.md](scripts/README.md) — the build backend, one file at
  a time
- the comments in `.github/workflows/*.yml` and `pyproject.toml`, which
  carry the reasoning behind their choices

## The gate is one file

`.pre-commit-config.yaml` is the single definition of what "clean" means.
The `lint` workflow runs that very file, so what CI enforces is what a
commit enforces:

    uvx pre-commit run --all-files

Never add a check that exists only in a workflow, and never leave a hook
weaker locally than on a runner: a hook that needs a tool the developer
may not have carries it in `additional_dependencies` (this is why
`actionlint` ships `shellcheck-py` and `zizmor` is a `local` hook pinned
to a version). A check discovered by CI after a push is a check in the
wrong place.

## Commands whose flags are load-bearing

    # the suite, as the coverage job runs it: uv run syncs by itself, and
    # without these flags it installs the whole dev set
    uv run --locked --no-default-groups --group test pytest --cov

    # another interpreter; --no-cache because the cached extension
    # belongs to one ABI
    uv run --python 3.9 --no-cache pytest

    # the packaging gates, pinned by uv.lock rather than fetched by uvx
    uv build --sdist
    uv run --locked --only-group check twine check --strict dist/*
    uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz

    # after touching pyproject.toml; the uv-lock hook does it too
    uv lock

    # after adding to tests/ecdsa*_sig.json, whose known findings are
    # recorded rather than excluded
    uvx --from detect-secrets detect-secrets scan --baseline .secrets.baseline

## What this repository expects

- **comments say why.** The what is in the diff; the why is not
  recoverable from it. A change that makes a comment untrue updates the
  comment, in the workflows and the build scripts as much as in the
  package
- **tests validate against external vectors.** A test that compares these
  bindings with themselves proves nothing. `tests/test_vectors.py`
  documents where each vendored file comes from
- **coverage is a ratchet at 100%,** with `raise RuntimeError` excluded:
  see the reasoning in `pyproject.toml`
- **warnings are errors** (`filterwarnings`), because the 3.9 to 3.14
  spread turns a deprecation into a breakage
- **the version is declared once,** in `pyproject.toml`; `__version__`
  reads the installed metadata. Never bump it in an ordinary change:
  releases are cut by a maintainer, and the release workflow checks the
  tag against it
- **the `secp256k1` submodule moves in a change of its own,** with the
  version named in `README.md` and `HISTORY.md` moved with it
- development happens on `dev`; a pull request targets `dev`, and `master`
  only ever receives merges from it

## Verifying, rather than reasoning about, a change

The build matrix is expensive — tens of jobs compiling C — and this
package exists to behave identically everywhere, so a claim about it is
worth a command:

- run the thing. A local `pre-commit` pass is not evidence that CI passes
  if the runner has a tool this machine lacks
- when adding a check, hand it something bad and watch it fail. Every hook
  here was verified that way
- prefer reading a log to predicting one: `gh run view <id> --log-failed`

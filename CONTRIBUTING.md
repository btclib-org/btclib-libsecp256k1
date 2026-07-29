# How to contribute

Thank you for investing your time in this project. What follows is what
this repository expects of a change; how to build, test and benchmark it
is in the
[Build, test, develop, and contribute](README.md#build-test-develop-and-contribute)
section of the README, which is not repeated here.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) too.

## Which project is this

These are thin python bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). Three
repositories are easy to confuse, and an issue in the wrong one is slow
to route:

- the cryptography is upstream, in
  [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1/issues).
  It is vendored as the `secp256k1` submodule and only ever read from: a
  flaw in the library itself is not ours to fix
- anything with state of its own — a wallet, a transaction, a signing
  session — belongs in
  [btclib](https://github.com/btclib-org/btclib/issues), which is what
  these bindings are for. The Design section of the README says where the
  line is
- what belongs here is how the bindings drive the library: the wrapping,
  the argument validation at the cffi boundary, the packaging, and the
  wheels

A vulnerability is never an issue: see the
[security policy](SECURITY.md).

## Opening an issue

Search the [issues](https://github.com/btclib-org/btclib_libsecp256k1/issues)
and [pull requests](https://github.com/btclib-org/btclib_libsecp256k1/pulls)
first, then use one of the
[forms](https://github.com/btclib-org/btclib_libsecp256k1/issues/new/choose).
The bug form asks which of the three artifacts is installed — a static
wheel, a dynamic one, or a build from the sdist — because they differ in
how libsecp256k1 is linked and a bug is rarely in all three.

Issues are not assigned to anyone: if one interests you, you are welcome
to open a pull request for it.

## What a change has to satisfy

Development happens on `dev`, so that is what a pull request targets;
`master` only ever receives merges from it, and a tag on `master` is a
release.

- **the pre-commit hooks pass.** `uv run pre-commit run --all-files` runs
  the formatter, the linters and the type checker; the `lint` workflow
  runs that very configuration, so what CI enforces is what the hook
  does. `uvx pre-commit install` makes it a commit hook
- **the tests pass with full coverage.** `uv run pytest --cov`; the
  `fail_under` ratchet in `pyproject.toml` is what makes the number mean
  something, so new code arrives with the tests that cover its branches
- **new wrapped functionality is validated against external vectors.**
  A test that compares these bindings against themselves proves nothing.
  `tests/test_vectors.py` documents where each vendored vector file comes
  from — BIP340, RFC6979, trezor-firmware — and a new wrapper should
  reach for something published elsewhere in the same way
- **the comments say why, not what.** The workflows, the build scripts
  and the configuration files in this repository carry the reasoning
  behind their choices, because that is the part a reader cannot recover.
  A change that invalidates one of those comments has to update it
- **the vendored submodule moves on purpose.** Bumping `secp256k1` is a
  change of what this package wraps: it belongs in its own pull request,
  with the version named in the README and in `HISTORY.md` moved with it.
  Dependabot signals upstream movement but tracks the default branch, so
  a release always needs the tagged commit

## Pull requests

The whole build and test matrix — tens of jobs, each compiling
libsecp256k1 from source — runs on every pull request and on every push
to it, which is deliberate: this package exists to be identical
everywhere. It does mean a draft pull request is the polite place for
work in progress.

Link the issue the pull request solves, allow maintainer edits so the
branch can be updated for a merge, and mark review conversations
resolved as you address them.

Releases are cut by a maintainer, following [RELEASING.md](RELEASING.md);
nothing about a version needs to be touched in a pull request.

Once merged, your contribution is visible on the
[contributors page](https://github.com/btclib-org/btclib_libsecp256k1/graphs/contributors).

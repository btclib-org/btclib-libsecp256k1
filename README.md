# btclib_libsecp256k1

[![python](https://img.shields.io/pypi/pyversions/btclib_libsecp256k1.svg?logo=python)](https://pypi.python.org/pypi/btclib_libsecp256k1/)
[![pypi](https://img.shields.io/pypi/v/btclib_libsecp256k1.svg?logo=pypi)](https://pypi.python.org/pypi/btclib_libsecp256k1/)
[![downloads](https://static.pepy.tech/badge/btclib_libsecp256k1)](https://pepy.tech/project/btclib_libsecp256k1)
[![status](https://img.shields.io/pypi/status/btclib_libsecp256k1.svg)](https://pypi.python.org/pypi/btclib_libsecp256k1/)
[![license](https://img.shields.io/github/license/btclib-org/btclib_libsecp256k1.svg)](https://github.com/btclib-org/btclib_libsecp256k1/blob/master/LICENSE)
[![lint and format: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![type-check: mypy](https://img.shields.io/badge/type--check-mypy-yellowgreen.svg?logo=mypy)](http://mypy-lang.org/)
[![main](https://github.com/btclib-org/btclib_libsecp256k1/actions/workflows/main.yml/badge.svg)](https://github.com/btclib-org/btclib_libsecp256k1/actions/workflows/main.yml)

[![Follow on Twitter](https://img.shields.io/twitter/follow/btclib?style=social&logo=twitter)](https://twitter.com/intent/follow?screen_name=btclib)

---

[Browse GitHub Code Repository](https://github.com/btclib-org/btclib_libsecp256k1/)

---

Simple python bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
([v0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)).
It is intended to be used with the
[btclib](https://github.com/btclib-org/btclib) library.

To install (and/or upgrade):

    python -m pip install --upgrade btclib_libsecp256k1

## Wrapped modules

All the optional libsecp256k1 modules are compiled in and their
declarations are available through the `lib` and `ffi` cffi objects:

| libsecp256k1 module | bindings                                  |
| ------------------- | ----------------------------------------- |
| (core)              | `dsa`, `mult`, `keys`, `hashes`           |
| `ecdh`              | `ecdh`                                    |
| `recovery`          | `recovery`                                |
| `extrakeys`         | `xonly`, used by `ssa`                    |
| `schnorrsig`        | `ssa`                                     |
| `musig`             | raw `lib` bindings only, see the tests    |
| `ellswift`          | `ellswift` (BIP324)                       |

`keys` provides the scalar and point algebra (tweaking, negation,
combination, arbitrary point multiplication) underlying BIP32 key
derivation, plus the lexicographic ordering of public keys (`pubkey_cmp`,
`pubkey_sort`) that BIP67 and MuSig2 key aggregation call for; `xonly`
provides the BIP341 taproot tweaking of x-only public keys and of their
private keys; `hashes` provides the BIP340 tagged hash, the domain
separation the taproot tags are built on.

`ssa.sign` signs a 32-byte message hash, as bitcoin does; `ssa.sign_custom`
signs a message of any length, which BIP340 allows and which a protocol
of its own may define.

MuSig2 has no dedicated binding module yet: its two-round protocol
needs an interface that makes secret nonce reuse hard, which is still
to be designed. `tests/test_modules.py` shows a complete 2-of-2
signing session through the raw bindings.

## Thread safety

The bindings can be called concurrently from several threads. They hold
a single libsecp256k1 context, created and randomized at import time and
passed to every call: `secp256k1_context_randomize` is what mutates a
context, it runs once before any thread exists, and each call allocates
the buffers it writes to.

This matters on a free-threaded interpreter, for which a wheel is built
(`cp314t`), where those calls are no longer serialized;
`tests/test_concurrency.py` exercises it.

What is not protected is the secret material itself, which lives in
Python objects for as long as the interpreter keeps them: see
[SECURITY.md](SECURITY.md).

## Versioning

btclib_libsecp256k1 version numbers track the wrapped libsecp256k1
version: release M.N.P wraps libsecp256k1 vM.N.P
(e.g. btclib_libsecp256k1 0.7.1 wraps libsecp256k1 v0.7.1).
When a new release of the bindings is needed while still wrapping the
same libsecp256k1 version, a fourth number is appended:
0.7.1.1, 0.7.1.2, etc.

## Release process

Releases are published to PyPI by the `release` GitHub workflow using
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
no long-lived PyPI token exists anywhere; PyPI trusts the workflow
itself (via GitHub OIDC) and hands out a short-lived upload token at
run time. Wheels and sdist are uploaded with PEP 740 attestations, so
their provenance can be verified on PyPI.

To cut a release:

1. update the version in `pyproject.toml` and HISTORY.md,
   merge `dev` into `master` with a green CI
2. tag `master` with the version (`git tag v0.7.1 && git push --tags`):
   the `release` workflow builds and tests every artifact
   (including the Intel macOS ones, skipped on development branches)
3. approve the `pypi` deployment when the workflow pauses for review:
   the artifacts are then published to PyPI

One-time setup (already done, documented for reference):

- on PyPI, project Publishing settings: add a GitHub trusted publisher
  for `btclib-org/btclib_libsecp256k1`, workflow `release.yml`,
  environment `pypi`
- on GitHub, repository Settings, Environments: create the `pypi`
  environment and add the required reviewers who approve releases

## Build, test, develop, and contribute

On POSIX systems the vendored libsecp256k1 is built with autotools
(automake, libtool, and a C toolchain must be available).
On Windows it is built natively with CMake/MSVC and the cffi extension
with the standard setuptools toolchain; a `gcc` in the PATH is still
required, as it preprocesses the library headers for cffi. Both
architectures are built this way: CMake and MSVC target the host, so
`win_amd64` and `win_arm64` wheels need no configuration of their own.
The `win_arm64` wheels start at CPython 3.11, the first version with a
Windows arm64 build.
The dynamic (ABI mode) Windows wheel is instead cross-compiled
on Linux with mingw-w64, and is x86_64 only.

The btclib_libsecp256k1 project includes
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
as submodule in the secp256k1 folder.
By default, when cloning a project you get the directories that contain
submodules, but none of the files within them.
You must run `git submodule init` to initialize
your local configuration file,
and `git submodule update` to fetch the submodule data
and check out the appropriate commit.

<!-- markdownlint-disable MD013 -->
    $ git submodule init
    Submodule 'secp256k1' (git@github.com:bitcoin-core/secp256k1.git) registered for path 'secp256k1'
    $ git submodule update
    Cloning into 'secp256k1'...
<!-- markdownlint-enable MD013 -->

The project uses [uv](https://docs.astral.sh/uv/) to manage the
development environment. The interpreter it is built on is pinned in
`.python-version`, and uv installs it if missing: neither pyenv nor a
hand-made virtualenv is needed. The development dependencies are the
PEP 735 groups declared in `pyproject.toml`.

    uv sync

This also builds and installs the extension in editable mode, so the
autotools toolchain listed above must be available.

To build:

    uv build --sdist
    uv build --wheel

To test:

    uv run pytest

To measure the code coverage provided by tests:

    uv run pytest --cov

Coverage is measured in branch mode and gated by the `fail_under`
ratchet in `pyproject.toml`; the same check runs in CI.

To run everything CI checks before a PR, i.e. the formatter, the
linters and the type checker:

    uv run pre-commit run --all-files

To test against another supported interpreter, bypass the build cache:
uv keys it on the sources, which do not tell it that the compiled
extension belongs to one ABI version only.

    uv run --python 3.9 --no-cache pytest

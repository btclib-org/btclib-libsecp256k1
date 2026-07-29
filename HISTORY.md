# Release notes

Notable changes to the codebase are documented here.

## v0.7.1

Major changes include:

- Wrapped
  [libsecp256k1 0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
  (1a53f49)
- New versioning scheme: release numbers now track the wrapped
  libsecp256k1 version; binding-only releases append a fourth number
  (0.7.1.1, 0.7.1.2, etc.)
- Added support for Python 3.13 and 3.14
- Dropped support for Python 3.7 and 3.8 (minimum is now 3.9):
  both are end-of-life (3.7 since June 2023, 3.8 since October 2024)
  and the current build/test infrastructure cannot support them anymore,
  as cibuildwheel 4.x does not build cp37/cp38 wheels and GitHub-hosted
  runners no longer provide those interpreters
- Added macOS arm64 and Linux aarch64 wheels
- Added native Windows wheels for CPython, built with CMake/MSVC via
  cibuildwheel; the mingw cross-compiled dynamic wheel is still
  provided
- Dynamic wheels now carry the platform tag of the machine they are
  built on (it was hardcoded to x86_64, with a fake macOS 10.16
  minimum version)
- Updated CI to current GitHub Actions runners and actions,
  cibuildwheel 4.x (static wheels now cp39-cp314, PyPy opt-in)
- Hardened CI: least-privilege GITHUB_TOKEN (contents: read), actions
  pinned to commit SHAs, superseded runs auto-cancelled
- New release workflow: tag-triggered, publishing to PyPI with Trusted
  Publishing (OIDC, no long-lived tokens) and PEP 740 attestations,
  behind a manual approval gate
- Updated all pre-commit hooks to their latest versions
- Fixed sdist builds with multi-pass PEP 517 frontends such as uv:
  the callback stubs are now a separate compilation unit,
  no longer mutating the vendored sources (#20)
- Build scripts now fail fast on subprocess errors
- Tests now cover the official BIP340 test vectors, the published
  RFC6979 deterministic ECDSA vectors for secp256k1, the secp256k1-py
  ECDSA vectors used by btclib, DER edge cases, and the error paths
  of the bindings
- Bindings now validate inputs and check libsecp256k1 return codes,
  raising `ValueError` with a clear message; malformed keys and
  signatures were previously verified against uninitialized memory
- A single shared libsecp256k1 context is created with the modern
  `SECP256K1_CONTEXT_NONE` flag (the SIGN/VERIFY flags are deprecated)
  and randomized to protect against side-channel leakage

## v0.4.0

Major changes include:

- Wrapped
  [libsecp256k1 0.4.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.4.0)
  (199d27c)

## v0.3.0

Major changes include:

- Wrapped
  [libsecp256k1 0.3.2](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.3.2)
  (acf5c55)
- Build platform wheels using cibuildwheel
- Switched from setuptools to hatch
- Improved project standards (pyproject.toml, nox)

## v0.2.1

Major changes include:

- Fixed bug in `mult`

## v0.2.0

Major changes include:

- Wrapped
  [libsecp256k1 0.2.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.2.0)
  (21ffe4b)
- Increased test coverage
- Improved project standards (pre-commit hooks, mypy, tox)

## v0.1.1

Major changes include:

- Fixed `mult` return type

## v0.1

Major changes include:

- Wrapped
  [libsecp256k1](https://github.com/bitcoin-core/secp256k1/tree/3efeb9da21368c02cad58435b2ccdf6eb4b359c3)
  (3efeb9da)
- Updated nonce generation
- Added `mult` module

## v0.0.2

Major changes include:

- Fixed description
- Added `py.typed`

## v0.0.1

Wrapped
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/tree/fecf436d5327717801da84beb3066f5a9b80ea8e)
(fecf436d)

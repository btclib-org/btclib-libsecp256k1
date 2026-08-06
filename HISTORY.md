# Release notes

Notable changes to the codebase are documented here.

## v0.7.1.1

The same
[libsecp256k1 0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
(1a53f49) as v0.7.1, and the same bindings: no wrapper changed
behaviour, and nothing in the public API moved. What a fourth number
carries here is the floor the package is built on, its documentation,
and the gate around both.

- Dropped support for Python 3.9 (minimum is now 3.10): it reached end
  of life in October 2025, and keeping it held `uv.lock` at a second
  resolution of its own, cffi 2.1 requiring 3.10 and cffi 2.0 staying
  pinned for 3.9 alone. It also cost the build matrix its widest cell,
  CPython having no Windows arm64 build before 3.11
- Published documentation: a Sphinx build under `docs/`, served at
  [Read the Docs](https://btclib-libsecp256k1.readthedocs.io), which the
  `documentation` metadata url now names instead of the README
- The distribution names The btclib developers as its author and ships
  `AUTHORS.md` beside `LICENSE` and `COPYRIGHT`. The licence header of
  every source file is the short MIT one, so the three no longer state
  the same holder and the same terms three different ways
- Three scheduled workflows join `published`, each asking on a morning
  of its own a question no pull request can: whether the urls in the
  prose still resolve (`links`), whether the tree survives every
  dependency at its newest (`latest`), and whether the suite would
  notice a wrong line (`mutation`). None of them gates a merge, and that
  is the design: what they report is the outside world moving, or a test
  nobody has written, and neither is something a branch can act on
- Each vendored test vector is pinned to a commit and a blob SHA-1 in
  `tests/README.md`, so a citation names the revision actually copied
  rather than a file that changes underneath it, and a monthly workflow
  opens an issue when upstream moves one
- New `REPOSITORY.md`: the branch rules, required checks, token
  permissions, publishing environments and scanning settings that live
  outside the tree and cannot be recovered by reading it, each with the
  API call that reads it back
- The pre-commit gate, which is the one definition of clean and what CI
  runs rather than a second list of its own, now also measures the yaml,
  the prose and the packaging metadata, and checks itself. mypy runs
  with more of its optional error codes and ruff with more rule-sets,
  every one of which the tree already satisfied
- More tests, and what each one verifies is now stated in its docstring
  and gated as such: the callbacks, the copyright headers, the
  documentation build and the vendored data are covered where they were
  not

## v0.7.1

Major changes include:

- Wrapped
  [libsecp256k1 0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
  (1a53f49)
- Wrapped the `ecdh`, `recovery`, `ellswift` (BIP324) and `musig`
  (MuSig2) libsecp256k1 modules, besides the already wrapped
  `extrakeys` and `schnorrsig` ones; new `ecdh`, `recovery`, and
  `ellswift` binding modules, while MuSig2 is available through the raw
  cffi bindings only, by decision: its two-round protocol needs a
  session whose secret nonce cannot be reused, which is a property of an
  object's lifetime and belongs where the signing state lives, in
  btclib; what has no state in it is wrapped here (key ordering and
  aggregation, taproot tweaking, tagged hashing, and the BIP340
  verification an aggregate signature reduces to)
- New `keys` binding module: private and public key algebra (verify,
  negate, tweak add and multiply, combine), including the
  multiplication of an arbitrary point, which `mult` does not provide
- New `xonly` binding module: BIP341 taproot tweaking of x-only public
  keys (`tweak_add`, `tweak_add_check`) and of the corresponding
  private keys, so that a key path spending can be signed with `ssa`
- New `hashes` binding module: the BIP340 tagged hash
  (`tagged_sha256`), which the taproot tags of BIP341 (TapLeaf,
  TapBranch, TapTweak) and the BIP340 challenge are built on
- `keys` also provides the lexicographic ordering of public keys
  (`pubkey_cmp`, `pubkey_sort`), which is the one of a BIP67 multisig
  script and the one MuSig2 key aggregation applies by default
- New `ssa.sign_custom`: BIP340 signing of a message of any length,
  which `sign` cannot do and `verify` could already check
- `dsa` now exposes the signature malleability primitives
  (`normalize`, `is_low_s`) and the conversions between the DER and the
  64-byte compact encodings (`to_compact`, `to_der`)
- `dsa.verify` and `ssa.verify` return `bool` instead of `int`
- `ssa.verify` takes the 32-byte x-only public key BIP340 verifies
  against, and so do `xonly.tweak_add` and `xonly.tweak_add_check`: a
  full public key used to be accepted and reinterpreted as its even y
  point, which is a different key from the one passed whenever y is odd.
  `xonly.from_pubkey` is that conversion, and making it is the caller's
  decision
- the 32 bytes of nonce entropy are 32 bytes or omitted: `ndata`
  (`dsa.sign`, `recovery.sign`), `aux_rand32` (`ssa.sign`,
  `ssa.sign_custom`, `ellswift.create`) and `rnd32` (`ellswift.encode`)
  used to be left padded when shorter, turning a caller mistake into a
  valid argument; a wrong length now raises `ValueError`. The boundary
  checks what C cannot see and normalizes nothing else, which the README
  states as such under What the boundary checks
- All the wrapped modules are now requested explicitly at configure
  time (`recovery`, in particular, is disabled by default upstream):
  upstream defaults are not part of its API, and the autotools and
  CMake build paths were enabling different module sets
- The vendored library is now built with CMake on every platform, in a
  single build path: autotools (on POSIX) and mingw cross-compilation
  (through `--host`) are gone, and with them the need for automake,
  libtool, pkg-config and autoconf. CMake is declared as a build
  requirement, so that installing the sdist provisions it instead of
  demanding a package manager step: only a C toolchain is needed
- The build no longer writes inside the vendored tree: the callback
  stubs are added to the library target from the CMake binary
  directory, which is outside the submodule, so `git reset --hard` and
  `git clean -fxd` on the submodule (which used to discard any local
  change to it) are gone, and a wheel built on Windows can no longer
  ship the CMake build tree in an sdist
- Fixed the shared object lookup of a dynamic build giving up on the
  first candidate directory, which the CMake layout (POSIX libraries in
  `lib`, Windows DLLs in `bin`) would have hit
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
  cibuildwheel, for both x86_64 and arm64 (`win_arm64` from CPython 3.11,
  the first version with a Windows arm64 build); the mingw
  cross-compiled dynamic wheel is still provided, x86_64 only
- Dynamic wheels now carry the platform tag of the interpreter they are
  built with (it was hardcoded to x86_64, with a fake macOS 10.16
  minimum version)
- The vendored library is now built for the architecture of the
  interpreter, which is the one its toolchain compiles the extension
  for, instead of the one CMake infers from the host: an emulated
  interpreter (an x86-64 CPython on Windows arm64, which is what uv
  installs there by default) used to get an archive of the wrong
  architecture, and every libsecp256k1 symbol unresolved at link time
- Updated CI to current GitHub Actions runners and actions,
  cibuildwheel 4.x (static wheels now cp39-cp314, PyPy opt-in)
- Hardened CI: least-privilege GITHUB_TOKEN (contents: read), actions
  pinned to commit SHAs, superseded runs auto-cancelled
- New release workflow: tag-triggered, publishing to PyPI with Trusted
  Publishing (OIDC, no long-lived tokens) and PEP 740 attestations,
  behind a manual approval gate
- New `SECURITY.md`: how to report a vulnerability, and where the
  boundary with libsecp256k1 lies, as the cryptography is upstream and
  what is ours is the layer driving it
- Updated all pre-commit hooks to their latest versions
- Replaced black, isort, flake8, autoflake, pyupgrade, bandit,
  pydocstringformatter and yesqa with ruff: one linter and formatter,
  one configuration section
- mypy now runs in strict mode; the cffi extension module is described
  by a hand-written stub (`stubs/_btclib_libsecp256k1.pyi`), without
  which `ffi` and `lib` are `Any` and the whole package type-checks
  vacuously. Opaque libsecp256k1 handles are spelled `CData` in the
  public signatures that return them
- The package now exposes `__version__`
- CI additionally gates on the pre-commit hooks, on branch coverage
  with a `fail_under` ratchet, on installing from the sdist (the only
  path that compiles libsecp256k1 on the user's machine), and on the
  `twine check --strict` and `check-wheel-contents` validation of every
  wheel and sdist before a release can reach PyPI
- Development environment managed by [uv](https://docs.astral.sh/uv/),
  with PEP 735 dependency groups and the interpreter pinned in
  `.python-version`; the hatch environments and the noxfile are gone
- PEP 639 license metadata (`license = "MIT"` plus `license-files`,
  replacing the deprecated license table and the `License ::`
  classifier)
- An import failure of the extension now raises `ImportError` naming
  the directory searched, instead of a bare `NameError`
- Fixed sdist builds with multi-pass PEP 517 frontends such as uv:
  the callback stubs are now a separate compilation unit,
  no longer mutating the vendored sources (#20)
- Build scripts now fail fast on subprocess errors
- Tests now cover the official BIP340 test vectors, the published
  RFC6979 deterministic ECDSA vectors for secp256k1, the secp256k1-py
  ECDSA vectors used by btclib, DER edge cases, and the error paths
  of the bindings: every line and branch reachable through the API is
  covered, the `fail_under` ratchet is at 100%, and the unreachable
  `RuntimeError` paths are excluded from the measure instead of being
  counted as a gap that could never be closed
- New invariant tests, over inputs derived from a SHA256 chain rather
  than chosen: round trips, the scalar operations agreeing with the
  point ones, and the two sides of ECDH and of BIP324 agreeing. They
  reach what a fixed key cannot, such as a public key whose x
  coordinate starts with a zero byte or a signature whose DER encoding
  is 69 bytes, both pinned as well; no test dependency is added, the
  suite running inside every wheel test environment too
- Bindings now validate inputs and check libsecp256k1 return codes,
  raising `ValueError` with a clear message; malformed keys and
  signatures were previously verified against uninitialized memory
- A single shared libsecp256k1 context is created with the modern
  `SECP256K1_CONTEXT_NONE` flag (the SIGN/VERIFY flags are deprecated)
  and randomized to protect against side-channel leakage
- The shared context now records what libsecp256k1 reports through its
  illegal argument and internal error callbacks, and the new
  `context.check()` raises it, the failed precondition verbatim, as a
  `ValueError` or a `RuntimeError`. The do-nothing stubs of the vendored
  build keep an illegal argument from aborting the process, but left the
  caller a bare 0 and no reason for it; that is unreachable through the
  bindings, which validate their arguments first, and matters for a call
  made through `lib`, as a MuSig2 session is: signing twice with the
  same secret nonce is refused by libsecp256k1 through that very
  callback. What is recorded is per thread, as the callback runs on the
  thread of the call that triggered it
- The bindings are documented as safe to call concurrently, and tested
  for it: the shared context is only mutated at import time, and a
  wheel is built for the free-threaded interpreter (`cp314t`), where
  those calls are no longer serialized

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

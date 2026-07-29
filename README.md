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
As used by the
[btclib](https://github.com/btclib-org/btclib) library.

To install (and/or upgrade):

    python -m pip install --upgrade btclib_libsecp256k1

## Versioning

btclib_libsecp256k1 version numbers track the wrapped libsecp256k1
version: release M.N.P wraps libsecp256k1 vM.N.P
(e.g. btclib_libsecp256k1 0.7.1 wraps libsecp256k1 v0.7.1).
When a new release of the bindings is needed while still wrapping the
same libsecp256k1 version, a fourth number is appended:
0.7.1.1, 0.7.1.2, etc.

## Design

These bindings are a boundary, not a library: every function is one
libsecp256k1 call, with its arguments validated first and its return
code checked. The cryptography — the algorithms, the constant-time
implementation, the side-channel hardening — is upstream's, and none of
it is reimplemented, extended or second-guessed here. Wrappers of the
same C library cannot honestly differ in what it computes, nor in how
fast; where they can differ is the boundary, and that is where the work
went:

- what runs is known: the version number names the libsecp256k1 being
  wrapped (see Versioning), pinned as a submodule and compiled from
  source with every optional module requested explicitly, upstream
  defaults not being part of its API. `__version__` describes the C
  code underneath, not the wrapper around it
- the surface is complete: every optional module is compiled in and
  reachable, through a validated binding where a function suffices and
  through the raw `lib` where only an object would do (see Wrapped
  modules). What is absent — a MuSig2 session, the ECDH hash callback,
  linking a system library — is absent by recorded decision, not by
  omission
- no input can take the process down: the bindings validate before
  calling, so a malformed key or signature raises `ValueError` naming
  the check that failed, before the C call could meet it; and the
  vendored build replaces the abort()ing libsecp256k1 default
  callbacks, so even an illegal argument handed to `lib` directly is
  survived, `context.check()` reporting it verbatim
- side channels are the context's problem, and it is handled: the one
  shared context is randomized at import time, before any thread
  exists; concurrent use is documented and tested, free-threaded
  interpreter included (see Thread safety)
- the boundary is typed: `py.typed` ships, mypy runs in strict mode,
  and the cffi extension itself is described by a hand-written stub, so
  what downstream type-checks against is the real signatures rather
  than `Any`
- validation is independent: the tests are published vectors (BIP340,
  RFC6979, third-party fixtures) and invariants over derived inputs,
  never the downstream library these bindings exist to serve; branch
  coverage is ratcheted at 100%, with only the unreachable excluded
  from the measure
- provenance is checkable: every wheel and the sdist are built and
  tested in public CI from the pinned source, and published by the
  workflow itself through Trusted Publishing with PEP 740 attestations
  — no long-lived token, and no maintainer laptop in the path

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
| `musig`             | raw `lib` bindings, by decision           |
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

`ecdh.shared_secret` returns the SHA256 of the compressed shared point,
the libsecp256k1 default. The hash function is not exposed: libsecp256k1
takes it as a C callback, and a protocol needing another derivation has
the shared point itself as `keys.pubkey_tweak_mul(pubkey, prvkey)`,
constant time like the ECDH call and without python in the middle of it.

MuSig2 has no binding module, by decision. What its two-round protocol
needs is a session whose secret nonce cannot be reused, and that is a
property of an object's lifetime rather than of a function: only whoever
owns the session can invalidate it. This package is stateless by
construction, every function being one libsecp256k1 call with its
arguments validated, so the place to enforce it is where the signing
state already lives, in [btclib](https://github.com/btclib-org/btclib):
its PSBT is the multi-party signing machinery MuSig2 plugs into, and the
specifications say the same (BIP327 the protocol, BIP373 its PSBT
fields, BIP328 its descriptors).

What MuSig2 needs from here is what has no state, and it is all present:
`keys.pubkey_sort` for the key ordering and `keys.pubkey_combine` for
aggregation, `xonly.tweak_add` for the taproot output,
`hashes.tagged_sha256`, and `ssa.verify`, an aggregate MuSig2 signature
being a plain BIP340 signature. The 17 `musig` entry points remain
available through `lib`, and `tests/test_modules.py` drives a complete
2-of-2 signing session with them.

A call made through `lib` has no argument validation in front of it, so
libsecp256k1 is the only thing checking its preconditions: it reports a
violated one through a callback of the context and returns 0, leaving
nothing in the return value to say what happened. `context.check()`
raises what was reported, the failed precondition verbatim, and is meant
to follow such a call:

    if not lib.secp256k1_musig_partial_sign(ctx, psig, secnonce, ...):
        context.check()  # ValueError, naming the failed precondition

That example is the one that matters: partial signing zeroes the secret
nonce, so signing twice with it is refused, and this is how a session
learns why. The bindings need none of this, validating their arguments
before calling, and the abort()ing libsecp256k1 defaults are replaced by
do-nothing stubs in the vendored build, so no illegal argument can take
the hosting process down.

## Thread safety

The bindings can be called concurrently from several threads. They hold
a single libsecp256k1 context, created and randomized at import time and
passed to every call: `secp256k1_context_randomize` is what mutates a
context, it runs once before any thread exists, and each call allocates
the buffers it writes to.

This matters on a free-threaded interpreter, for which a wheel is built
(`cp314t`), where those calls are no longer serialized;
`tests/test_concurrency.py` exercises it.

What `context.check()` reports is per thread: the callback recording it
runs on the thread of the call that triggered it, which is what
attributes a message to the right caller.

What is not protected is the secret material itself, which lives in
Python objects for as long as the interpreter keeps them: see
[SECURITY.md](https://github.com/btclib-org/btclib_libsecp256k1/blob/master/SECURITY.md).

## The vendored library is not optional

Linking against a libsecp256k1 already installed on the system, instead
of the vendored one, is what a distribution packager needs: Debian,
Fedora, conda-forge, Nix and Alpine have policies against vendored copies
of a cryptographic library. This package does not offer that mode, by
decision, and the account of it belongs here rather than in a closed
issue.

In favour of it:

- it is the only way to reach the users of apt, dnf and conda, who do not
  install from PyPI at all; the coincurve fork
  [libsecp256k1-py-bindings](https://github.com/MementoRC/libsecp256k1-py-bindings)
  exists to fill exactly that gap for a conda-forge recipe
- a libsecp256k1 vulnerability would then be fixed once for the whole
  system, instead of once per wheel of every package vendoring it
- it would cost little to add: the build is a single CMake path, so there
  is exactly one method to bypass, and pkg-config already knows where an
  installed library and its headers are

Against it:

- the versioning contract above breaks, and nothing can detect that it
  has: libsecp256k1 has no runtime version function, and no version macro
  in its headers either, so `__version__` would go on claiming the
  version it wraps over a library of any vintage. The only
  machine-readable version is the pkg-config field, read at build time
  and gone afterwards
- the module set stops being an assertion: headers are installed per
  module, so what is there can be detected, but a distribution ships an
  older library, without `musig` or `ellswift`, and `recovery` is off by
  default upstream. Every binding module would need a capability check,
  and the table above a column of conditions
- the abort() semantics would differ between the two builds: the shared
  context sets its own callbacks, so the bindings stay safe either way,
  but a system library is built with the abort()ing defaults, so a
  context created through `lib` could take the process down, which is
  what `tests/test_core.py` asserts cannot happen
- the test suite would become conditional on the library it finds, while
  the coverage ratchet is measured on one configuration
- it is a second build path, which unifying on CMake removed, and a
  support surface: reports about a libsecp256k1 this project did not
  build, possibly patched downstream, in consensus critical code

It stays out until a packager asks for it. The value is in opening a
channel, and the costs above are paid from the first day, whether anyone
walks it or not.

## Build, test, develop, and contribute

The vendored libsecp256k1 is built with CMake on every platform, out of
tree: the submodule is only ever read from. CMake is declared as a build
requirement, so a PEP 517 frontend provisions it and only a C toolchain
has to be there already; a system CMake 3.22 or newer serves just as
well, with `--no-build-isolation`.

The cffi extension itself is compiled with the interpreter's own
toolchain, which on Windows is the standard setuptools/MSVC one; a `gcc`
in the PATH is still required there, as it preprocesses the library
headers for cffi. Both Windows architectures are built this way: the
vendored library is built for the architecture of the interpreter, which
is what its toolchain compiles the extension for, and not for the one of
the host, which is what CMake would otherwise pick. The two differ
whenever the interpreter is emulated, and on Windows arm64 that is the
default case rather than an exotic one; the same holds for a universal2
interpreter on macOS, which needs both architectures in the archive it
links. The `win_arm64` wheels start at CPython 3.11, the first version
with a Windows arm64 build.
The dynamic (ABI mode) Windows wheel is instead cross-compiled on Linux
with mingw-w64, through the vendored CMake toolchain file, and is
x86_64 only.

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
    Submodule 'secp256k1' (https://github.com/bitcoin-core/secp256k1.git) registered for path 'secp256k1'
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
C toolchain listed above must be available.

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

To time these bindings against the other python wrappers of
libsecp256k1, and against the pure python implementation of btclib:

    uv run --group bench scripts/benchmark.py

That group is not part of `dev`, and installing it is a choice: btclib
depends on this package, so it cannot be a dependency of developing it,
and `coincurve` and `secp256k1` build a libsecp256k1 of their own, which
needs `pkg-config` besides the toolchain above.

To test against another supported interpreter, bypass the build cache:
uv keys it on the sources, which do not tell it that the compiled
extension belongs to one ABI version only.

    uv run --python 3.9 --no-cache pytest

On a Windows arm64 machine, mind which interpreter that request gets:
uv installs an x86-64 one unless the architecture is named
(`--python cpython-3.13-windows-aarch64`), reporting that support for
the native architecture is not yet mature. Both work — the build follows
the interpreter, as above — but only the native one exercises what the
`win_arm64` wheels are.

Beware that this replaces `.venv` with an environment built on that
interpreter, and leaves it there. Going back is another `uv sync`, and
`--reinstall-package btclib_libsecp256k1 --no-cache` if the extension it
finds in the cache is the one of the ABI just left behind. Requesting a
free-threaded interpreter (`--python 3.14t`) has a second effect: it
installs it as a managed one, and `uv sync` then prefers it to a system
3.14, so `uv python install 3.14` is what makes the default environment
reproducible again.

## Release process

Releases are published to PyPI by the `release` GitHub workflow using
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
no long-lived PyPI token exists anywhere; PyPI trusts the workflow
itself (via GitHub OIDC) and hands out a short-lived upload token at
run time. Wheels and sdist are uploaded with PEP 740 attestations, so
their provenance can be verified on PyPI.

The steps to cut a release, to rehearse one on TestPyPI, and the
one-time setup each index needs are in
[RELEASING.md](https://github.com/btclib-org/btclib_libsecp256k1/blob/master/RELEASING.md).

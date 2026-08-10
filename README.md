# btclib_libsecp256k1

<!-- The badges are what the reader decides with: the first line says what
this is and whether it can be used, the second whether it works, the third
where the code is and where to ask about it. A badge that reports no state
-- "we use ruff", "we use uv" -- reports a choice instead, and those are in
CONTRIBUTING.md, beside the prose that says how the choice is enforced. One
badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them. btclib and
bitcoin-core-rpc carry the same three lines. -->
[![PyPI version](https://img.shields.io/pypi/v/btclib_libsecp256k1.svg?logo=pypi)](https://pypi.python.org/pypi/btclib_libsecp256k1/)
[![downloads](https://static.pepy.tech/badge/btclib_libsecp256k1)](https://pepy.tech/project/btclib_libsecp256k1)
[![development status](https://img.shields.io/pypi/status/btclib_libsecp256k1.svg)](https://pypi.python.org/pypi/btclib_libsecp256k1/)
[![license](https://img.shields.io/github/license/btclib-org/btclib-libsecp256k1.svg)](https://github.com/btclib-org/btclib-libsecp256k1/blob/master/LICENSE)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib_libsecp256k1.svg?logo=python)](https://pypi.python.org/pypi/btclib_libsecp256k1/)

[![test workflow status](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/test.yml)
[![lint workflow status](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/lint.yml)
[![docs workflow status](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/docs.yml/badge.svg)](https://github.com/btclib-org/btclib-libsecp256k1/actions/workflows/docs.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib-libsecp256k1/master.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib-libsecp256k1/master)
[![documentation build](https://readthedocs.org/projects/btclib-libsecp256k1/badge/?version=latest)](https://btclib-libsecp256k1.readthedocs.io)

[![GitHub repository: btclib-org/btclib-libsecp256k1](https://img.shields.io/badge/GitHub-btclib--org%2Fbtclib--libsecp256k1-181717?logo=github)](https://github.com/btclib-org/btclib-libsecp256k1/)
[![slack: btclib_dev](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES)

---

Simple python bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
([v0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)).
As used by the
[btclib](https://github.com/btclib-org/btclib) library.

To install (and/or upgrade):

```shell
python -m pip install --upgrade btclib_libsecp256k1
```

## Quickstart

Sign and verify, ECDSA and BIP340. Every line below is executed by the
test suite, on every interpreter and every kind of wheel, so an example
that stops working fails a build rather than sitting here:

```python
>>> import hashlib
>>> from btclib_libsecp256k1 import dsa, keys, ssa, xonly

>>> # BIP340 test vector 1; yours comes from os.urandom or a wallet
>>> prvkey = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
>>> pubkey = keys.pubkey_from_prvkey(prvkey)
>>> msg = hashlib.sha256(b"hello").digest()

```

ECDSA, over the 32-byte hash, with the deterministic RFC6979 nonce:

```python
>>> signature = dsa.sign(msg, prvkey)
>>> dsa.verify(msg, pubkey, signature)
True

```

BIP340 Schnorr, over the same hash, against the x-only key:

```python
>>> xonly_pubkey, parity = xonly.from_pubkey(pubkey)
>>> signature = ssa.sign(msg, prvkey)
>>> ssa.verify(msg, xonly_pubkey, signature)
True

```

Both take the private key as `bytes` or as an `int`, and both return
`bytes`. What each argument may be, and what is refused rather than
coerced, is *What the boundary checks* below; every function states its
own contract in its docstring.

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
code checked. A function returning a key or a signature calls it twice:
libsecp256k1 hands back an opaque object — a `secp256k1_pubkey`, a
`secp256k1_ecdsa_signature` — that only a second call serializes into
bytes, no libsecp256k1 call producing them directly.
`keys.pubkey_from_prvkey` is `secp256k1_ec_pubkey_create` followed by
`secp256k1_ec_pubkey_serialize`; every other function returning a key or
a signature has the same shape, the second call being the serialization
the first cannot do rather than a second decision. The cryptography —
the algorithms, the constant-time
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
  survived, `context.check()` reporting it verbatim. What that
  validation is, and what it deliberately is not, is What the boundary
  checks below
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

## What the boundary checks

Every wrapper validates its arguments before calling, and what it
validates is deliberately narrow: the boundary checks what C cannot see,
and decides nothing else.

- **sizes are checked here, because nothing else can.** libsecp256k1
  takes bare pointers whose length is in the parameter name — `msg32`,
  `input32`, `seckey` — and reads a fixed number of bytes from them. Hand
  a 32-byte parameter 20 bytes and it reads past the end, and no return
  code or callback of the library can report it: the length never reached
  C to be checked. This is memory safety rather than cryptography, and it
  is the one part that cannot be left to the caller — a binding that
  reads adjacent heap into a signature when handed a short `bytes` would
  be safe only for the single caller who remembers to check first
- **and the type is checked with the size, that check being one
  question.** `len` answers for a `bytearray` and a `memoryview` as
  readily as for `bytes`, so a size check on its own let both through,
  and cffi refused them one call later in its own words and about a
  ctype — naming neither the argument nor what was wrong with it. What
  crosses is octets: `bytes`, `bytearray` or `memoryview`, plus an `int`
  where a scalar is named. Anything else is refused here and called by
  the name the signature gives it — the `TypeError` these wrappers
  raise, every other refusal below being a `ValueError`.
  The three are not a leniency of the kind refused above: each states a
  value *and* a width, so nothing has to be disbelieved and nothing
  supplied — the `int` is the wider door of the two, the 32-octet width
  being the curve's. What they are not is passed through. The copy is
  taken at the boundary, so a caller holding a secret in memory they can
  overwrite — which is the reason to reach for a `bytearray` at all —
  cannot change what libsecp256k1 is about to read
- **validity is libsecp256k1's to decide, and it does.** Whether 32 bytes
  are a scalar in `[1, n-1]` is answered by
  `secp256k1_ec_seckey_verify`, and `keys.prvkey_verify` is that call, not
  a reimplementation of it. A public key becomes one by passing
  `secp256k1_ec_pubkey_parse`, a signature by
  `secp256k1_ecdsa_signature_parse_der`, a tweak by the return value of
  the function applying it; the `ValueError` names what the library
  refused. No wrapper here knows the curve order
- **nothing is normalized into validity.** An argument of the wrong size
  raises, and is never padded: the 32 bytes of nonce entropy (`ndata`,
  `aux_rand32`, `rnd32`) are 32 bytes or omitted, a shorter value being a
  caller mistake rather than a small number. BIP340 verification
  (`ssa.verify`) and taproot tweaking (`xonly.tweak_add`,
  `xonly.tweak_add_check`) take the 32-byte x-only key and only it: a
  full public key with odd y would be verified or tweaked as a point the
  caller did not pass, so `xonly.from_pubkey` is where a y coordinate
  gets dropped, in the caller's own code. A leniency is a guess at what
  the caller meant, and that decision is theirs to make
- **the one convenience is the int scalar,** and it widens nothing. A
  private key or a tweak may be given as an `int`, checked against
  `0 <= num < 2**256` and serialized big endian. This is not the padding
  refused above: a short `bytes` states a value and a width, and accepting
  it means choosing which of the two to disbelieve, while an `int` states
  only a value — the 32-byte width is the curve's, not a fact the caller
  supplied and got wrong. The set of valid scalars is unchanged; only the
  type spelling them is. What the door is for is the caller who already
  holds a number: `mult(3)`, a vector, a tweak just computed.
  The cost is not in that serialization, which is a loop over nine CPython
  digits and measures as noise. It is that an `int` holding a secret was
  produced by python arithmetic, variable in time with the magnitude of
  its operands and leaving unzeroized copies of every intermediate on the
  heap — and that happened before this binding saw the value. `bytes` is
  not zeroized either, so what passing them buys is narrow but real: no
  arithmetic on the secret happened here. Scalar arithmetic that must not
  leak belongs where that can be promised

None of these checks branches on the content of a secret — they look at a
type, a length, or a magnitude, all of which the caller knows already —
so the constant-time guarantee is the C call's, and it is intact. What
python cannot give back is what happens on either side of that call:
`bytes` is not zeroized either, and
[SECURITY.md](https://github.com/btclib-org/btclib-libsecp256k1/blob/master/SECURITY.md)
records both limits as inherent.

And there is a way past all of it: `lib` and `ffi` are exported, and a
call made through them has no python in front of it whatsoever. That is
how MuSig2 is reachable, and it is the path for a caller who wants the
library and nothing added to it.

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

`keys` provides the public key of a private key (`pubkey_from_prvkey`,
compressed by default, of which `mult.mult_` is the uncompressed
spelling) and the scalar and point algebra (tweaking, negation,
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
fields, BIP328 its descriptors). That place already holds the session:
`btclib.ecc.musig2.sign` zeroes the secret nonce it consumes, so a
second call with it fails before a second signature exists, and
`btclib.psbt.musig2.partial_sign` carries the same guarantee into a PSBT
round.

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

```python
if not lib.secp256k1_musig_partial_sign(ctx, psig, secnonce, ...):
    context.check()  # ValueError, naming the failed precondition
```

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
[SECURITY.md](https://github.com/btclib-org/btclib-libsecp256k1/blob/master/SECURITY.md).

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

## Build

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

How to get the submodule, set up the development environment, run the
suite and the benchmarks, reproduce each CI job locally, and what a
change is expected to satisfy are in
[CONTRIBUTING.md](https://github.com/btclib-org/btclib-libsecp256k1/blob/master/CONTRIBUTING.md).

## Release process

Releases are published to PyPI by the `release` GitHub workflow using
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
no long-lived PyPI token exists anywhere; PyPI trusts the workflow
itself (via GitHub OIDC) and hands out a short-lived upload token at
run time. Wheels and sdist are uploaded with PEP 740 attestations, so
their provenance can be verified on PyPI.

The steps to cut a release, to rehearse one on TestPyPI, and the
one-time setup each index needs are in
[RELEASING.md](https://github.com/btclib-org/btclib-libsecp256k1/blob/master/RELEASING.md).

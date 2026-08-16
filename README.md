# btclib_secp256k1

<!-- The badges are what the reader decides with: the first line says what
this is and whether it can be used, the second whether it works, the third
where the code is and where to ask about it. A badge that reports no state
-- "we use ruff", "we use uv" -- reports a choice instead, and those are in
CONTRIBUTING.md, beside the prose that says how the choice is enforced. One
badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them. btclib and
bitcoin-core-rpc carry the same three lines. -->
[![PyPI version](https://img.shields.io/pypi/v/btclib_secp256k1.svg?logo=pypi)](https://pypi.python.org/pypi/btclib_secp256k1/)
[![downloads](https://static.pepy.tech/badge/btclib_secp256k1)](https://pepy.tech/project/btclib_secp256k1)
[![development status](https://img.shields.io/pypi/status/btclib_secp256k1.svg)](https://pypi.python.org/pypi/btclib_secp256k1/)
[![license](https://img.shields.io/github/license/btclib-org/btclib-secp256k1.svg)](https://github.com/btclib-org/btclib-secp256k1/blob/main/LICENSE)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib_secp256k1.svg?logo=python)](https://pypi.python.org/pypi/btclib_secp256k1/)

[![test workflow status](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/test.yml)
[![lint workflow status](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/lint.yml)
[![docs workflow status](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/docs.yml/badge.svg)](https://github.com/btclib-org/btclib-secp256k1/actions/workflows/docs.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib-secp256k1/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib-secp256k1/main)
[![documentation build](https://readthedocs.org/projects/btclib-secp256k1/badge/?version=latest)](https://btclib-secp256k1.readthedocs.io)

[![GitHub repository: btclib-org/btclib-secp256k1](https://img.shields.io/badge/GitHub-btclib--org%2Fbtclib--libsecp256k1-181717?logo=github)](https://github.com/btclib-org/btclib-secp256k1/)
[![slack: btclib_dev](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES)

---

Simple python bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
([v0.8.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.8.0)).
As used by the
[btclib](https://github.com/btclib-org/btclib) library.

To install (and/or upgrade):

```shell
python -m pip install --upgrade btclib_secp256k1
```

## Quickstart

Sign and verify, ECDSA and BIP340. Every line below is executed by the
test suite, on every interpreter and every kind of wheel, so an example
that stops working fails a build rather than sitting here:

```python
>>> import hashlib
>>> from btclib_secp256k1 import dsa, keys, ssa, xonly

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

btclib_secp256k1 version numbers track the wrapped libsecp256k1
version: release M.N.P wraps libsecp256k1 vM.N.P
(e.g. btclib_secp256k1 0.8.0 wraps libsecp256k1 v0.8.0).
When a new release of the bindings is needed while still wrapping the
same libsecp256k1 version, a fourth number is appended:
0.7.1.1, 0.7.1.2, etc.

## The name

This package was `btclib_libsecp256k1` up to and including 0.7.1.3, and
0.8.0 is the first release under this name. `lib` named the C library
being wrapped, and a python distribution is not that library: it is
btclib's bindings to secp256k1, which is what the name now says.

Nothing on PyPI bridges the two, deliberately: `btclib_libsecp256k1`
stops at 0.7.1.3 and stays installable, wrapping libsecp256k1 0.7.1, and
`pip install btclib_libsecp256k1` keeps resolving to it rather than
following the rename. Moving means changing the requirement and the
import, which are the same edit twice:

```diff
-btclib_libsecp256k1>=0.7.1.3
+btclib_secp256k1>=0.8.0
```

```diff
-from btclib_libsecp256k1 import dsa, keys, ssa, xonly
+from btclib_secp256k1 import dsa, keys, ssa, xonly
```

The two can be installed side by side while that happens: the import
package was renamed with the distribution, so neither shadows the other.
Everything inside the API — the module names, every function, and the
`ffi` and `lib` a caller reaches MuSig2 through — is unchanged.

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
the first cannot do rather than a second decision.

A function that does make a second decision is named after both of them
and is here for one reason: what the composition saves is the crossing
between its halves, which is the caller's cost and not its own choice.
`xonly.from_prvkey` is the private key's public key and then the x of
it; `keys.pubkey_tweak_mul_sum` is a `pubkey_tweak_mul` per term and one
`pubkey_sum` over them, which is the multi-scalar multiplication a
verification equation is written as, with no product serialized on its
way into the sum. Neither computes anything libsecp256k1 does not: the
arithmetic is upstream's calls in the order the equation names them, and
*Parsing the key once* below is where the crossing they save is
measured. One entry point is more than a composition, and it is
`dsa.sign(grind=True)`: a loop that signs again, with a counter mixed
into the nonce, until `r` is the low one. That is Bitcoin Core's
`CKey::Sign` and not a scheme of this package's — a signer's size policy,
which is why it is asked for and never done by default — and *Grinding
for a low r* below is where its cost, and the reason the loop is python
rather than C, are measured. The cryptography —
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
  — no long-lived token, and no maintainer laptop in the path. The sdist
  attached to the GitHub release carries a build provenance attestation
  besides, which `gh attestation verify` checks; SECURITY.md has the
  command

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
- **and a caller validating its own input gets a verdict, not an
  exception.** `keys.prvkey_verify`, `keys.pubkey_verify`,
  `xonly.pubkey_verify` and `dsa.signature_verify` are the four: the same
  proof the `parse` beside each of them makes, with nothing kept and
  nothing to catch. A library holding octets at its own boundary has its
  own word for what is wrong with them, and an exception carrying this
  package's word for it is a message it would have to translate. The
  length is part of the verdict — 34 octets are no public key, and
  answering `False` is what a caller asking "do I have one" wants — where
  every entry point that goes on to *use* the key raises instead
- **nothing is normalized into validity.** An argument of the wrong size
  raises, and is never padded: the 32 bytes of nonce entropy are 32 bytes
  or omitted, a shorter value being a caller mistake rather than a small
  number. They are `aux_rand32` in every module that takes them, BIP340's
  own name for the pair libsecp256k1 spells `ndata` here and `rnd32`
  there, and what omitting them means is the one thing that differs:
  fresh randomness where BIP340 and BIP324 ask for it, and the RFC6979
  nonce alone where ECDSA leaves it deterministic. Taking a public key in any
  of its three serializations is not a leniency of that kind and is worth
  the distinction: BIP340 verification (`ssa.verify`) and taproot
  tweaking (`xonly.tweak_add`, `xonly.tweak_add_check`) take 32, 33 or 65
  octets because `02 || x`, `03 || x` and `04 || x || y` are one key —
  `lift_x` is the even-y point whatever form the x arrived in, and a
  signer whose point has odd y signs with `n - d` for that reason. The y
  is not consulted rather than guessed at, and `xonly.from_pubkey`
  answers which form was handed in for a caller that wants to know. A
  leniency is a guess at what the caller meant, and that decision is
  theirs to make.
  `dsa.verify(..., normalize=True)` is that decision made, rather than an
  exception to it: ECDSA signatures are malleable, which of the two forms
  one carries was the signer's choice, and a caller checking signatures
  it did not make says so in the call instead of round-tripping the
  signature through `dsa.normalize` and back into DER. Off, which is the
  default, a signature outside the lower-s form is refused as before
- **the one convenience is the int scalar,** and it widens nothing. A
  private key or a tweak may be given as an `int`, checked against
  `0 <= num < 2**256` and serialized big endian. This is not the padding
  refused above: a short `bytes` states a value and a width, and accepting
  it means choosing which of the two to disbelieve, while an `int` states
  only a value — the 32-byte width is the curve's, not a fact the caller
  supplied and got wrong. The set of valid scalars is unchanged; only the
  type spelling them is. What the door is for is the caller who already
  holds a number: a nonce, a vector, a tweak just computed.
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
[SECURITY.md](https://github.com/btclib-org/btclib-secp256k1/blob/main/SECURITY.md)
records both limits as inherent.

And there is a way past all of it: `lib` and `ffi` are exported, and a
call made through them has no python in front of it whatsoever. That is
how MuSig2 is reachable, and it is the path for a caller who wants the
library and nothing added to it.

## Parsing the key once

A public key crosses this boundary as octets, and every wrapper taking
one begins by parsing it — for a compressed key that is a field square
root, which is a measurable part of the verification that follows it. A
caller that has already paid for that parse can hand it on instead of
paying again: `keys.parse` returns the libsecp256k1 object, and every
wrapper whose first act is to build one has a half that takes it in
place of the octets.

That half is spelled `_foo_`, and both underscores are load-bearing. The
leading one says private, and means it: an object is a promise no
argument check can hold a caller to, so what answers for a wrong one is
libsecp256k1's own illegal-argument callback, and a caller reaching for
these is past the boundary that proves things. The trailing one says
which kind of private — `_verify_` takes a parsed key where `_parse_der`
is an ordinary helper.

**A private half does not read that callback**, and what it answers when
libsecp256k1 refuses its object is therefore whatever the C call
answered: its own exception where a return code allowed one, and
otherwise a value that means nothing — `False` from a verification, an
ordering from a comparison, `None` from a sum, and, in `ecdh`, 32 bytes
that are a shared secret with nobody. Nothing raises in those four.
`context.check()` immediately after the call is what says so, and
proving the object once — `keys.parse` built it, or `keys.pubkey_verify`
answered for the octets it came from — is what makes the question moot.
The public half has no such case, having parsed its own octets, and that
is the whole of what a caller gives up by reaching past it.

```python
>>> ecdsa_sig = dsa.sign(msg, prvkey)
>>> parsed = keys.parse(pubkey)           # a valid point: proved once
>>> parsed_sig = dsa.parse_der(ecdsa_sig)
>>> dsa._verify_(msg, parsed, parsed_sig)  # used, rather than proved again
True

```

The public half is the private one with a `parse` in front of it, and
nothing else about the two differs: the remaining arguments are checked
exactly as before, a bare pointer's length being what no C return code
can report. The callers this is for are the one that validates a key and
then verifies with it, the one checking several signatures against a
single key, and the one asking `is_low_s` about a signature it is about
to verify. `xonly.parse` is the same thing for the x coordinate BIP340
verifies against, `dsa.parse_der` and `dsa.parse_compact` for the two
serializations of a signature, and every one of them has a `serialize`
beside it turning the object back into octets.

The other side of the boundary is spelled the same way. A wrapper that
*produces* an object — recovering a key from a signature, decoding it,
deriving it, adding keys together, signing — serializes what
libsecp256k1 handed it already made, and its private half answers with
the object instead:

```python
>>> from btclib_secp256k1 import recovery
>>> sig, recid = recovery.sign(msg, prvkey)
>>> parsed_recoverable = recovery.parse_compact(sig, recid)
>>> recovered = recovery._recover_(msg, parsed_recoverable)  # the point
>>> dsa._verify_(msg, recovered, parsed_sig)                 # as it stands
True

```

So `_foo_` means one thing in both directions: the half that speaks in
libsecp256k1 objects, where the public half speaks in octets. What it
buys is what composing two wrappers otherwise pays between them — a
serialization of a point that was already in hand, and a parse of what
was just serialized, which for the compressed form is that square root
again. Sorting keys and then adding them together is the composition
that pays it per key; scanning block after block for a silent payment
pays it per transaction, which is why `silentpayments` has a private
half for each of its three entry points, the summary of a transaction's
inputs included.

Some compositions are an entry point instead of two halves, where what
the caller wanted was the composition. `xonly.from_prvkey` is the
x-only public key of a private key — the two halves above composed,
which is what BIP340 and BIP341 ask for and what this package used to
make every caller spell in two steps, with a full public key in the
middle that nothing wanted. `keys.pubkey_tweak_mul_sum` is the other:
a term per scalar and one sum over them, which is a verification
equation, a MuSig2 aggregate key and BIP352's tweak data, and where the
crossing is per term — every product serialized as 65 octets only for
the sum to parse them again. Handed over whole it is about a seventh of
the call from three terms up and stays there, 64 terms 459.3 µs against
536.5; the CHANGELOG entry that added it has the count-by-count table
and the conditions. It is the naive form and not a batched algorithm:
`secp256k1_ecmult_multi_var` is internal to libsecp256k1 and not
declared in its public header, so what is saved here is the crossing,
which is flat in the number of terms.

`ssa.Signer.pubkey` reads that same key off the keypair the signer
already holds, which is a read rather than a multiplication, and so is
cheaper than any composition could be.

## Two outposts past the boundary

The private halves above hand one object from a call to the next. What
they do not answer is the caller who crosses the boundary again and
again with the *same* key: a signer signing message after message, a
wallet walking a BIP32 path one index at a time. Each crossing pays the
conversion at its far end — a keypair is a point multiplication, a
compressed key is a field square root — and pays it for a key it had
already converted.

`ssa.Signer` and `keys.PubkeyTweakChain` are the two outposts on that
side of the boundary, and the only things in these bindings that hold
state at all. Each holds the converted object across calls, so the
conversion happens once and every crossing afterwards carries only what
changes: a message, a tweak.

The two are not worth the same, and the numbers below say which is
which. A keypair is *arithmetic* — a point multiplication, half of what
a signature costs — and no serialization would give it back. A parsed
public key is a *parse*, and the caller can make that parse cheap by
carrying the uncompressed form instead: 0.269 microseconds against
2.326. So the signer saves what nothing else can, and the chain saves
what a caller free to choose its serialization could have saved itself.

**The rule that separates them is the test a third outpost would have to
pass**, and it is worth stating on its own, because the answer to every
proposal of one — a held public key for verifying, for ECDH, for
combining — is here rather than in the proposal:

> what an object saves is the cost of *rebuilding, from octets, whatever
> it holds*. It earns its state when that cost is arithmetic, and does
> not when it is a parse.

The saving is not merely bounded by that cost; it *is* that cost, and by
construction rather than by measurement. `ssa.sign` builds the keypair,
signs with it and wipes it; `signer.sign` is that middle term with the
first already paid — so the difference between them is
`secp256k1_keypair_create` on any machine, and what the numbers below
add is that nothing else of consequence sits in it. They are the ones
this section already states: 15.82 microseconds against the signer's
8.27, of which the keypair is 7.55, and 15.82 − 8.27 is that 7.55.

The chain reads the same way and answers differently, which is the
distinction of the paragraph above arrived at from the other end. What
it saves is the parse it holds, so *which* parse decides the figure —
and that is the pair the paragraph above states, the caller's to choose
by the serialization they carry. A keypair offers its caller no such
choice.

Two things the rule needs said, or it reads as narrower than it is. The
first is what recovers a parse, and it is **`keys.parse` itself, not a
cheaper serialization**. The argument through the uncompressed form does
not reach an x-only key, which is a field square root to rebuild and has
no second serialization to escape to — and it does not always reach a
full one either, which is what the walk below measures: from the 33
octets an xpub carries, reaching the uncompressed form costs a
`reserialize` that the chain does not pay. A caller who wants the parse
held holds it — `keys.parse` hands back the object and the private
halves take it, which is what "the private halves above hand one object
from a call to the next" already promised. What a class would add there
is a name, not a saving. The second is the other side of the ledger:
this package is [stateless by construction](#design), which is also why
MuSig2 is not
wrapped, so an object is an exception to that, with an owner and an
invalidation and a threading story, and the rule is what the exception
has to be paid for with. What it does not weigh is ergonomics — the line
a caller does not have to write is real, and belongs in btclib along
with the lifetimes.

So the numbers **confirm** the rule rather than establish it, and it is
worth being clear which of them would survive a different machine. Not
the microsecond counts, which are one laptop's; the identity is what
carries, and it carries because it is structural rather than because a
ratio travels better than an absolute. A rule resting instead on which
of two measurements is larger would invert on the first machine that
measured them differently — and one such pair is a rounding error apart,
which the walk below is about.

`ssa.Signer` holds the keypair:

```python
>>> messages = [hashlib.sha256(bytes([index])).digest() for index in range(3)]
>>> with ssa.Signer(prvkey) as signer:
...     signatures = [signer.sign(each) for each in messages]
>>> [ssa.verify(m, xonly_pubkey, s) for m, s in zip(messages, signatures)]
[True, True, True]

```

`ssa.sign` builds that keypair, signs with it and overwrites it before
returning, so a caller signing a second message under the same key builds
it again — and it is about half of what a BIP340 signature costs here,
15.82 microseconds against the signer's 8.27, of which the keypair is
7.55. `signer.pubkey()` reads the x-only key off it rather than deriving
it a second time.

`keys.PubkeyTweakChain` holds the parsed point:

```python
>>> tweaks = [hashlib.sha256(bytes([index])).digest() for index in range(5)]
>>> chain = keys.PubkeyTweakChain(pubkey)
>>> path = [chain.tweak_add(tweak) for tweak in tweaks]
>>> path[-1] == chain.pubkey()
True

```

That is a BIP32 path walked one index at a time, and the shape of it is
what costs: each step needs the previous step's *serialized* key to hash
into the next tweak, so `pubkey_tweak_add` on the compressed form parses
at every step the very point the step before had built and serialized —
64.62 microseconds against the chain's 55.14, for the five steps above,
which is the 2.326 of a compressed parse saved four times.

What that comparison leaves out is the caller's other move, and it is
worth stating because it is nearly free: walking the same path in the
*uncompressed* form and compressing each answer in python is 54.75, which
is the chain's 55.14 within the noise. The uncompressed parse is 0.269,
so there is almost nothing left for holding the point to save — the
chain's saving is real against the compressed walk and a rounding error
against that one, where the caller already holds the 65 octets — which
two paragraphs below is the assumption that turns out to decide it. What
it is unambiguously worth is not having to write
`bytes([2 + (sec[64] & 1)]) + sec[1:33]` where BIP32 wants 33 octets to
hash. `chain.pubkey()` is the key it has arrived at, and
`chain._pubkey_()` the point itself for a caller handing it on.

The two moves do not compose into a third saving, which is worth saying
because the shape of them invites it. A chain answers whichever
serialization it is asked for, but it re-parses nothing in either: the
point is what it holds. So `chain.tweak_add(compressed=False)` saves no
parse that `chain.tweak_add()` had been paying, and gives back the line
above to be written at every step — it measures slightly slower, for the
serialization and that line, and it is not the spelling to reach for.

What the three numbers do leave unasked is where the walk *starts*. An
xpub carries the 33 octets, so a caller taking the uncompressed path
reaches its starting form through `keys.reserialize` — a compressed
parse, the 2.326 above, and a serialization — before the first step,
and that is rather more than the 0.39 separating the two walks. Counted
from the key a BIP32 caller actually holds, the chain is *ahead* of the
uncompressed walk rather than a rounding error behind it: the parse it
pays at construction is the one that caller could not have avoided, and
it pays it once where the compressed walk pays it five times. Which
does not make the chain's saving arithmetic — this section's distinction
stands — but it is the parse the caller could not make cheap, which is
the case the class is for.

What the two do not share is what they hold. A parsed public key is a
public value a caller may keep for as long as it likes; a keypair is the
private key in libsecp256k1's own layout, so the signer hands the caller
a lifetime and not only a saving. That is what the `with` block is for:
on the way out of it the keypair is overwritten, whether the block ended
in a signature or in an exception, and a wiped signer refuses to sign
rather than signing with the zeros left behind. `signer.wipe()` is the
same instruction spelled by hand, for a caller who is done before the
block is. The chain needs none of it, and has none of it. What none of it
changes is the python side: the `bytes` or `int` the constructor is
handed is a python object like any other, and
[SECURITY.md](https://github.com/btclib-org/btclib-secp256k1/blob/main/SECURITY.md)
records why that copy cannot be taken back.

ECDSA has no counterpart, and the reason is in the equation rather than
in the C signature. BIP340 challenges with `e = H(R ‖ P ‖ m)`, so the
*public* key is an input to every signature: it has to be derived, which
is a point multiplication, and the keypair is where it is kept — with
the parity that decides whether the signature is made with `d` or with
`n - d`. ECDSA signs `s = k⁻¹(z + r·d)`, and `P` appears nowhere in it.
There is no object derived from the key, and so nothing to hold across
calls.

What a `dsa.Signer` could save is the argument check `scalar` makes of
the private key: 0.117 microseconds of the 12.93 a signature costs, where
`ssa.Signer` saves the 7.55 of 15.82. What it would cost is the lifetime
the paragraph above describes, a second copy of the secret held for as
long as the signer is. That trade is worth making for half a signature
and not for a hundredth of one.

What does cost in `dsa.sign` is the DER serialization, 0.757
microseconds, and a caller who wanted the other form never has to pay it:
`compact=True` answers the 64 octets of `r ‖ s` directly, where reaching
them through `to_compact` writes the DER and parses it straight back.

## Grinding for a low r

`dsa.sign(grind=True)` answers the signature of the same key and message
whose `r` has its high bit clear. DER spends a leading zero octet on an
integer whose top bit is set, so that signature encodes one octet
shorter — which is what Bitcoin Core's `CKey::Sign` grinds for, and this
is Core's scheme rather than a rephrasing of it: the first attempt is the
plain RFC6979 signature, and each retry mixes a `uint32` counter, little
endian in the first 4 of 32 octets, into the nonce. Written any other
way it would answer octets nobody else answers; written this way,
`tests/test_vectors.py` holds it to Core's own vectors and to
rust-secp256k1's.

It costs a signature and then some: 25.23 microseconds against the 12.62
of a plain one, measured beside it over 2000 keys, because half the
attempts are wasted and the tail is longer than the average — 2.09
attempts on the mean, and the worst of those 2000 keys took 14. That is
why it is a parameter and not the default, and why `s` is not mentioned
in the same breath: libsecp256k1 has already returned the lower of the
two, so there is nothing there to grind for.

Where the loop is written was measured, not assumed. In the compact form,
which is what the retry tests: 25.90 microseconds for a loop calling the
wrappers once per attempt, 24.82 for what is implemented — the key
checked once, the two scratch buffers allocated once per call — and 23.82
for the same loop with those buffers held at module level, which a
package with one shared context and a
[thread safety](#thread-safety) story does not get to do. A loop compiled
in C would have started from that last number, so what crossing the
boundary twice on average actually costs is about a microsecond of
twenty-five. It buys nothing here, and it would have cost the one thing
these bindings do not trade: a
[dynamic build](#the-vendored-library-is-not-optional) compiles no C at
all, so a C helper would be a feature the static wheels have and the
dynamic ones do not.

What the loop tests is the compact serialization, and not the DER
length, which is not the same question: DER is `6 + lenR + lenS`, so a
high `r` of 33 octets with an `s` that happens to need only 31 encodes to
70 octets too — about one signature in 500 — and a length test would
take those for low-r ones. The first octet of the compact form is the top
of `r`, which is exactly what Core's `SigHasLowR` reads.

The entropy argument is refused together with it. Grinding writes the
very 32 octets `aux_rand32` is, so `dsa.sign(msg, key, aux, grind=True)`
raises rather than resolving silently in favour of one of them.
`recovery.sign` has no `grind`, and the reason is that there is nothing
to shorten: a recoverable signature is 65 fixed octets, so grinding one
would buy the caller two signatures' worth of nothing.

## Wrapped modules

All the optional libsecp256k1 modules are compiled in and their
declarations are available through the `lib` and `ffi` cffi objects:

| libsecp256k1 module | bindings                                  |
| ------------------- | ----------------------------------------- |
| (core)              | `dsa`, `keys`, `hashes`                   |
| `ecdh`              | `ecdh`                                    |
| `recovery`          | `recovery`                                |
| `extrakeys`         | `xonly`, used by `ssa`                    |
| `schnorrsig`        | `ssa`                                     |
| `musig`             | raw `lib` bindings, by decision           |
| `ellswift`          | `ellswift` (BIP324)                       |
| `silentpayments`    | `silentpayments` (BIP352)                 |

`keys` provides the public key of a private key (`pubkey_from_prvkey`,
compressed by default, `compressed=False` for the uncompressed form)
and the scalar and point algebra (tweaking, negation,
combination, arbitrary point multiplication, and the multi-scalar
multiplication of `pubkey_tweak_mul_sum`) underlying BIP32 key
derivation, plus the lexicographic ordering of public keys (`pubkey_cmp`,
`pubkey_sort`) that BIP67 and MuSig2 key aggregation call for; `xonly`
provides the BIP341 taproot tweaking of x-only public keys and of their
private keys, and the x-only public key itself, from a full public key
(`from_pubkey`) or straight from a private key (`from_prvkey`);
`hashes` provides the BIP340 tagged hash, the domain separation the
taproot tags are built on.

Wherever one of these answers a *secret* — a tweaked or negated private
key, a shared secret, a nonce — it also takes a keyword-only `into`: a
writable buffer of exactly 32 contiguous octets, which receives the
secret in place of the `bytes` the call would otherwise return, so that
the copy the caller is left holding is one they can overwrite. It is an
addition and not a change; omit it and nothing differs. SECURITY.md is
where what it does and does not buy is stated, and names the two
`silentpayments` secrets it does not reach.

Two of those have a second spelling for a caller doing arithmetic rather
than holding a key. `keys.pubkey_sum` is `pubkey_combine` with the point
at infinity answered as `None` instead of refused: `P + (-P)` is the
identity, which a curve library has a value for and which no
`secp256k1_pubkey` can hold, so the sum that is no public key is the one
thing the two calls do differently. And `xonly.to_pubkey` is the lift:
an x-only key is an x, the point it names is the one with even y, and
reading that y is `secp256k1_ec_pubkey_parse` of `0x02 || x` — octets a
caller used to write itself, there being no libsecp256k1 call from an
x-only object back to a point.

Converting between two serializations of the same value is
`keys.reserialize` for a key and `dsa.to_der` and `dsa.to_compact` for a
signature. Two names there and one here, because which serialization a
signature arrived in cannot be read off its octets: a DER signature of 64
of them exists, and begins with the `0x30` a compact `r` may begin with
too. So the input form is named by the call, as `compact` names it on
`dsa.sign` and `dsa.verify`, where a key's is read from its length.

`ssa.sign` signs a 32-byte message hash, as bitcoin does; `ssa.sign_custom`
signs a message of any length, which BIP340 allows and which a protocol
of its own may define.

`dsa.nonce_rfc6979` and `ssa.nonce_bip340` answer the nonce each signer
derives, which is the one part of signing these bindings used to compute
and never show. libsecp256k1 exports both derivations as callable
pointers, so this is the C function itself rather than a second
implementation of it, called with what the signer passes it -- and what
comes back is the `k` of the signature the same arguments produce, which
is how `tests/test_nonces.py` checks it: `r` is the x of `k` times the
generator. A python implementation of either derivation has published
vectors and, until now, no oracle. The nonce is the secret a signature is
built on, so reading one into python takes it out of constant-time code:
what these are for is checking a derivation, not driving one.

`ecdh.shared_secret` returns the SHA256 of the compressed shared point,
the libsecp256k1 default. The hash function is not exposed: libsecp256k1
takes it as a C callback, and a protocol needing another derivation has
the shared point itself as `keys.pubkey_tweak_mul(pubkey, prvkey)`,
constant time like the ECDH call and without python in the middle of it.

`silentpayments` is BIP352, and the elliptic curve half of it, which is
what libsecp256k1 implements: `create_outputs` is the sender's side and
takes the private keys of the inputs the payment is funded from,
`prevouts_summary` and `scan_outputs` the recipient's, and `label` and
`labeled_spend_pubkey` the several addresses one scan key can receive
at. What is not there is what BIP352 states over scripts -- which inputs
of a transaction are eligible, and which of those are taproot -- because
that is a script question and there is no script here: the two kinds of
key are two arguments, and the caller says which is which.
`tests/test_vectors.py` drives both directions of every BIP352 vector,
and reads that eligibility off the keys the vector file itself publishes
rather than off its scripts, for the same reason.

Two things about it are worth knowing before it is used. The summary
`prevouts_summary` returns is opaque and not a serialization: what is
inside is libsecp256k1's own, portable across neither platforms nor
versions, and the only thing to do with it is hand it to `scan_outputs`
in the same process. And the label cache is a mapping the caller owns:
libsecp256k1 recognizes a label by calling back to look it up, so a
labeled output is found only if its label is in the mapping handed in --
which is also why the keys of that mapping are `bytes` and only bytes,
a `bytearray` and a `memoryview` not being hashable.

`secp256k1_context_set_sha256_compression`, new in libsecp256k1 0.8.0,
has no binding, by the decision that keeps the ECDH hash out: it replaces
the SHA256 compression function the library uses internally, and its
purpose is to route it to a hardware implementation. Reached from python
it would do the opposite -- a python call per 64-byte block, in the
innermost loop of every hash the library computes -- so what it is for is
unreachable through these bindings and what it would be is a way to make
them slow. It remains available through `lib` for a caller who has a C
function pointer to give it.

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
learns why. The entry points taking octets need none of it, validating
their arguments before calling; the private halves taking an object need
exactly it, for the reason that parsing the key once gives. Either way the
abort()ing libsecp256k1 defaults are replaced by do-nothing stubs in the
vendored build, so no illegal argument can take the hosting process
down.

## Thread safety

The bindings can be called concurrently from several threads. They hold
a single libsecp256k1 context, created and randomized at import time and
passed to every call: `secp256k1_context_randomize` is what mutates a
context, it runs once before any thread exists, and each call allocates
the buffers it writes to.

This matters on a free-threaded interpreter, for which a wheel is built
(`cp314t`), where those calls are no longer serialized;
`tests/test_concurrency.py` exercises it.

The two outposts above are what hold a buffer across calls, and they
answer differently. `ssa.Signer` does not cost that guarantee:
libsecp256k1 takes a keypair const, so several threads may sign through
one signer. What is theirs to order is the wipe, which overwrites the
very memory a concurrent signature is reading — the same shape of race as
re-randomizing the context below, and the reason the `with` block ends
where the threads have joined.

`keys.PubkeyTweakChain` is the exception, and by construction:
`secp256k1_ec_pubkey_tweak_add` takes its key as *in and out*, so every
`tweak_add` writes the point the chain holds. One chain belongs to one
thread, and a path is a sequence in any case — two threads sharing one
are not two walkers of it but two writers of the same point. Each thread
that wants one builds its own, which costs the parse the chain exists to
pay once.

The one way to lose that guarantee is to re-randomize the shared context
while it is in use. `context._randomize(context.ctx)` is there for a
caller who wants fresh blinding, and libsecp256k1 asks for exclusive
access to a context to mutate one: call it before the threads start, or
hold a read-write lock over every call that takes `ctx`.

What `context.check()` reports is per thread: the callback recording it
runs on the thread of the call that triggered it, which is what
attributes a message to the right caller.

What is not protected is the secret material itself, which lives in
Python objects for as long as the interpreter keeps them: see
[SECURITY.md](https://github.com/btclib-org/btclib-secp256k1/blob/main/SECURITY.md).

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
suite, reproduce each CI job locally, and what a change is expected to
satisfy are in
[CONTRIBUTING.md](https://github.com/btclib-org/btclib-secp256k1/blob/main/CONTRIBUTING.md).

## Release process

Releases are published to PyPI by the `release` GitHub workflow using
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/):
no long-lived PyPI token exists anywhere; PyPI trusts the workflow
itself (via GitHub OIDC) and hands out a short-lived upload token at
run time. Wheels and sdist are uploaded with PEP 740 attestations, so
their provenance can be verified on PyPI; the sdist attached to the
GitHub release is signed a second time, so that copy can be verified
without the index.

The steps to cut a release, to rehearse one on TestPyPI, and the
one-time setup each index needs are in
[RELEASING.md](https://github.com/btclib-org/btclib-secp256k1/blob/main/RELEASING.md).

## Comparison

Wrappers of the same C library cannot honestly differ in what it
computes, nor in how fast — the point Design makes above about where the
actual work goes, `coincurve`, `secp256k1-py` and `electrum-ecc`
included, every one of them the same libsecp256k1 underneath. That does
not make the difference unmeasurable, only certain about what it is a
difference *in*: not the cryptography, which is upstream's regardless of
which wrapper calls it, but the boundary each one places around the same
calls — how much a caller pays to cross it. Measuring that honestly, and
publishing the run rather than a claim, is what
[btclib-benchmarks](https://github.com/btclib-org/btclib-benchmarks)
is for, and
[the libsecp256k1 wrappers table](https://github.com/btclib-org/btclib-benchmarks/blob/main/results/libsecp256k1-wrappers.md)
is where this project's own boundary is timed against the others', one
run kept whole rather than reduced to a single figure — an order of
magnitude to read there, never a number to quote here.

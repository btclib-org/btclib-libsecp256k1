# Release notes

Notable changes to the codebase are documented here. Every entry of a
release is in [CHANGELOG.md](./CHANGELOG.md); what follows is what a user
has to act on and what a user gains, and it is what the GitHub release of
a tag is generated from.

## v0.8.0.3 (work in progress, not released yet)

**Breaking: one module is gone, and every other break is a rename.**
The public surface of these bindings speaks in octets, and the two
changes are that sentence made true. The half of each call that speaks in
libsecp256k1 objects is now private, spelled `_foo_` where it was `foo_`,
and no behaviour changed with those names: a caller holding parsed keys
renames what it calls. The `mult` module is what went
rather than moved: `mult.mult` answered coordinates where every other
entry point answers octets, and what that left — `mult_bytes` — was
`keys.pubkey_from_prvkey` with a flag fixed, so the module folded into
the one it delegated to. A caller of either has one line to change, and
everything else in the octets API is what it was.

| module | was | is |
| --- | --- | --- |
| `keys` | `pubkey_from_prvkey_` | `_pubkey_from_prvkey_` |
| `keys` | `pubkey_negate_` | `_pubkey_negate_` |
| `keys` | `pubkey_tweak_add_` | `_pubkey_tweak_add_` |
| `keys` | `pubkey_tweak_mul_` | `_pubkey_tweak_mul_` |
| `keys` | `pubkey_combine_` | `_pubkey_combine_` |
| `keys` | `pubkey_cmp_` | `_pubkey_cmp_` |
| `keys` | `pubkey_sort_` | `_pubkey_sort_` |
| `xonly` | `from_pubkey_` | `_from_pubkey_` |
| `xonly` | `tweak_add_` | `_tweak_add_` |
| `dsa` | `verify_` | `_verify_` |
| `ssa` | `verify_` | `_verify_` |
| `ecdh` | `shared_secret_` | `_shared_secret_` |
| `recovery` | `recover_` | `_recover_` |
| `ellswift` | `encode_`, `decode_` | `_encode_`, `_decode_` |
| `silentpayments` | `label_` | `_label_` |
| `silentpayments` | `labeled_spend_pubkey_` | `_labeled_spend_pubkey_` |
| `mult` | `mult_`, `mult_bytes` | `keys.pubkey_from_prvkey` |
| `mult` | `mult` | *gone: see below* |

**What the removals cost a caller.** `mult.mult` answered the pair of
coordinates as ints, which is the one place a point of the curve left this
package as numbers instead of as a serialization. What it did is two
`int.from_bytes` over the halves of `mult_bytes`, and they are 0.138
microseconds of a call that is some 8.5 — 1.6% of it, and about what the
python frame that used to hold them cost in the other direction:

```diff
-x, y = mult.mult(num)
+sec = keys.pubkey_from_prvkey(num, compressed=False)
+x, y = int.from_bytes(sec[1:33], "big"), int.from_bytes(sec[33:], "big")
```

And `mult_bytes` is the call it always was, under the name of the module
that makes it:

```diff
-sec = mult.mult_bytes(num)
+sec = keys.pubkey_from_prvkey(num, compressed=False)
```

Three of the renamed take a different argument as well, the object having
replaced the octets there too: `dsa._verify_` takes the parsed signature
`dsa.parse_der` returns, and `recovery._recover_` the parsed pair
`recovery.parse_compact` returns, in place of a signature and a recovery
id. And four argument names changed: the 32 bytes of nonce entropy are
`aux_rand32` everywhere, where `dsa.sign` and `recovery.sign` called
them `ndata` and `ellswift.encode` called them `rnd32`, and
`silentpayments.prevouts_summary` takes `taproot_pubkeys_bytes` and
`pubkeys_bytes`. All four are keyword names; a positional call is
unaffected.

What the rest of the release adds: one for a caller that signs more than
once under one key, one for a caller whose ECDSA signatures go into a
transaction, one for a caller computing a taproot output key from a
public key it has validated, a set for a caller composing two of these
calls where the second used to parse what the first had just serialized,
and one for a caller that would rather hold octets than a parsed key at
all.

`ssa.Signer` is new: it builds the BIP340 keypair once and signs with it
as often as asked, where `ssa.sign` and `ssa.sign_custom` build one per
call and wipe it before returning. That keypair is about half of what a
signature costs — 15.7 microseconds a signature through `ssa.sign`
against 8.2 through a signer, on the machine and with the method
CHANGELOG.md states — so a caller signing a batch under one key roughly
halves it. Both functions are unchanged in behaviour and cost, and are
still the right call for a single signature.

What a signer holds is a secret, and it is the caller's for as long as
they hold it: use it in a `with` block, which overwrites the keypair on
the way out whether the block ended in a signature or in an exception.
`signer.wipe()` says the same thing by hand, and a wiped signer refuses
to sign rather than signing with what the wipe left. Neither is a
formality: a signer that is simply dropped is collected with the keypair
still holding the key, cffi freeing that memory without overwriting it,
and nothing runs behind the caller to do it — SECURITY.md now names this
as the one buffer of the package whose zeroing is asked for rather than
done. The private key handed to the constructor is a python `bytes` or
`int` and is no more zeroizable than before.

`dsa.sign` takes `grind=True`, which answers the signature of the same
key and message whose `r` has its high bit clear — one octet shorter in
DER, and the reason Bitcoin Core's `CKey::Sign` does it. It is Core's
scheme rather than a rephrasing: a `uint32` counter mixed into the nonce,
so what comes back is what Core and rust-secp256k1 answer for the same
inputs, held to their own vectors here. It costs two signatures on
average — 11.7 microseconds against 24.9, on the machine and with the
method CHANGELOG.md states — which is why it is asked for and never done
by default. `aux_rand32` is refused alongside it, being the same 32
octets, and `s` needs nothing of the kind: libsecp256k1 has always
returned the lower of the two.

`dsa.is_low_r` is the same question asked of a signature somebody else
made, as `is_low_s` is for the other half. It is not a rule and nothing
rejects a high-r signature: what it answers is whether this one is the
octet shorter that grinding produces — a caller enforcing that on its own
signatures, or counting how many of somebody else's carry it, is who it
is for.

`xonly._tweak_add_` is the private half of `xonly.tweak_add`: it takes
the parsed point `keys.parse` returns, rather than the x-only form, and
so tweaks a key that is already lifted instead of lifting its x a second
time. The x-only conversion in front of the tweak is
`secp256k1_xonly_pubkey_from_pubkey`, which reads the y it is given; the
result is the output key and parity `tweak_add` answers with, the
negation of an odd-y point included, and `tweak_add` itself is unchanged
in behaviour and cost.

**The convention now runs in both directions, and over every kind of
object.** It has meant "takes the parsed key in place of the bytes"
since 0.8.0.2; a wrapper that *answers* with a key had no such half, so
a caller composing two of them — sorting keys and then adding them
together, recovering a key and then verifying with it, decoding an
ElligatorSwift encoding and then tweaking what came out — serialized a
point libsecp256k1 had just handed over and parsed it straight back,
which for the compressed form is a field square root. And a signature, a
label or the summary of a transaction's inputs is an object like a key:
`dsa.parse_der`, `dsa.parse_compact`, `recovery.parse_compact` and
`xonly.serialize` join the `parse`/`serialize` pairs, so `dsa._sign_`,
`_normalize_`, `_is_low_s_`, `recovery._sign_`, `_to_der_` and the three
of `silentpayments` — `_create_outputs_`, `_prevouts_summary_`,
`_scan_outputs_` — have something to take and something to hand back.
Every public half is unchanged in behaviour and cost, and is now written
as its private half with a `parse` in front of it, a `serialize` behind
it, or both.

The Silent Payments three are the ones a wallet feels: scanning block
after block, `scan_outputs` parses the spend key and every transaction
output at every transaction, where `_scan_outputs_` takes them parsed
once and takes the summary object `_prevouts_summary_` built rather than
octets to be written back into a struct.

What that saves is the round trip and nothing else, so it is worth what
the two calls around it are not: aggregating five public keys the BIP67
way is 28.2 microseconds through `pubkey_combine(pubkey_sort(...))` and
14.8 through the two inner halves on keys parsed once, and a labeled
Silent Payments address is 14.3 against 9.3. CHANGELOG.md states the
machine and the method.

**`keys.pubkey_verify` and `keys.reserialize` are for the caller who
wants none of that.** The first is the public-key twin of
`prvkey_verify`: the validation a library makes at its own boundary, with
nothing kept — where `parse` hands back an object to hold and
`reserialize` the octets the caller already had.
`xonly.pubkey_verify` and `dsa.signature_verify` complete it: the same
verdict for an x coordinate and for a signature, in either of its
serializations, so that a library validating input has one shape of
answer for all four kinds of octets rather than a verdict for two of them
and an exception for the rest.

**Two entry points answer the nonce a signature was built on.**
`dsa.nonce_rfc6979` and `ssa.nonce_bip340` call through the function
pointers libsecp256k1 exports, with what each signer passes them, so what
comes back is the `k` of the signature the same arguments make -- `r`
being the x of `k` times the generator. A python implementation of either
derivation had published vectors and no oracle; this is the C function
itself. The nonce is the secret the signature is built on, and reading it
into python takes it out of constant-time code: they are for checking a
derivation, not for driving one.

**Two more entry points are for the caller doing arithmetic rather than
holding a key.** `keys.pubkey_sum` is `pubkey_combine` answering `None`
where the sum is the point at infinity, instead of refusing it: `P + (-P)`
is a value to a curve library and no public key to libsecp256k1, and the
two calls are otherwise the same. `xonly.to_pubkey` is the lift — an
x-only key is an x, the point it names is the one with even y, and
reading that y meant writing `0x02 || x` yourself, libsecp256k1 having no
call from an x-only object back to a point.

The second is for the caller that wants the *other* serialization. A
parsed key is an optimization of a parse, and a parse of the
*uncompressed* form is 0.256 microseconds against 2.343 for the
compressed one — both coordinates are there to read, where a compressed
key is a field square root. So 65 octets are a parsed key that costs
nothing to open, and nothing has to own their lifetime.
`keys.reserialize` is `serialize(parse(key))` in one call, and it is also
the conversion between the two serializations, which nothing here
offered — `compressed` is a filter on the form everywhere else, not a
conversion to it. And every entry point taking a public key now
takes any of its three serializations: `02 || x`, `03 || x` and
`04 || x || y` are one BIP340 key, `lift_x` being the even-y point
whatever form the x arrived in, so `ssa.verify`, `xonly.tweak_add` and
`xonly.tweak_add_check` no longer refuse the 33- and 65-byte forms — what
that refusal cost was a lift, and a tweak from the uncompressed form is
4.11 microseconds against the 5.92 of the 32-byte one.

**`dsa.sign` and `dsa.verify` take a `compact` flag**, false by default,
so an ECDSA signature crosses in either of its two serializations. A
signature is `r` and `s`, and DER is what the wire carries: a caller
holding the two scalars was writing an ASN.1 structure around them for a
call that takes it apart again, and reading one back on the answer — 0.7
and 1.3 microseconds of the caller's own time, the second of them per
attempt where low-r grinding discards what it has just parsed. Which form
is being handed in has to be said and cannot be read off the length: a
DER signature of 64 octets exists. Nothing about the default moves, and
`to_der` and `to_compact` are unchanged.

**`xonly.from_prvkey` and `ssa.Signer.pubkey` are two entry points
rather than two halves**, and they save different things. The first is
the x-only public key of a private key: it is `_pubkey_from_prvkey_` and
`_from_pubkey_` composed, so the halves above are where its 7.9
microseconds against 10.5 come from, and what it adds is a name for a
composition BIP340 and BIP341 make the common case — the full public
key in the middle being an intermediate step nothing here asked for.
The second saves what no pair of halves could: a signer holds the
keypair, and the point with it, so reading the key off it is a read and
not a multiplication — 0.4 microseconds, where deriving it again is
10.5. `xonly.from_keypair` is that read for a caller holding a keypair
of its own, a MuSig2 session through `lib` being one.

**`keys.pubkey_tweak_mul_sum` multiplies each key by its scalar and adds
the products**, which is a verification equation, a MuSig2 aggregate key
and BIP352's tweak data, and which written with the public halves
serializes every product as 65 octets only for `pubkey_sum` to parse
them back. Handed over whole, no product crosses: about a seventh of the
call from three terms up, 64 terms 459.3 microseconds against 536.5, and
the saving does not shrink with the count -- it is the naive form, one
term at a time and one sum, libsecp256k1 exporting no batched
multi-multiplication, so what it saves is the crossing and not the
arithmetic. Like `xonly.from_prvkey` it
is a composition rather than one libsecp256k1 call, and for the same
reason — what it saves is the crossing between its halves, which is the
caller's cost and not its own choice. The sum at infinity is
`pubkey_sum`'s `None`, which a verification equation is written to land
on.

**And a wrong object is now told to the caller, wherever one is taken.**
`keys.serialize` and `xonly.from_keypair` raised what libsecp256k1
reported of an argument no python check can prove; every other call
taking such an object did not, which was measured rather than assumed:
a wiped or unwritten key made `dsa._verify_` answer `False`,
`keys._pubkey_cmp_` answer `0` — the answer for two equal keys — and
`ecdh._shared_secret_` answer success and 32 bytes that are a shared
secret with nobody, each leaving libsecp256k1's reason on the thread for
the next `context.check()` to raise about a call that did not produce
it, a MuSig2 caller's own being the one that would. All of them raise a
`ValueError` carrying that reason now. A caller passing the objects
these calls are meant to take sees no difference in what it gets back,
and 0.48 microseconds a call in what it costs: nothing on a
verification, which is 12.9 microseconds against 12.1, and most of the
call on `keys._pubkey_cmp_`, which is 0.57 against a C comparison of
0.087. `lib` is exported for a caller who counts that.

**Importing the package is ten times cheaper**, 1.69 milliseconds against
15.85 — an Apple M5, macOS 26.6, arm64, CPython 3.14.6, minimum of 12
fresh interpreters, CHANGELOG.md carrying the command and the table. Two
imports did it, neither of them the compiled extension, which is 0.58 of
those milliseconds: `importlib.metadata`, reached at import to fill
`__version__` and pulling `email`, `json` and `inspect` behind it, and
`pathlib`, which only the dynamic branch of `_load_lib` uses and which a
static wheel never reaches. The version is read on first access now, and
`pathlib` where it is used — and it takes both, `importlib.metadata`
importing `pathlib` itself. What a caller has to know is one thing:
`dir(btclib_secp256k1)` does not list `__version__` until something reads
it, and does afterwards. Reading it — as the attribute, as
`from btclib_secp256k1 import __version__`, or straight out of the
metadata — answers what it always answered, and costs what it always
cost, the first read and every one after it.

## v0.8.0.2

Non-breaking, and two additions for a caller that verifies signatures it
did not make.

Verification takes the parsed public key now, where it took only the
bytes: `dsa.verify_`, `ssa.verify_` and `ecdh.shared_secret_` are the
inner halves of the three, taking what `keys.parse` and `xonly.parse`
return, and `keys.pubkey_negate_`, `keys.pubkey_tweak_mul_`,
`keys.pubkey_cmp_` and `xonly.from_pubkey_` complete the convention
`keys.pubkey_tweak_add_` had started. A caller that validated a key
before verifying with it, or that checks several signatures against one
key, parses it once instead of once per call — and for a compressed key
that parse is a field square root, a measurable part of a verification
rather than a rounding error. Every outer half is unchanged in behaviour
and cost.

`dsa.verify` and `dsa.verify_` take a `normalize` flag, off by default:
with it on, a signature outside the lower-s form is normalized and
verified rather than rejected, which is what a caller checking other
people's signatures wants. `dsa.verify(msg, key, dsa.normalize(sig))`
still says the same thing and costs a DER serialization and a second
parse more. What the default refuses, it still refuses.

The benchmark is no longer in this repository: it lives in
[btclib-benchmarks](https://github.com/btclib-org/btclib-benchmarks) as
`scripts/libsecp256k1_wrappers.py`. `uv sync --group bench` resolves
nothing — that dependency group is gone — and CONTRIBUTING.md says where
to run it instead.

## v0.8.0.1

Non-breaking. `keys.PubkeyTweakChain` is new: it adds a sequence of
tweaks to a public key, parsing the key once rather than once per tweak,
for a caller who is about to feed each result back in as the next tweak's
argument — a BIP32 public derivation path is exactly that. Nothing
existing changes shape or cost: `pubkey_tweak_add` still parses and
serializes on every call, which is the right cost for one tweak.

## v0.8.0

[libsecp256k1 0.8.0](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.8.0)
(6e2c8bc), up from 0.7.1: a minor version of the wrapped library, so a
minor version here, the numbers tracking each other. **The package is
renamed, which every user acts on**; besides that, one breaking change
for a caller reaching through `lib`, and two arguments that used to be
answered wrongly now raise instead.

- **`btclib_libsecp256k1` is now `btclib_secp256k1`**, the distribution
  and the import package both, and this is the first release under the
  name. `lib` named the C library being wrapped, and a python
  distribution is not that library: it is btclib's bindings to secp256k1.
  Nothing bridges the two on PyPI, and that is a decision rather than an
  omission: `btclib_libsecp256k1` stops at 0.7.1.3, stays installable,
  and `pip install btclib_libsecp256k1` keeps resolving to it instead of
  quietly following the rename. Moving is one edit in the requirement and
  one in the imports:

  ```diff
  -btclib_libsecp256k1>=0.7.1.3
  +btclib_secp256k1>=0.8.0
  ```

  ```diff
  -from btclib_libsecp256k1 import dsa, keys, ssa, xonly
  +from btclib_secp256k1 import dsa, keys, ssa, xonly
  ```

  Nothing inside the API moved: the modules, every function, and the
  `ffi` and `lib` a MuSig2 caller reaches through are what they were. The
  two can be installed at once while a codebase moves, the import package
  having been renamed with the distribution, so neither shadows the
  other. The documentation moves with it, to
  [btclib-secp256k1.readthedocs.io](https://btclib-secp256k1.readthedocs.io),
  and so does the repository, which is now
  [btclib-org/btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1).
  GitHub redirects every old path to it — a clone, a fetch, a bookmark
  and the api alike — so nothing has to be changed to keep working; a
  remote is worth repointing anyway, so that what it prints is where it
  goes.
- **Silent Payments are wrapped**, as `silentpayments`, BIP352's new
  libsecp256k1 module: `create_outputs` pays a list of addresses from the
  private keys of a transaction's inputs, `prevouts_summary` and
  `scan_outputs` find what a scan key was paid and the tweak that spends
  it, and `label` and `labeled_spend_pubkey` are the several addresses one
  scan key can receive at. What BIP352 states over scripts — which inputs
  are eligible, and which of those are taproot — stays the caller's, this
  package reading no script; both directions of all of BIP352's own
  vectors are what it is tested against.
- **Two libsecp256k1 symbols are gone**, removed upstream after being
  deprecated: `secp256k1_context_no_precomp`, whose replacement is
  `secp256k1_context_static`, and the `secp256k1_schnorrsig_sign` alias,
  whose replacement is `secp256k1_schnorrsig_sign32`. Nothing in these
  bindings used either, so code calling only the wrappers is unaffected;
  code reaching for one of the two through `lib` has to move to its
  replacement, and will fail to import the attribute rather than
  misbehave.
- **`ellswift.xdh` refuses a private key at or above the group order**,
  where it used to reduce it modulo the order and answer. That was
  upstream's bug and is upstream's fix; what changes here is that such a
  key now raises `ValueError` naming an invalid private key, which is
  what the docstring already said it did. No securely generated key is
  affected: the probability of one landing there is about 2**-128.
- **A `memoryview` of items wider than an octet is refused**, everywhere
  bytes cross, where it used to be read as the octets underneath those
  items — 32 of them for eight `uint32`, which is a value the caller never
  wrote and not the same one on a big endian machine. It now raises
  `TypeError`; `.cast("B")` is how a caller who does mean those octets
  says so. `bytes`, a `bytearray` and a `memoryview` of bytes are
  unaffected, a stride and extra dimensions included.
- **ECDSA and BIP340 verification are faster on GCC and MSVC**, by up to
  about 11% upstream's measure, the 64-bit field multiplication and
  squaring now being force-inlined. Clang, which is what the macOS wheels
  are built with, is largely unaffected; the compiled library is somewhat
  larger everywhere.
- **Re-randomizing the shared context is documented as needing exclusive
  access to it.** Nothing changed in the code: `context._randomize` is
  what it was, and the bindings stay safe to call from several threads.
  What was missing is that repeating that one call while other threads
  are in flight is what takes that safety away — libsecp256k1 asks for a
  read-write lock, or for randomization at creation time, which is what
  happens at import.

## v0.7.1.3

The same
[libsecp256k1 0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
(1a53f49) as v0.7.1.2: **no breaking changes**.

- **A dynamic wheel's import failure says why.** `ImportError` now names
  every shared-object candidate `_load_lib` rejected and chains the last
  loader error, instead of only "no loadable shared libsecp256k1 found".
- **`cryptography` moved to 50.0.0**, closing CVE-2026-69247 — a PKCS#7
  decryption oracle pulled in transitively through the packaging tools,
  and unreachable from this package's own code either way.
- **Two README clarifications**: why `pubkey_from_prvkey` is two
  libsecp256k1 calls rather than one, and which btclib functions guard a
  MuSig2 nonce against reuse.

## v0.7.1.2

The same
[libsecp256k1 0.7.1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
(1a53f49) as v0.7.1: **no breaking changes** — nothing in the public API
moved, and the one wrapper whose behaviour changed changed the text of an
error message. What a fourth number carries here is one new function, the
contract of every function where a caller reads it, a static extension
compiled the way the interpreter compiles its own, and metadata that says
what the wheels are.

- **`keys.pubkey_from_prvkey` is the public key of a private key**,
  compressed by default, and the 65 bytes of `mult.mult_` with
  `compressed=False` — which is what `mult_` now is. Generator
  multiplication was the one producer here that could not answer the
  compressed form, so a caller who wanted the 33 bytes had to parse and
  re-serialize what libsecp256k1 had just serialized, or slice the parity
  out of the 65 bytes themselves. `mult_` answers exactly what it did;
  the one thing to know is that the `ValueError` of a scalar outside
  `[1, n-1]` now names a private key, which is what
  `secp256k1_ec_pubkey_create` calls its argument, so code matching on
  that message matches on the new text.
- **Every function documents its arguments, its return value and what it
  raises.** That contract used to be prose in the README, several hundred
  lines from the functions it applies to, which for a package shipped as
  a compiled wheel is all a reader of `help()` or of an IDE tooltip
  could have had. `mult.mult_` and `mult.mult`, which shared a docstring
  verbatim while returning 65 uncompressed bytes and a pair of ints, now
  each say which. A `pydoclint` hook keeps it that way.
- **The README opens with a Quickstart** — sign and verify, ECDSA and
  BIP340 — and every example in it, and in every docstring, is executed
  by the suite on each interpreter and each kind of wheel. An example
  that stops working fails a build instead of sitting there.
- **The static extension is faster on Unix**, and correct on universal2.
  It was compiled without the interpreter's own `CFLAGS`: no
  optimization at all, unlike everything CMake builds beside it, and on
  a universal2 interpreter a single-arch object inside a dual-arch
  bundle.
- **A wheel whose extensions disagree on static or dynamic is refused**
  rather than reported. It would have been tagged `py3-none-<platform>`
  while holding an ABI-specific extension: installable on any
  interpreter of that platform, and broken on most of them.
- **The classifiers say what the package is**: the three systems the
  wheels are built for instead of `OS Independent`, and `Typing ::
  Typed`, which is the classifier PyPI users filter on.
- **More of the library is held to published vectors**: BIP324 for
  ellswift encoding and the `ellswift_xdh` shared secret, BIP327 for
  every step of MuSig2 aggregation, the four long BIP340 messages
  through `ssa.sign_custom`, and recovery ids 2 and 3, which no test had
  ever reached.
- **Two hooks that were passing without reading a file now read one.**
  The copyright notice hook was checking only newly added staged files,
  so on a clean checkout — every run in CI — it checked nothing; the
  entropy detectors of `detect-secrets` were off for the whole tree
  rather than for the vector files that motivated it.
- **The release path checks before it builds what it used to discover
  after uploading**: that the tag is on `master`, and that this file has
  a section for it. A rehearsal re-run gets a version of its own instead
  of colliding with itself on TestPyPI, and no longer shares a
  concurrency group with a push to the branch it was dispatched from.

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
  [Read the Docs](https://btclib-secp256k1.readthedocs.io), which the
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

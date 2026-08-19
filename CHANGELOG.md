# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - a group heading repeats under every
    // release with an entry in that group ("Packaging metadata", "The
    // gate", "CI"), which is what keeps the page readable scrolling down
    // it; only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

Every change of a release, in full: what changed, why, and what it cost.
[HISTORY.md](./HISTORY.md) has the release notes, which say what a user has
to act on; this file is the record behind them, and is where a claim in
those notes can be checked.

This file starts at v0.7.1.2. The releases before it were documented at
release-notes length in the first place, and are still in
[HISTORY.md](./HISTORY.md) rather than duplicated here.

## v0.8.0.3 (work in progress, not released yet)

### The pull request is the only way into main, and the review has a standard

- **The landing convention says what is in force: the squash button.**
  `CONTRIBUTING.md` said the landing is "a push rather than a button",
  `REPOSITORY.md` titled a section for the push its bypass was for, and
  `CLAUDE.md` kept a fast-forward exception for a stacked pull request.
  The `main-self-merge` bypass now reads `pull_request` mode, so it
  excuses the approving review a solo-maintainer repository cannot
  produce and excuses nothing else: a direct push to `main` is refused
  for everyone, the holder included. The ruleset also names `squash` as
  the only merge method it accepts, stating the constraint where the
  rule is rather than only in a repository toggle. What the exception
  bought — a stacked child keeping its base — is paid for with a rebase
  instead, a button recreating rather than moving whatever the count of
  commits: GitHub's documentation has rebase-and-merge "always updates
  the committer information and creates new commit SHAs". The
  configuration is the organization's, identical in btclib,
  bitcoin-core-rpc and btclib-benchmarks.

- **`REVIEWING.md` is the standard a review is written against**, the
  reviewer's half of `CONTRIBUTING.md`: what a review establishes before
  it gives an ack, what a finding must contain and how it labels its
  severity, and what becomes of everything a reviewer notices that the
  diff is not about — every collateral finding is filed as an issue
  rather than asked for in a comment. It states no new rule; the rules
  it cites stay in the files that state them. Registered the way
  `CONTRIBUTING.md` is: a page of the sphinx toctree through a
  `reviewing_link.md` shim, named from the README and from `CLAUDE.md`,
  which is the file a repository-aware reviewer reads.
  `.claude/commands/review.md` is it as the `/review` command. The body
  is deliberately the text btclib carries, one section excepted: the
  questions a review of *this* tree asks and a generic one would not.

### The recoverable check takes that key too

- **`recovery.sign` and `recovery._sign_` take a keyword-only `pubkey`**
  (#246), the key the recovered one is compared with, so that
  `_abort_unless_recovered` no longer derives a key the caller is
  holding. Everything around it is what #245 settled for `dsa` and is
  not restated in a second shape: the key is taken on trust, it is
  refused beside `verify=False` in both halves, and octets are parsed at
  the boundary so that a mistyped argument is refused before anything is
  signed rather than arriving as a verdict on a signature the caller now
  has.
- **The dearest check of the three, and the same saving as `dsa`'s.**
  Measured in one session with `dsa.sign` beside it so the two
  are comparable rather than merely printed together -- an Apple M5,
  macOS 26.6, arm64, CPython 3.14.6, nine rounds of 3 000 calls with the
  minimum of each kept, the private key handed in as octets in every row,
  and the unchecked signature run a second time so the noise has a figure
  of its own:

  | `recovery.sign` | per call | the check |
  | --- | --- | --- |
  | `verify=False` | 12.07 | |
  | the key derived, as before | 35.00 | 22.93 |
  | a compressed key handed in | 29.67 | 17.60 |
  | an uncompressed key handed in | 27.49 | 15.42 |
  | the point already parsed, through `_sign_` | 27.25 | 15.18 |
  | `verify=False` again (the noise) | 12.09 | ±0.02 |

  `dsa.sign` in that same session was 12.14 unchecked, 31.97 with the key
  derived and 24.55 with an uncompressed one handed in, so its check went
  19.83 to 12.41 -- both within a few tenths of #245's own session, which
  is between sessions and not within either. The 7.51 removed here is
  `secp256k1_ec_pubkey_create` and nothing besides: timed alone in the
  same session it is 7.53. The 2.18 between the two serializations is the
  field square root that recovers y and the 0.24 under it is the
  uncompressed parse only the private half avoids, both agreeing with the
  2.02 and 0.26 measured for `dsa`. What is left is what a recovery and a
  comparison cost over a verification, and it is the same ~3 microseconds
  before and after -- 22.93 against 19.83 derived, 15.42 against 12.41
  handed in -- which is what says the argument removed the derivation and
  changed nothing else.

  Which also settles a guess #246 made before anything was measured:
  "It is the scheme whose check is doing the most work, so the saving is
  largest". The check is the most work, 22.93 against 19.83; the saving
  is not larger. 7.51 here against 7.42 in `dsa` is 0.09, in a session
  whose own noise row is ±0.02 but which calls a 0.16 difference between
  the two square roots "agreeing" -- and both land on the 7.53 the call
  costs timed alone, which is the reading that matches "and nothing
  besides". The saving is one `secp256k1_ec_pubkey_create`, in both
  modules, at one price.
- **A mismatch now has three causes, and two of them share an answer.**
  The key given is not this private key's, the recovery id is not the
  signature's, or the computation faulted; the first is an argument and
  the other two are not. One comparison separates them and it is paid
  only where something already went wrong: the recovered key against the
  derived one. Where those agree the signature is the signer's and the
  argument is wrong, which is the `ValueError`; where they do not, the
  signature does not recover its own signer, which is what a wrong id and
  a fault both look like from here. That they share the `RuntimeError` is
  the decision rather than an oversight -- a caller of `sign` cannot pass
  an id at all, it coming back from `secp256k1_ecdsa_sign_recoverable`
  beside the signature, so an id that is not the signature's is a fault
  by the time the check runs.
- **So the discrimination is `dsa`'s shape, and the third cause is what
  the issue asked about.** #246 left open whether `recovery` should take
  the argument at all, the saving being the largest and the diagnosis
  having the most ways to go wrong. What decided it is that the third
  cause needs no third message: it is unreachable from any argument of
  `sign`, and where it is reachable -- through the parsed signature the
  private half takes -- it is the fault the `RuntimeError` already names.
  So the cost of taking the saving is one comparison on a path that was
  already failing.
- **The case no other module in this package can write.** A wrong
  recovery id is one `parse_compact` away, so all three causes are
  reachable with no stand-in anywhere:
  `test_a_wrong_id_under_a_right_key_is_not_reported_as_a_wrong_key`
  signs once and asks the real libsecp256k1 three questions -- the
  signature's own id under the signer's key, the other id under that same
  key, and the signature's own id under a stranger's -- and holds the
  first to passing and the other two to the two different exceptions.
  Both misdiagnoses are what it rules out: a right key with a wrong id
  reported as a wrong argument, and a wrong key reported as a fault.
- **The rest of the group is `dsa`'s, asserted again here** rather than
  assumed to carry over: the same signature and the same recovery id
  whichever way the check got its key and in both serializations of it,
  the refusal of a key beside `verify=False` in both halves, octets that
  are not a key refused before signing, and the property over forty keys
  and messages -- which is a stronger sentence here than there, since the
  key handed in has to be the single key the signature recovers rather
  than one of the keys it verifies under.
- **The README's section on the check carries the tables**, and the
  sentence that said the saving was "available and not yet taken" for
  `recovery` is now the one that says what taking it cost.

### A scalar may be memory the caller can overwrite

- **`_scalar.scalar` takes a cffi array of exactly 32 octets and hands it
  on unconverted** (#247), so wherever a private key or a tweak is
  accepted, `ffi.new("unsigned char[32]", ...)` is too. It is the only
  argument of these bindings that is not copied at the boundary, and the
  reason is what the copy would be: an immutable `bytes` of a secret,
  which nothing can overwrite and which stays until the collector gets to
  it. A caller signing again and again under one key can now hold it in
  memory it owns and wipe that when done, with no `bytes` of the key made
  per call. What that gives up is stated where `octets` states the
  opposite -- the copy is also what stops a caller changing the octets
  libsecp256k1 is reading -- and it is the caller's to give up, the
  buffer and its synchronization being theirs already.
- **What decided the shape is where the coercion actually binds**, and
  the issue's premise was wrong about it. #247 reasoned that a
  `dsa.Signer` holding a buffer "would have to turn it back into a
  `bytes` on every call". It would not: `dsa._signed` and `dsa._checked`
  hand libsecp256k1 the pointer, exactly as `ssa.Signer` bypasses
  `keypair` per signature, so a prototype signer holding
  `ffi.new("unsigned char[32]")` produced byte-identical signatures
  before this change and hoisted 0.37 microseconds of 23.42 -- an Apple
  M5, macOS 26.6, arm64, CPython 3.14.6, nine rounds of 3 000 calls with
  the minimum kept, the checked call with its key handed in as the
  anchor and run again for a noise of 0.02. Which leaves the README's
  verdict on speed where it was.
- **It binds on the derivation, and the sharpest case is a diagnosis.**
  `keys._pubkey_from_prvkey_` asks for a scalar, so a key in a buffer
  could not have its public key derived at all -- and the failing branch
  of `dsa._checked`, which derives precisely in order to tell a wrong
  argument from a fault, answered `TypeError: the private key must be
  bytes or an int, not __CDataOwn`. A caller whose hardware had faulted
  was told they had mistyped an argument they passed correctly, which is
  the misdiagnosis #245 built that branch to avoid. So the door is open
  for the diagnosis rather than for the microsecond, and
  `test_the_discrimination_holds_for_a_key_held_in_a_buffer` holds both
  sides of it with the key in a buffer.
- **Any item type an octet wide, because what crosses is a re-view.**
  `ffi.from_buffer` over `ffi.buffer` answers an `unsigned char[32]`
  pointing at the caller's own memory, which is the one item type cffi
  will pass to `const unsigned char *`: without it the acceptance would
  be `char` and `unsigned char` alone, and `uint8_t[32]` -- what a C
  programmer writes for 32 octets -- would clear every check and die at
  the boundary in cffi's words about an internal ctype. Not `ffi.cast`,
  which answers the same pointer for nothing and does **not** keep the
  memory alive: measured, a cast whose owner is dropped and collected
  reads 32 octets that no longer hold the key, with no error anywhere.
  `from_buffer` keeps a reference to what it views.
- **Three obligations pass to the caller with the copy**, and the
  docstring names them because none of them exists for a `bytes`. The
  octets must stay put for the whole call, which is more than one read:
  `secp256k1_ecdsa_sign` loads the scalar (`secp256k1.c:555`) and derives
  the nonce from the same pointer (:563), and `dsa._sign_` reads it again
  per grinding attempt and in `_checked`'s failing branch -- so a write in
  between gives a nonce and a signature under two different keys, arriving
  as the fault `RuntimeError`. The memory must outlive the call, which no
  python argument has had to promise: a cffi view -- a slice, a cast --
  does not keep its owner alive, measured, and a dangling one reads freed
  memory as a key. And the length is the declaration's word, `ffi.sizeof`
  answering what the type says: a cast of 8 octets to `unsigned char[32]`
  clears every refusal and has libsecp256k1 read 24 octets of whatever
  follows, which cffi cannot report and so neither can this.
- **Three refusals, because what follows is a bare pointer** libsecp256k1
  reads 32 octets from. A *pointer* rather than an array, whose
  `ffi.sizeof` is 8 and says nothing about what it points at -- the trap
  `_secret.wipe` records from the other side, where that number would
  have wiped a quarter of a private key and reported success. An array of
  wider items: `uint32_t[8]` is 32 octets of whatever this machine's byte
  order made of them, refused for the reason `octets` refuses a
  `memoryview` of wider items. And an array of the wrong length, which is
  the check every other scalar gets and the one a bare pointer cannot be
  given later.
- **A `str` is refused before the question is asked, and that is a bug
  the suite caught rather than a case somebody thought of.**
  `ffi.typeof` reads a str as a *cdecl*: `"x" * 32` comes back as cffi's
  own `error: undefined type name`, which is neither this function's
  `TypeError` nor about the argument -- and `"char[32]"` is worse, being
  a cdecl that resolves, measures 32 octets, and would have been passed
  to libsecp256k1 as a str.
  `test_type_checks_refuse_what_merely_has_a_length` failed on the first
  spelling the moment the branch was written; the second was found
  looking for why, and both are cases now.
- **Four call sites copy the octets, and had to be taught to.**
  `keys.prvkey_negate`, `keys.prvkey_tweak_add`, `keys.prvkey_tweak_mul`
  and `silentpayments._create_outputs_` allocate a buffer of their own --
  the first three because libsecp256k1 writes the answer through that
  pointer, the last because this package wipes it in a `finally` -- so
  handing them the caller's memory would negate or zero the key that was
  passed in. They spelled it `ffi.new(cdecl, scalar(...))`, whose
  initializer is `bytes` or a list and never a cdata, so each refused one
  of the two obvious cdecls with cffi's own message about an internal
  `char[32]`: `unsigned char[32]` failed in the three `keys` functions and
  `char[32]` in `silentpayments`, and `ssa.nonce_bip340` therefore failed
  for *half of all keys*, reaching `prvkey_negate` only where the point
  has odd y. `_secret.scalar_buffer` is now the one statement of that
  copy -- `ffi.new` then `ffi.memmove`, which takes either source and
  makes no `bytes` of the secret in between -- and it says which of the
  two reasons each site has.
- **The sweep is what would have caught it, and now exists.**
  `tests/test_bytes_like.py` drove every entry point with bytes, a
  bytearray and a memoryview; it drives them with a 32-octet buffer too,
  swapping the private keys and tweaks of its own table by identity. It
  asserts the answer is the same *and* that the caller's octets are still
  there afterwards, which is the half a comparison of answers cannot see.
  Reverting one of the four sites fails it on that row. The parity branch
  gets a case of its own beside it, `PRVKEY` being 7 and even-y, so that
  the half of `nonce_bip340` no table row reaches is driven with 5 and 6
  and both parities are asserted to occur.
- **The public annotations do not widen, which was the cost the issue
  named.** `CData` is `Any`, so `BytesLike | int | CData` on `dsa.sign`
  would have stopped mypy checking every caller's private key. Only
  `scalar`'s own parameter widens: the entry points still declare
  `BytesLike | int`, so a `float` is still refused statically at the call
  the caller made, while a cdata still arrives because `ffi.new` answers
  `Any`. What is given up is mypy checking this package's own calls of
  `scalar`, whose run-time check is the one that was doing the work.
- **The cffi stub gains what the question reads**: `_CType.kind`,
  `.cname` and `.item`, and `typeof` now takes a cdata as well as a
  cdecl -- `Any`, as `sizeof`'s parameter already is for the same reason,
  cdata being what that file cannot name. It was opaque because nothing
  read what cffi answered, and its docstring says what now does. Two
  functions join it, `from_buffer` and `memmove`, being the two halves of
  what a caller's octets can become.
- **Whether a `dsa.Signer` is worth having is still
  btclib-org/btclib#982's question**, and this does not answer it. What
  it does is take the blocker away: the wiping ground that issue would
  have to be argued on no longer needs a signer at all, a caller holding
  the buffer and calling `dsa.sign` getting the same thing.

### The check takes a public key the caller already has

- **`dsa.sign` and `dsa._sign_` take a keyword-only `pubkey`**, the key
  the check verifies under, so that a caller who already holds it does
  not pay for deriving it again. It is taken on trust and never checked
  against the private key on the way in: checking it would cost the
  point multiplication the argument exists to avoid.
- **What that saves is most of what ECDSA's check costs over BIP340's.**
  Measured on an Apple M5, macOS 26.6, arm64, CPython 3.13.14, the five
  shapes alternated in one process, 9 rounds of 3 000 calls with the
  minimum of each kept, and the unchecked signature run again at the end
  so the noise has a figure of its own -- ±0.04 against an unchecked
  11.72. The check is **20.20** deriving the key per call, **15.08** with
  a compressed key handed in, **13.06** with an uncompressed one, and
  **12.80** with the point already parsed and `_sign_` called directly.
  The 7.40 between the first and the last is the derivation, which is
  `secp256k1_ec_pubkey_create` through `keys._pubkey_from_prvkey_`;
  timed alone in a session of the same shape it is 7.31, against a
  noise of ±0.14. The 7.55 the README carries and the 7.16 measured for
  `secp256k1_keypair_create` are that other call rather than this one,
  and land within half a microsecond of it because the two do the same
  work. Within the handed-in rows, 2.02 is what a compressed key costs
  to parse over an uncompressed one -- the field square root -- and
  0.26 is the uncompressed parse: what the parse adds back above the
  fully parsed row, not slices of the derivation. Under all of it is a
  bare verification, which is what BIP340's check has always been.
- **A failed check now says which of two things failed**, and that is
  what makes the trust affordable rather than merely cheap. A key that
  is not this private key's makes the verification fail exactly as a
  faulted computation does, and reporting one as the other would tell a
  caller their hardware is wrong because they passed the wrong argument.
  So the failing branch, and only the failing branch, derives the key
  and asks again: `RuntimeError` where the signature does not verify
  under the key the private key actually has, `ValueError` where it does
  and the one handed in is simply not it. The rare branch pays the
  derivation the common one saved.
- **The trust cannot let a bad signature through**, which is the
  property the whole argument rests on and is now a test rather than a
  paragraph. The keys a signature verifies under are a property of that
  signature -- `recovery.recover` walks them -- so a key fixed before
  the signature exists is not one of them.
  `test_a_key_fixed_in_advance_cannot_pass_a_signature_of_another_key`
  holds that over forty keys and messages.
- **And it catches a fault the derived check cannot.** A private key
  corrupted before it was signed with passes the derived check in
  silence: the signature and the key it is verified against come out of
  the same corrupted octets and agree. A key handed in came from
  somewhere no fault in that call could reach, so it does not agree --
  which means the `ValueError` names the likelier of two causes rather
  than the only one, and the docstring says so.
- **Both halves of the discrimination are held to.** The `ValueError`
  side has a case of its own; the `RuntimeError` side has one too, and
  it needs a substituted verification because no input reaches it --
  `raise RuntimeError` is outside the coverage ratchet, so nothing else
  would have said that stubbing the second verification to succeed
  turns every genuine fault under a handed-in key into a report that
  the caller mistyped an argument. That mutation now fails the suite.
- **And the saving itself is asserted rather than only measured**
  (#251). What the argument buys is the early return in `_checked`, and
  deleting that return changed no answer: a correct key reached the
  derived comparison, which agreed and gave back the same signature, so
  every other case of the argument passed with the derivation paid for
  again -- the figures above false and nothing red.
  `test_the_derivation_the_argument_saves_is_not_made_at_all`
  substitutes the multiplication for one that raises, and the signature
  coming back at all is what says it was never made. That mutation now
  fails the suite, and it failed nothing before.
- **Refused rather than resolved**, as `aux_rand32` beside `grind`
  already is: a key given with `verify=False` raises, being a caller
  contradicting themselves, and octets that are not a key are parsed and
  refused on the way in rather than arriving as a failed check on a
  signature the caller now holds.
- **Not on `ssa`, and deliberately.** The check there is 13.2
  microseconds whether the key is held or not, the keypair already
  holding the point, so the argument would buy nothing and sell one
  thing: a second reason a check can fail, and the discrimination step
  that reason costs. btclib-org/btclib#982 has the measurement.
- **Not folded in for `recovery`, and taken there in a change of its
  own** (#246, the section above). `_abort_unless_recovered` derived the
  same key -- `keys._pubkey_cmp_(recovered,
  keys._pubkey_from_prvkey_(...))` -- so the saving available there was
  exactly the one taken here: the recovery stays and the derivation goes.
  What differed was the discrimination, a recovered key that is not the
  one handed in having a third possible cause the two schemes above do
  not, which is the recovery id. That wanted a measurement and cases of
  its own, and is what got them.
- **The README carries all of this**, in the section on the check, which
  said `verify=False` was the only thing a caller could do about the
  cost and is where CLAUDE.md puts the design.

### A signer checks its own signature

- **`dsa.sign` and `ssa.sign` verify what they made before answering
  with it**, under the public key of the very key that made it, and take
  a keyword-only `verify` that defaults to `True` to say so.
  `ssa.sign_custom`, `ssa.Signer.sign`, `ssa.Signer.sign_custom` and the
  private `dsa._sign_`, `ssa._sign32` and `ssa._sign_custom` take the
  same argument with the same default, so no path reaches libsecp256k1
  with a weaker policy than the one above it. A signature that fails is
  a `RuntimeError` and is never returned.
- **The two halves of that arrived by different routes.** For BIP340 it
  is a step of the algorithm rather than a practice around it: *Default
  Signing* ends with "If Verify(bytes(P), m, sig) returns failure,
  abort", and the BIP's own note gives the reason and the escape --
  computation errors, random or provoked, yield a signature that "may
  leak information about the secret key", and the step "can be omitted
  if the computation cost is prohibitive". For ECDSA no standard asks,
  and Bitcoin Core does it anyway at the end of `CKey::Sign`, with no
  way to decline; declining is what `verify=False` is here.
- **What it costs was measured rather than reasoned about**, the
  variants alternated in one process over 7 rounds of 20 000 calls with
  the minimum kept for each -- an Apple M5, macOS 26.6, arm64, CPython
  3.13.14, and a noise row of ±0.04. `dsa.sign` 12.15 against 31.67,
  `ssa.sign` 15.87 against 28.57, `ssa.Signer.sign` 8.18 against 20.82.
  The finding is the gap between the two increments: 19.5 for ECDSA
  against 12.7 for BIP340, the 6.8 between them being the point
  multiplication `secp256k1_ec_pubkey_create` does and
  `secp256k1_keypair_xonly_pub` does not. The step the specification
  prescribes is the cheaper of the two, which is why neither is opt-in.
- **A caller that signs and does not publish pays for a guarantee it may
  not want**, and `verify=False` is the whole of the remedy: the
  signature is the same bytes either way, which
  `tests/test_verified_signing.py` asserts at each entry point rather
  than at one of them.
- **`recovery.sign` is in it too, and asks a different question** (#217).
  It takes the same keyword-only `verify`, defaulting to `True`, and so
  does `recovery._sign_`; what it does with it is recover the public key
  from the signature and refuse one that is not the signer's, rather
  than verify. The difference is the recovery id, which a verification
  does not look at: a signature carrying the wrong one verifies
  perfectly and then recovers somebody else's key, and recovering a key
  is what a caller of that module does with the answer. Core makes the
  same distinction in the same file -- `CKey::Sign` ends in
  `secp256k1_ecdsa_verify`, `CKey::SignCompact` in
  `secp256k1_ecdsa_recover` and `secp256k1_ec_pubkey_cmp` -- and it
  subsumes the verification exactly rather than probably. Recovery is
  not selective: for a given id it answers *the* key under which that
  `r` and `s` verify, so an inconsistent pair does not fail, it comes
  back as a different key -- and fails only where `r` is not the x of a
  point at all, which a faulted `r` is about half the time. Which is the
  stronger argument: the recovered key is by construction the key that
  verifies the signature, so `recovered == signer` **is** a verification,
  with the id checked besides. Nothing is given up by not verifying, and
  that is provable rather than argued.
- **What that check costs was measured in a session of its own**, which
  re-measured `dsa.sign` beside it rather than printing the two
  together: `recovery.sign` 12.02 against 34.41, `dsa.sign` 12.06
  against 31.54 there, agreeing with the 12.15 and 31.67 above. So the
  recovery shape costs 22.4 against ECDSA's 19.5, a recovery being about
  a verification's work with the comparison and the derivation making up
  the rest. Same method as the rest, noise +/-0.02.
- **`_abort_unless_recovered` turns `_recover_`'s `ValueError` into a
  `RuntimeError`**, which is the one place the two exception kinds of
  this package meet. "No key can be recovered" is an argument error of a
  signature a caller handed in, and nothing of the sort for one made a
  line earlier: what it reports there is the computation having gone
  wrong, which is what a `RuntimeError` means throughout.
- **The three do not check quite the same region**, which is worth a
  sentence and not a change. `ssa` verifies the 64 octets it answers
  with; `dsa` verifies the signature object and serializes it after, so
  the encoding is outside what was checked. `recovery` is the case worth
  the sentence most: what its check reads is the id inside the
  `secp256k1_ecdsa_recoverable_signature`, and the id the caller
  receives is the one `serialize_compact` writes afterwards -- so the id
  is outside the checked region exactly as the DER is. Core does the
  same, `CKey::SignCompact` recovering from `rsig` and not from the
  octets it filled, and for the same reason: the serializers are
  memcpy-shaped where the signing is arithmetic.
- **`xonly._from_keypair_` is new**, and is what makes the BIP340 half
  cheap: `xonly.from_keypair` is now that call with a serialize behind
  it, where reaching the key through the public half would have written
  a point out only to lift it back, and a lift is a field square root.
  It is the one private half whose object is a keypair, so
  `test_every_private_half_is_paired` excuses it from the parametrized
  tables the way it already excuses `ssa._verify_` and
  `xonly._tweak_add_`, and a test of its own holds the equality.
- **The fault is out of reach for the two that verify, and reachable for
  the one that recovers.** No input makes a fresh ECDSA or BIP340
  signature fail its own verification, so in `dsa` and `ssa` the `raise
  RuntimeError` is excluded from coverage for the reason every other one
  is. What is tested there is the wiring around it: the verification is
  substituted for one that refuses, and each entry point is held to
  raising rather than returning -- and, in the other direction, to *not*
  raising where `verify=False` was passed, which is the only assertion
  that sees the flag at all: the signature is the same bytes whether or
  not it was honoured, so a `verify` ignored altogether answers exactly
  what it should. Replacing every `if verify:` with `if True:` leaves
  the rest of the suite passing, which is how that hole was found rather
  than argued for. The keys of both y parities are signed with as well,
  both parities asserted to occur, because a check read off the wrong
  half of the negation BIP340 prescribes would pass for the wrong
  reason. `recovery` is the exception, and it is the test that says what
  the check is for rather than that the raise is wired to it: what that
  check reads is the recovery id, a wrong id is one `parse_compact`
  away, and `test_the_recovery_id_is_what_the_check_catches` produces
  the fault from an input and holds real libsecp256k1 to refusing it
  with no stand-in anywhere — the other parity of the same `r` recovers
  somebody else's key, ids 2 and 3 recover nothing, and the octets
  refused three lines up still verify as a plain ECDSA signature.
- **`dsa.sign` carries a `noqa: PLR0913`** and the reason above it: six
  arguments where the rule allows five, and the alternative is an
  options object for one function whose four questions group with
  nothing.
- **The default is Bitcoin Core's, and what it costs is now in the
  docstrings** (#224). Whether `dsa.sign` should default to
  `verify=False` — no standard asking the check of ECDSA, and the caller
  paying for a public key the signing itself did not need — was asked
  and answered the other way: one policy across the three modules, which
  is `CKey::Sign`'s, and a caller that has measured the check against
  its own threat model turns it off by name. A default per scheme would
  make the safer answer the one a reader has to look up, and
  `verify=False` is already the whole of the remedy. What was missing is
  the magnitude: the docstrings priced `grind` at "what the octet is
  worth" and left the check that is on by default at "a point
  multiplication and a verification", which is its shape and not its
  size. `dsa.sign` says 31.67 microseconds against 12.15 now, `ssa.sign`
  28.57 against 15.87 with the 6.8 between the two increments named as
  the `secp256k1_ec_pubkey_create` ECDSA has to do and BIP340 does not,
  and `recovery.sign` 34.41 against 12.02, the dearest of the three.
  `ssa.Signer.sign` carries the ratio rather than a third increment —
  20.82 against 8.18, the check being more than half again a signature
  whose keypair was built already, where `ssa.sign`'s is four fifths of
  one, and 1.545 against `dsa.sign`'s 1.607 is where BIP340's cheaper
  check costs what ECDSA's does — and `ssa.sign_custom`, the entry point
  btclib calls, carries `sign`'s figure with the sentence that a longer
  message costs more to sign and to check by the same hash. The figures
  are the ones measured above rather than a second session. `dsa.sign`
  also says what a caller grinding *outside* the call pays, that being
  one check per attempt where the wrapper's own `grind` checks only the
  attempt it settles on — which is the reading the caller that raised
  the issue was getting.
- **The record said the fault is not tested, and a test produces one**
  (#225). The bullet above opened "The fault itself is not tested,
  because no input produces one", which was true of #216 and false after
  #218: `recovery`'s check reads the recovery id, a wrong id is one
  `parse_compact` away, and the test that produces one holds real
  libsecp256k1 to refusing it with no stand-in. The test module's own
  header carried the same sentence and was qualified in #218; this file
  was not, so the record stated of the suite the opposite of what the
  suite does — the same defect as the "eight entry points" count #218
  removed, a claim about the tests that the tests disprove. It now
  carries the qualification the test module already found. Two lines
  from the same tail go with it: the docstring of
  `test_a_signature_that_does_not_verify_is_not_answered_with`
  documented `refusal` as "unused where the test does not refuse one",
  which was true of the other readers of `SIGNERS` and false of exactly
  this one, where it is the `match=`; and the 34-character line of this
  file's own prose, between lines of 69 to 72, which was the reflow a
  qualifier insertion did not get. That last one is why the paragraph
  above is rewrapped whole rather than at the line named: inserting the
  qualification left two more widows of the same shape, at 14 and 27
  columns, so a fix line by line would have closed one instance of the
  class and opened two. #233 counts the thirteen this change does not
  reach. No hook reflows prose, which is why every one of them passed
  the gate.
- **`SIGNERS` stops handing a test an argument no body reads** (#226).
  It grew a third element in #218 and that closed a real gap: before it
  one `match="signing produced"` matched all three modules, so the test
  could not say which failure it had provoked. The cost was that four
  tests are parametrized over the table, one reads the refusal, and the
  three that do not each carried two lines of docstring explaining that
  they do not — which is how that sentence reached the fourth.
  `SIGNING_CALLS` is the calls alone and `REFUSING_CALLS` the call with
  its refusal, both derived from `SIGNERS` in a comprehension, and the
  name goes with the refusal: it is the `ids=` and no body has ever read
  it, so five tests stop declaring it and five docstrings stop excusing
  it. `_DEFAULTING` is the same move on the one table that is not
  `SIGNERS` — a mapping of the ten functions whose default is asserted,
  its keys being those ids. The mapping the issue proposed instead —
  `_REFUSALS` keyed by module, with `SIGNERS` back to pairs — is
  declined for the reason the issue states against itself: a row would
  no longer be the whole truth about its entry point, and finding a
  module by splitting a test id on `.` is a weaker statement than the
  message written beside the call. The ids are stated once as well,
  every table here being those rows in that order.
- **The module docstring of `tests/test_verified_signing.py` names the
  tests it points at** (#256). Two of its landmarks were positions rather
  than names, and each had come to name the wrong test. "The last test in
  this file" arrived with #217 meaning
  `test_the_recovery_id_is_what_the_check_catches`, and #245 appended the
  `dsa` group after it. "The last of those tests" meant
  `test_a_wrong_id_under_a_right_key_is_not_reported_as_a_wrong_key` and
  arrived with #246 -- which in that same diff put two tests after the one
  it points at, so it was false in the commit that wrote it. That is the
  whole argument against the form: a position is a claim nothing checks,
  and an append falsifies it in silence, sometimes its own. Both now name
  the test.
- **And the account of the two key-handed-in groups gains the third thing
  they hold**, in one clause for both halves rather than one for `dsa`:
  that the saving is asserted and not only priced, by
  `test_the_derivation_the_argument_saves_is_not_made_at_all` and
  `test_the_derivation_the_recoverable_check_saves_is_not_made_at_all`.
  Raised as a non-blocking review finding on #254, where folding it into
  that diff would have put the asymmetry in a second place. What a name
  still does not buy is a check -- a rename falsifies it as quietly as an
  append falsified a position -- which is #258, and the count in the same
  docstring is #259.

### The frames between an entry point and libsecp256k1

- **Five entry points are spelled out rather than composed of their
  halves**: `keys.parse` and `xonly.parse`, which delegated to their
  `_parsed`, `keys.pubkey_tweak_add`, which was three calls, and
  `dsa.verify` and `ssa.verify`, which parsed through one call and
  verified through another. What a python frame is worth was measured by
  alternating the two spellings in one process, 7 rounds each and the
  minimum kept for each -- an Apple M5, macOS 26.6, arm64, CPython
  3.13.14: `keys.parse` of 65 bytes 0.010 of 0.205 and of 33 bytes 0.013
  of 2.324, `xonly.parse` of 65 bytes 0.012 of 0.485, `ssa.verify` 0.009
  of 14.275, `dsa.verify` 0.035 of 11.813, `keys.pubkey_tweak_add` 0.037
  of 3.403. Small everywhere, and largest where the call is shortest.
- **`dsa.sign` is composed still, and that is a measured result rather
  than an omission.** Three spellings were tried -- `_sign_` inlined, the
  DER serialization inlined, and both -- and all three land within 0.03
  microseconds of the composed one and on the wrong side of it. A
  signature is 11.9 microseconds of libsecp256k1; two python frames do
  not show against it, and a body written twice for nothing is worse
  than the frames.
- **Measuring the two spellings one after the other is what made them
  look bigger.** Run in sequence rather than alternated, the same
  comparison reported 0.027, 0.083, 0.154 and 0.261 for four of the
  calls above -- two to four times the alternated figure, and for
  `dsa.sign` a saving that is not there at all. The machine drifts under
  a benchmark, and a pair measured in a fixed order gives the drift to
  one side of it.
- **Every private half stays, and removing them was measured before it
  was declined.** They are what a caller holding a parsed object does
  not pay a parse for, and that is worth 0.558 microseconds per call
  against a 65-byte key, 2.676 against a 33-byte one -- where the parse
  is a field square root -- and 2.687 on a tweak applied to its own
  output. Two orders of magnitude more than the frames are worth, and in
  the opposite direction: deleting them to save a frame on the octets
  path would cost the object path a parse at every call. `ssa.Signer`
  and `keys.PubkeyTweakChain` are the same trade already made.
- **So five bodies are written twice**, once taking octets and once
  taking the object, and the equality is asserted rather than assumed:
  `tests/test_parsed_keys.py` holds every public half to its private
  one, pair by pair and over both serializations of a public key, and
  `test_every_private_half_is_paired` makes an unpaired half an absence
  rather than a test nobody wrote. That test is what makes the
  duplication survivable, and it is why it was not extended to
  `recovery`, `ellswift` or `silentpayments`, whose entry points no
  benchmark reaches and which still compose.

### What a crossing costs, and what stops being paid for it

- **`context.guarded` is gone, and every call it held is now a bare
  call.** It cleared the thread, ran the libsecp256k1 call, and raised
  whatever the illegal callback had recorded, which turned a refused
  object into an exception at each of the twenty-six places it was
  used. Measured around one trivial C call, it cost 0.201 microseconds
  of the 0.292 that call took — an Apple M5, macOS 26.6, arm64, CPython
  3.13.14, minimum of 9 rounds of a million calls — and an entry point
  crossing twice, as `keys.pubkey_tweak_add` does, paid it twice.
  `context.check` is unchanged and still exported: what it reports is
  now every caller's to ask for, and its docstring says when.
- **and what a refused object does instead is the contract this
  changes.** Where the wrapper read a return code it still raises, with
  its own message rather than libsecp256k1's — `keys.serialize` of a
  NULL pointer is a `RuntimeError` naming the serialization, where it
  was a `ValueError` naming `pubkey != NULL`; `xonly.serialize`,
  `xonly._drop_y`, `xonly.from_keypair`, `recovery._to_der_`,
  `recovery.serialize_compact`, `dsa.serialize_der`,
  `dsa.serialize_compact` and `silentpayments.serialize_label` moved
  from `ValueError` to `RuntimeError` with it, libsecp256k1 answering
  the same 0 for a refusal as for a failure of its own. Where the
  wrapper believed the return value, there is now no exception at all:
  `dsa._verify_` and `ssa._verify_` answer `False`, `keys._pubkey_sum_`
  answers `None`, `keys._pubkey_cmp_` answers an ordering, `dsa._is_low_s_`
  answers `True`, and `ecdh._shared_secret_` answers 32 bytes that are a
  shared secret with nobody. Each is driven in `tests/test_callbacks.py`
  rather than described, the ECDH one because it is the gravest: the
  call succeeds, the answer is the right length, and only the thread
  says it is worthless.
- **No entry point taking octets is in that position**, which is why the
  trade is worth stating separately from the cost. `verify`,
  `pubkey_tweak_add`, `shared_secret` and the rest parse what they are
  given, so the objects they hand libsecp256k1 are ones it has just
  built and the refusal cannot arise; a bad key is the parse's
  `ValueError`, and the thread is left clean. What is given up belongs
  to a caller passing a `secp256k1_pubkey` of its own to a `_foo_` half,
  and `keys.pubkey_verify` on the octets it came from is what settles it
  once instead of at every call.
- **`_scalar.octets` and `_scalar.scalar` answer `bytes` without asking
  the questions `bytes` already answers**, 0.034 microseconds against
  0.080 on the same machine. The two `isinstance` tests, the
  `memoryview` width test and the defensive copy are what a `bytearray`
  or a `memoryview` needs, and are what the slow path still does; the
  exact type is asked once in front of them. `dsa.verify` passes three
  arguments through it.
- **`keys.serialize` stopped building its buffer from an interpolated
  cdecl**, 0.313 microseconds against 0.356 with the guard already gone
  and 0.604 before it: `ffi.new` of an `f"char[{size}]"` parses that
  string on every call, and `ffi.sizeof` was called twice where the size
  was in hand. It went to a literal here and then to a hoisted type, for
  the reason and at the price the entry below states; what follows is
  what did not change. The length buffer is still built per call and
  deliberately not hoisted, though it holds the same number every time —
  libsecp256k1 writes 0 into it before it does anything and restores it
  only on success, and it holds what it finds there against 33 or 65 on
  the way in, so one failed call would leave a shared buffer at zero and
  every later serialization, on any thread and of a perfectly good key,
  would be refused. That was measured rather than reasoned about.
- **What the entry points cost now.** Microseconds per call on the
  machine above, the quickest of two passes run in either order so that
  neither tree is the one measured on a warm machine, before against
  after: `keys.parse` of 65 bytes 0.258 and 0.213, of 33 bytes 2.314 and
  2.294, `xonly.parse` of 65 bytes 0.832 and 0.500,
  `keys.pubkey_tweak_add` 4.179 and 3.480, `dsa.sign` in DER 12.063 and
  11.766, in the compact form 12.072 and 11.733, `dsa.verify` in DER
  12.221 and 11.846, in the compact form 12.203 and 11.880, `ssa.sign`
  15.724 and 15.631, `ssa.verify` of a 65-byte key 13.159 and 12.476, of
  an x-only key 14.624 and 14.272. The 33-byte parse is where there was
  nothing to win and the figures say so: the field square root is what
  that row is.

### What importing the package costs

- **`__version__` is read on first access rather than at import** (#210).
  The value comes from where it came from -- the installed distribution
  metadata, so that `pyproject.toml` stays the only place a release bumps
  -- and a module-level `__getattr__` (PEP 562) is what defers reading
  it. `importlib.metadata` pulls `email`, `json` and `inspect` behind it,
  among others.
- **`pathlib` is imported where it is used**, which is the dynamic branch
  of `_load_lib`. A static extension returns from `hasattr(module,
  "lib")` two lines earlier, and a static extension is what every
  platform of the matrix ships by default.
- **It takes both, and deferring `import pathlib` alone would have bought
  nothing.** `importlib.metadata` imports `pathlib` itself, and
  `import pathlib` was the statement *above* the one that read the
  version, so on the file as it was `pathlib` arrived whether that first
  line ran or not: the row below measures it at 0.09 milliseconds, which
  is nothing. The 2.27 that deferring it is worth here is a saving this
  branch creates rather than one that was lying there.
- Every figure below is one session, one build, `__init__.py` the only
  thing that differs, minimum of 12 fresh interpreters each -- an Apple
  M5, macOS 26.6, arm64, CPython 3.14.6. It is the only place this
  decomposition is written down; the docstrings that quote a figure send
  the reader here rather than repeating the split.

  ```shell
  # after each swap, run it once and throw that answer away: a changed
  # __init__.py invalidates its .pyc, and compiling this file is about a
  # millisecond -- most of the number being reported for the branch
  python -c "import time, importlib
  t = time.perf_counter(); importlib.import_module('btclib_secp256k1')
  print((time.perf_counter() - t) * 1e3)"
  ```

  | | ms |
  | --- | --- |
  | as it is now, both deferred | **1.69** |
  | with `import pathlib` back at module level | 3.96 |
  | with the `importlib.metadata` import back instead | 10.98 |
  | the file as it was: both, and the `version()` call | 15.85 |
  | the file as it was, with `import pathlib` deferred alone | 15.76 |
  | as it is now, then reading `__version__` | 15.59 |
  | the file as it was, then reading `__version__` | 15.97 |
  | `_btclib_secp256k1`, the extension, either way | 0.58 |

  The middle rows are marginal costs over this branch, each measured by
  putting one statement back, and they do not add up to the fourth: the
  9.3 of the metadata import already contains `pathlib`'s 2.27, and what
  is left of the 15.85 is the first `version()` call, 4.9 of it.

  The last two rows before the extension are the same number and not a
  saving of 0.4: a caller that reads the version pays what it paid, and
  which of the two comes out ahead is the drift of the machine between
  two batches.

- **The value is stored into the module's namespace on the way out.**
  `sys.modules` caches the module `importlib.metadata` is, not the answer
  `version()` gives, so a `__getattr__` that only defers would leave
  every read after the first walking the metadata again -- 290
  microseconds each, where the attribute it replaced was a dict lookup at
  0.010. Storing it is the usual shape of PEP 562 and makes the second
  read 0.018. It is also what makes the `dir()` sentence below true: the
  interpreter does not memoise a module `__getattr__`, so without this
  the attribute would never appear at all.
- **The reading of the version is outside the `TYPE_CHECKING` guard**,
  in `_read_version`, and only the `__getattr__` is inside it. mypy does
  not check the body of the `else` such a guard takes: with the two
  working lines in there, `return len(version(...))` from a function
  annotated `-> str` passes `--strict`, and `warn_unreachable` does not
  catch it either. Out here the same error is `[return-value]`, which is
  what `py.typed` and *a wrong annotation propagates* ask for.
- **The `__getattr__` is behind `if TYPE_CHECKING`, and that is the
  point of the change surviving the gate.** A module that has one is a
  module mypy stops checking attribute names on: measured on this tree,
  `from btclib_secp256k1 import nosuchmodule` and
  `btclib_secp256k1.typo` both stop being errors under `--strict`, and
  that is the front door of the package. Declaring `__version__: str` to
  the type checker and defining the function only at run time keeps both
  checks, and `tests/test_extension.py` needing a
  `type: ignore[attr-defined]` to ask for a missing attribute is the
  proof that it does.
- **Two tests hold the saving**, `test_import_defers_the_metadata` and
  `test_import_defers_pathlib`: each imports the package in a subprocess
  and asserts what is *not* in `sys.modules` afterwards. Nothing else
  would notice a module-level import added later, here or in anything
  this package imports, which is how the 13 milliseconds arrived. The
  second is skipped on a dynamic extension, which reaches `_load_lib`'s
  other branch and imports `pathlib` legitimately; the matrix runs the
  suite both ways.
- **What it costs a caller** is that `dir(btclib_secp256k1)` does not
  list `__version__` until something reads it, and does afterwards.
  Nothing else changes: the attribute, the `from … import __version__`,
  and reading the metadata directly all answer what they answered.

### The out-parameter that is the caller's to ask for

- **`xonly._from_keypair_` takes its parity pointer, defaulting to NULL**
  (#219), which is the shape the entry below gives `xonly._drop_y` and
  which libsecp256k1 documents in the same words for both:
  `secp256k1_extrakeys.h` says `pk_parity: Ignored if NULL` of
  `secp256k1_keypair_xonly_pub` as it does of
  `secp256k1_xonly_pubkey_from_pubkey`. `from_keypair` allocates one and
  reads it; `ssa._abort_unless_verified`, which threw it away, passes
  nothing. The allocation sits at the one call site that wants it rather
  than behind a helper — `_drop_y` needed `_drop_y_with_parity` because
  it has two such callers, and this has one.
- **It is worth 28% of the conversion and nothing where the conversion
  is**, and both halves of that are the point of taking it. Same session
  shape as the entry below — the two spellings alternated in one process
  over 15 rounds, a noise row beside each, an Apple M5, macOS 26.6,
  arm64, CPython 3.14.6:

  | | with the parity | with NULL |
  | --- | --- | --- |
  | the conversion alone | 0.2384 | 0.1718 |
  | `ssa.sign` with the check on, which is where it runs | 19.9400 | 20.0303 |
  | *noise*, the conversion twice | 0.2353 | 0.2404 |

  −28.0% on the call, +0.45% on the path against a noise row that moved
  2.18% — which is to say nothing, an `ffi.new` being some hundredths of
  a microsecond against a signature and a verification. **So this is
  taken for the convention and not for the speed**: the package had two
  answers to one question, written a week apart, and now has one.
- **One test holds it, and it takes two keys to.**
  `test_the_keypair_parity_is_the_callers_to_ask_for` runs over an even-y
  key and an odd-y one and asserts the 0 and the 1, because
  `ffi.new("int *")` zeroes what it allocates: over an even-y key alone
  every side of every comparison is 0 whether the pointer was written
  through or not, and discarding it inside the helper is then a mutant
  the whole suite passes while `xonly.from_keypair` answers 0 for every
  odd-y key. With both keys that mutant fails at the assertion meant to
  catch it. The same mutation on `_drop_y` fails eight tests, so the
  claim these two conversions now share is one the suite holds on both.

### What a wrapper works out per call, and now works out once

- **An interpolated cdecl is resolved at import, not at every call**
  (#212). `xonly.serialize` and `silentpayments.serialize_label` declared
  their buffer with `ffi.new(f"char[{_XONLY_SIZE}]")`, which states the
  width once — the reason it is an f-string — and costs twice what a
  literal does, cffi having to hash a string built afresh each time:
  0.1219 microseconds against 0.0681. `ffi.typeof` of the same f-string,
  evaluated once at module level, is the literal's price with the width
  still stated once.
- **A literal cdecl is left exactly as it was**, and that is the measured
  half of the same rule. cffi already caches the parse of one, so
  hoisting a literal saves 0.003 microseconds — real, 4.3% on a noise row
  of 0.5%, and an order below the 0.054 an interpolated cdecl gives back.
  That is the size a hoist has to be worth to justify spelling a width
  twice, or naming every cdecl in the package at module level, so every
  `ffi.new` here still spells its cdecl in full — including the two
  beside the hoisted types.
- **`ffi.sizeof` of a buffer whose size is a constant is not asked per
  call**, and that is what asked `keys.serialize` for a type at module
  level: the width is stated once and the type built from it, so the
  buffer and the length cannot say different numbers, and the 0.0175
  microseconds is not paid at every call. `keys.serialize` also decides
  its flag in the branch that picks its buffer, so the one condition is
  asked once. The length *object* is still built per call, for the
  thread-safety reason its comment gives.
- **Every buffer in the package whose bytes are unpacked is spelled that
  way now**, the eight sites that still asked `ffi.sizeof` of a cdata
  per call included: `dsa.serialize_der`, `dsa.serialize_compact`,
  `recovery.serialize_compact`, `hashes.tagged_sha256`,
  `ellswift.create`, `ellswift._encode_`, `ssa._sign32` and
  `ssa._sign_custom`. An int constant states the width, `ffi.typeof` of
  it is the buffer's type, and that same constant is the length — and
  where a module validates an argument against the width it writes,
  `dsa`, `recovery`, `ssa` and `ellswift` check it against the constant
  rather than against a second copy of the number.
- **What the mutants say, which is not that there are more of them.**
  `core/NumberReplacer` emits two mutants per numeric literal — `dsa.py`
  holds 20 and `cosmic-ray init` enumerates 40 of them among its 376 — and
  an AST census of the package counts 67 literals before this change and
  67 after: `ellswift` sheds two and `ssa` one, `hashes` gains one and
  `keys` two, and the surface is the size it was. Only three of the
  seven widths had no int literal anywhere before (`hashes._HASH_SIZE`,
  `keys._COMPRESSED_SIZE`, `keys._UNCOMPRESSED_SIZE`), so six mutants are
  new; the other four replace the seven literals that sat at the
  validation sites — `dsa`'s `!= 64`, `recovery.parse_compact`,
  `ssa._verify_` and `ssa.verify`, `ellswift._decode_` and both of
  `xdh`'s — which were fourteen of their own.
  What changed is what each covers: a width inside `"char[64]"` was
  reachable by no operator, so a wrong *buffer* was a mutation nobody
  could ask about, and the mutable copy answered only for the argument
  check. One number answers for both now, so each of the fourteen tests
  both — same count, more code under each. All fourteen die, each applied
  to the source one at a time with bytecode writing off and a passing
  control run either side.
- **The DER capacity is the one width not written as an int**, and it is
  the site where taking that trade would have cost a kill rather than
  bought one: what `serialize_der` unpacks is `length[0]`, the length
  libsecp256k1 reports back, so 73 leaves the whole suite passing where 71
  fails `test_der_reaches_all_72_octets` — the shape
  `.github/mutation/bindings.toml` records as closed, six of thirteen
  survivors, answered by deriving the capacity from the buffer rather than
  writing it twice. So it keeps `ffi.typeof("char[72]")` with `ffi.sizeof`
  of it, asked at import and not per call. Of the 40 `NumberReplacer`
  mutants `cosmic-ray init` enumerates in the module, the two that fall in
  the declaration block are both on `_COMPACT_SIZE` and none on those two
  lines: the width is stated once and there is no int for the operator to
  move.
- **What consolidating costs, since nothing else records it.** `ellswift`
  had three independently mutable copies of 64 — `_decode_` and both of
  `xdh`'s — and `ssa` had two; each is one constant now, so a single
  mutant changes every site at once and dies on whichever test reaches it
  first. Nothing is hidden today: every one of those seven literals was
  mutated on `main`, one at a time, and each dies on its own. But a check
  that later loses the test that covers it can no longer surface as a
  survivor, and `bindings.toml` asks for a survivor list to be read
  expecting nothing — so the trade is named here rather than left for a
  session to rediscover.
- **Four of the eight save nothing the measurement can resolve, and are
  spelled that way regardless.** The saving is 2.65% to 5.53% of the four
  serializations, and some hundredths of a microsecond of the two
  `ellswift` encodings and the two `ssa` signings, which cost 14.85 to
  30.54 — where timing each of those four against *itself* moves 0.003 to
  0.10, so the effect is under the resolution of its own measurement.
  What decided them is not the figure: a reader cannot see the cost of a
  host, so two spellings of one shape would leave the difference
  unexplainable at both, and a comment saying why a site was *left* alone
  is a comment about a non-change. One spelling is the whole of the
  reason, and the saving is what pays for the four where it shows.
- **`keys.py` derives its two the other way round**, so the six modules
  read alike: it stated `ffi.typeof("char[33]")` and took the size as
  `ffi.sizeof` of that type, where `xonly` and `silentpayments` state an
  int and build the type from it. The int is the spelling that says what
  the number is, and it is the one the whole package uses now.
- **What the eight cost, and what they cost now.** `main`'s spelling of
  each call written out and alternated against the shipped one in a
  single process over one build on the tree this branch lands as,
  minimum of 15 rounds — 500 000 calls for the primitive, 300 000 for
  the serializations, 20 000 for the four hosts — with every pair
  asserted to answer alike before it is timed, and a noise row for each
  site rather than for one of them. An Apple M5, macOS 26.6, arm64,
  CPython 3.14.6, microseconds per call:

  | | main | now | noise |
  | --- | --- | --- | --- |
  | `ffi.unpack` of a 64-byte buffer | 0.0690 | 0.0520 | 0.0005 |
  | `dsa.serialize_compact` | 0.1823 | 0.1765 | 0.0007 |
  | `dsa.serialize_der` | 0.2784 | 0.2665 | 0.0008 |
  | `recovery.serialize_compact` | 0.2720 | 0.2569 | −0.0009 |
  | `hashes.tagged_sha256` of an empty message | 0.5957 | 0.5800 | 0.0007 |

  The per-site saving is 0.006 to 0.016, and it is neither one number nor
  the primitive's 0.017. Within a session the noise rows move under 0.001,
  so no row here is noise; across four sessions the same site moved by
  more than that — `dsa.serialize_compact` between 0.006 and 0.013, the
  lowest of the four every time, `recovery` and `hashes` the highest. So
  what the measurement supports is a hundredth of a microsecond at a
  serialization rather than a figure per site, and no row is a regression.

  And the four hosts the saving disappears into, each timed against itself
  so that the row *is* the resolution: `ellswift.encode` 14.9537 and
  14.8501, `ellswift.create` 19.9003 and 19.9046, `ssa.sign` 30.2860 and
  30.2031, `ssa.sign_custom` 30.5408 and 30.5379 — moving 0.003 to 0.10
  either way around an effect of some hundredths. Every figure in the
  comments of `dsa.py`, `recovery.py`, `hashes.py`, `ellswift.py`,
  `ssa.py` and the last paragraph of `xonly.py`'s is from this session.
- **`_secret.take` zeroes through the view it already holds.** It built
  an `ffi.buffer` to read the secret and then called `wipe`, which built
  a second one over the same cdata. The statement that writes the zeros
  is now `_zero`, which `wipe` calls too, so it is written once — and
  that frame is paid for deliberately: `wipe` twice is 0.1826
  microseconds, `_zero` is 0.1439 and the same statement inlined in both
  places is 0.1314. A quarter of what was on the table, for one copy of
  the line that overwrites a secret rather than two.
- **The parity nobody reads is not allocated.**
  `secp256k1_xonly_pubkey_from_pubkey` documents `pk_parity` as "Ignored
  if NULL", and the callers that want the object alone — `parse`, `_parsed`
  and `_tweak_add_` — are why NULL is the default. `_drop_y` takes the
  pointer as an argument now: 0.1747 microseconds against 0.2425 on the
  conversion alone. `_from_pubkey_` and `to_pubkey` read a parity and go
  through `_drop_y_with_parity`, which is that allocation written once,
  and no saving lands on them — what it adds is some hundredths of a
  microsecond, measurable against both. One figure rather than one per
  caller: it is the same frame at each, and two harnesses put a different
  one of the two ahead, which is the spread of a number this small and
  not a structure. What they get out of this is the C call still written
  once and the call site they had.
- **Two sessions, and each is named where a figure comes from.** Every
  wrapper figure this change quotes — in CHANGELOG.md, HISTORY.md and in
  the comments of `keys.py`, `xonly.py`, `silentpayments.py` and
  `_secret.py` alike — is the one below; every cffi-primitive figure is
  the one after it. An Apple M5, macOS 26.6, arm64, CPython 3.14.6.

  `main`'s spelling of each call written out and alternated against this
  one in a single process over one build, minimum of 15 rounds of
  200 000 calls, a noise row running `main`'s spelling twice, and every
  pair asserted to answer alike before it is timed:

  | | main | now |
  | --- | --- | --- |
  | `_drop_y`, the conversion alone | 0.2425 | 0.1747 |
  | `xonly.serialize` | 0.2569 | 0.1969 |
  | `silentpayments.serialize_label` | 0.2621 | 0.2023 |
  | `_secret.take` | 0.1826 | 0.1439 |
  | `xonly.parse`, 65 bytes | 0.5021 | 0.4295 |
  | `xonly._from_pubkey_`, 65 bytes | 0.5127 | 0.4711 |
  | `keys.prvkey_negate` | 0.3790 | 0.3380 |
  | `keys.serialize`, compressed | 0.3106 | 0.2906 |
  | `keys.serialize`, uncompressed | 0.3101 | 0.2903 |
  | *noise* | 0.2578 | 0.2577 |

  and the primitives, minimum of 15 rounds of 300 000 calls:

  | | first | second |
  | --- | --- | --- |
  | `ffi.new` of an f-string, then of a literal `char[32]` | 0.1219 | 0.0681 |
  | `ffi.new` of a literal, then of a hoisted `char[33]` | 0.0685 | 0.0656 |
  | `ffi.new` of a literal, then of a hoisted `size_t *` | 0.0809 | 0.0774 |
  | `ffi.unpack` with `ffi.sizeof`, then with the constant | 0.0764 | 0.0589 |
  | *noise* | 0.0676 | 0.0680 |

- **`_scalar.scalar` was measured and left alone**, which is the one
  declined here. Asking `type(num) is int` instead of
  `isinstance(num, int) and not isinstance(num, bool)` is one check where
  those are two and excludes `bool` on its own, and it is 0.141
  microseconds against 0.157 — but it needs the range check and the
  serialization written twice, once for the exact type and once for the
  subclass, and the int path is the one this module's own docstring says
  is not the common one: a scalar handed to these bindings in a loop is
  bytes, and that path does not reach the test at all.
- **The stub gains an opaque `_CType`**, which is what `typeof` answers
  and what `new` takes beside a string. Typing that argument `Any`
  instead would be the vacuous type-checking
  `stubs/_btclib_secp256k1.pyi` exists to prevent: `ffi.new(_XONLY_SIZE)`
  — an int where a cdecl belongs, and the size and the type built from
  it now sit a dozen lines apart in the same module — passes `--strict`
  with `Any` and is an `[arg-type]` error with `_CType`.

### Signing under one key

- **`ssa.Signer` builds the BIP340 keypair once** (#153). `ssa.sign` and
  `ssa.sign_custom` build a `secp256k1_keypair` from the private key and
  wipe it in a `finally`, so a caller signing several messages under one
  key pays for it once per signature — and it is about half of what a
  signature costs, being the point multiplication of the public key.
  Measured on this tree, on an Apple M5, macOS 26.6, arm64, CPython
  3.14.6, minimum of 10 rounds of 20 000 calls, microseconds per call:
  `ssa.sign` 15.7, `Signer.sign` 8.2, `secp256k1_keypair_create` alone
  7.3 — the saving is the keypair and nothing else, and it puts one
  signature at the cost the C call itself has. `sign_custom` is the same
  pair, 16.0 and 8.4. What holds the new path to the old one is not that
  agreement: `tests/test_vectors.py` signs every BIP340 vector through a
  signer as well, so both are held against bitcoin/bips' published value
- **and it hands the caller a lifetime, which is the trade it makes.**
  A keypair is the private key in libsecp256k1's layout, in memory this
  package owns and can overwrite, so a signer holds a secret across
  calls where the two functions hold one for the length of one. The
  `with` block is what makes the wipe deliberate rather than forgotten:
  `__exit__` overwrites the keypair whether the block ended in a
  signature or in an exception, `wipe()` is the same instruction by
  hand, wiping twice is not an error, and a wiped signer raises rather
  than signing with the zeros — it cannot be revived, the private key
  being kept nowhere else here. This is the case #87 declined and the
  reason it declined it does not cover: that issue asked whether an
  opaque secret handle buys *assurance*, and the answer was no, the
  python-side copies at import and export being what they are — an
  answer this does not disturb, SECURITY.md's limits being unchanged and
  the constructor still taking a `bytes` or an `int` nothing can zeroize.
  What is new is a measured cost, and it is paid by every caller signing
  more than once under one key. BIP340 only: `secp256k1_ecdsa_sign`
  takes the private key directly, so `dsa.sign` has no keypair to hoist
- **and a signer that is dropped rather than wiped is named where the
  guarantee is made** (#177). SECURITY.md said the cffi buffer holding a
  secret is zeroed before it is dropped, which is true of every one of
  them except this: a signer told neither `wipe` nor `with` is collected
  with the keypair still holding the private key, cffi freeing that
  memory without overwriting it. The sentence now names the exception,
  `Signer`'s own docstring says it where a caller meets the class, and
  `tests/test_signer.py` asserts it — the keypair kept alive by a
  reference of its own, the signer dropped and collected, the key still
  in those octets. A `weakref.finalize` would close it in three lines and
  is deliberately not there: it runs at a time nothing specifies, which
  reads as a guarantee without being one, and the test is what makes
  adding it a decision to reread rather than a silent reversal
- **the two functions are now the signer's two calls with the keypair
  built and wiped around them**, `_sign32` and `_sign_custom` being the
  shared body, so neither side can drift into a second spelling of the
  same checks. One consequence is visible: those checks now happen after
  the private key is turned into a keypair rather than before, so a call
  with *both* a bad private key and a bad message names the key where it
  used to name the message. Each on its own is refused as before, and
  every wipe that happened still happens

### Grinding for a low r

- **`dsa.sign(grind=True)` signs again until `r` is the low one** (#204).
  Bitcoin Core's `CKey::Sign` scheme and not a rephrasing of it: the
  first attempt is the plain RFC6979 signature, and each retry mixes a
  `uint32` counter, little endian in the first 4 of 32 octets, into the
  nonce, until the high bit of `r` is clear and DER therefore spends no
  leading zero octet on it. One octet shorter, about half the time, for
  two signatures' work — measured on this tree, on an Apple M5, macOS
  26.6, arm64, CPython 3.14.6, 2000 distinct keys signed once each, the
  variants alternated in one process, seven rounds with the minimum of
  each kept, microseconds per call: `dsa.sign` 11.7 against
  `dsa.sign(grind=True)` 24.9, at 2.09 attempts on the mean and 14 for
  the worst of those keys. A row running one variant twice is what says
  what the noise is, and it is 0.1.
  Off by default for that reason, and asked for by a caller who wants the
  octet. `dsa._sign_` takes it too; `s` has no counterpart, libsecp256k1
  having already returned the lower of the two, and `recovery.sign` does
  not get one, a recoverable signature being 65 fixed octets with nothing
  to shorten
- **the loop is python, and no C was written** — measured rather than
  assumed, and re-measured on this tree, the first figures published
  having compared loops that differed in more than where they kept their
  buffers. Four loops answering the same signature, alternated as above,
  in the compact form the retry reads: 24.7 for a caller's own loop over
  the public wrappers once per attempt, 24.8 for what landed, 24.6 for
  the same keeping one compact buffer per call, 24.5 for the same again
  with both scratch buffers at module level — which one shared context
  and a documented thread-safety story rule out anyway. Three tenths
  separate the four, against a noise row of one tenth, and a caller's own
  loop is not measurably behind the one inside the package: whatever a
  loop crossing the boundary once per signature could save lies inside
  that spread, and most of what is in the spread is the per-attempt
  serialization the predicate costs rather than the buffer placement,
  the two buffer rows being 0.1 apart. A loop compiled in C would have
  started from the last row, and would have been bought with the one
  property these bindings do not trade: a dynamic build compiles no C at
  all, so a C helper would be a feature the static wheels have and the
  dynamic ones do not. Grinding here is worth having for the scheme and
  the vectors that judge it, not for the microseconds
- **the retry reads the compact serialization, not the DER length**,
  which is not the same question: DER is `6 + lenR + lenS`, so a high `r`
  of 33 octets with an `s` that needs only 31 encodes to 70 octets too —
  about one signature in 500, measured over 200 000 — and a length test
  would take those for low-r ones. The first octet of the compact form is
  the top of `r`, which is what Core's `SigHasLowR` reads
- **`dsa.is_low_r` asks that of a signature a caller did not make**
  (#209), with `dsa._is_low_r_` the half taking the parsed one, as
  `is_low_s` has had since the beginning. Not a rule, unlike that one:
  `verify` asks nothing about `r`, a high-r signature being valid and
  always having been, so what this answers is whether a signature is the
  octet shorter that `sign(grind=True)` makes it. It is where the
  grinding loop's own test now lives too — one spelling of the
  predicate, asked per attempt, which costs about 0.2 microseconds of
  the 24.8 above against the compact buffer the loop used to keep (three
  alternated runs put it between 0.13 and 0.31, where the noise row
  moves 0.1), and buys that what a caller can check is what the loop
  ground to. Asked once of a signature already made, it is 0.5: a
  `parse_der` and a `serialize_compact`, 12.2 against the 11.7 of the
  `dsa.sign` beside it
- **`aux_rand32` and `grind` are refused together**, with a `ValueError`.
  Grinding writes the very 32 octets that argument is, so a caller asking
  for both is asking for two values of one argument; ignoring one of
  them, as Core does with its `test_case`, would make an argument vanish
  where every other one here is checked
- **what judges it is Core's vectors and rust-secp256k1's**, in
  `tests/test_vectors.py`: the two deterministic signatures of Core's
  `key_test1`, which are already low-r at the first attempt and so pin
  that asking for grinding changes nothing; the property
  `key_signature_tests` asserts over 256 messages, together with the
  high-r half of that same test, which says the loop has something to
  find; and rust-secp256k1's `test_low_r`, whose vector takes five
  attempts and so pins the counter itself, in an implementation sharing
  no line with Core's

### The parsed public key

- **`xonly.tweak_add_` tweaks the point, where `tweak_add` tweaks its
  x.** BIP341's output key is an internal key plus the TapTweak hash
  times the generator, and the caller reaching it holds a public key it
  has just validated — which is a `keys.parse`, and for a compressed key
  a field square root. `tweak_add` takes the 32-byte x-only form and
  parses that, so such a caller lifted one x twice:
  `secp256k1_xonly_pubkey_from_pubkey` is a conversion and not a lift,
  and reading the y it is given costs what the square root did not.
  Measured as the entry above, on an Apple M5, macOS 26.6, arm64, CPython
  3.14.6, and by the median of seven alternating rounds of 20 000 calls,
  microseconds per call: `tweak_add` 5.92, `tweak_add_` 3.79, with a
  `mult.mult_` control that moved by 0.06 across the rounds. btclib's
  `script.taproot.output_pubkey` is the caller: it validates the internal
  key through `pub_keyinfo_from_key` and then hands the x-only octets to
  `tweak_add`.
- **It takes a full public key, and that is the module's rule rather than
  an exception to it.** The bytes entry points take the 32-byte form so
  that a y coordinate is never discarded inside an argument check; a call
  taking what `keys.parse` returns and answering 32 bytes discards it in
  plain sight. An odd-y point is tweaked as its negation, BIP341's
  internal key being x-only, and answers the output key `tweak_add`
  answers for the same x — `from_pubkey_` is where that parity is read,
  and takes the same object.
- **`tests/test_parsed_keys.py` pairs it outside the parametrized
  table**, as it pairs `ssa.verify_`: the equality is
  `tweak_add_(keys.parse(sec))` against `tweak_add(from_pubkey(sec)[0])`,
  held over both serializations and over the negated key, so the
  odd-y case is not left to the reading of a docstring.
- **The underscore now means the same thing on the producing side**
  (#159). It meant "takes the parsed key in place of the bytes", which
  covers every wrapper whose *first* act is a parse and none of those
  whose *last* act is a serialization — so a caller composing two of them
  paid, between the two, for a serialization of a point that was already
  in hand and a parse of what had just been serialized. The convention
  reads the same in both directions now, the outer half being the inner
  one with a `parse` in front of it or a `serialize` behind it, and
  `keys.parse` states both. `keys.pubkey_from_prvkey_`,
  `keys.pubkey_combine_`, `keys.pubkey_sort_`, `recovery.recover_`,
  `ellswift.decode_` and `silentpayments.label_` answer with the object;
  `ellswift.encode_` and `silentpayments.labeled_spend_pubkey_` take one,
  the second taking two. Every outer half is unchanged in behaviour and
  cost, and is now written as its inner half with the missing step around
  it, so neither can drift into a second spelling of the same call.
- **Which composition pays what.** Measured as the entries above, on an
  Apple M5, macOS 26.6, arm64, CPython 3.14.6, minimum of 10 rounds of
  20 000 calls, microseconds per call. The unit is one round trip of a
  compressed key: `keys.serialize` 0.35 and `keys.parse` 2.28, against
  0.24 for the uncompressed form, the difference being the field square
  root. So: aggregating five keys the BIP67 way, `pubkey_combine(
  pubkey_sort(keys))` 28.23 against 14.84 for the two inner halves over
  keys parsed once — it is per key, which is why this one is half the
  total; a labeled Silent Payments address, 14.28 against 9.25;
  `xonly.from_pubkey(ellswift.decode(ell))` 7.44 against 4.69; and
  recovering a key to verify with it, 29.57 against 26.75, the
  verification being most of that number either way.
- **`keys.pubkey_combine_` and `keys.pubkey_sort_` were the two v0.8.0.2
  left out**, on the grounds that their inner halves would take lists of
  cffi objects and no caller had asked. The caller is their own
  composition: sorting is what BIP67 and MuSig2 key aggregation do
  *before* adding, and between the outer halves every key is serialized
  and parsed again. `pubkey_sort_` hands back the caller's own objects,
  found by the address each reordered pointer holds — an element of the
  array libsecp256k1 sorted owns nothing, and would dangle the moment the
  caller dropped the sequence it points into. `tests/test_keys.py`
  asserts that identity rather than the value, which is the part a
  serialization comparison would not catch.
- **`xonly.from_prvkey` and `ssa.Signer.pubkey` are two shortcuts rather
  than two halves.** The x-only public key of a private key was
  `xonly.from_pubkey(keys.pubkey_from_prvkey(k))` — 10.49, of which 2.63
  is a round trip of the compressed key nobody wanted — and BIP340 and
  BIP341 want that key and not the point, so the composition is the
  common case and not an exotic one: `from_prvkey` is 7.90. It buys no
  microsecond the halves had not already bought —
  `from_pubkey_(pubkey_from_prvkey_(k))` is 7.87, and `from_prvkey` is
  written as exactly that — which is the whole claim: it is a name for a
  composition whose intermediate nothing here asked for, and the number
  beside it is the round trip, not a third algorithm. `Signer.pubkey()`
  is the one that saves what no pair of halves could: a signer already
  holds the keypair, and the point with it, so reading the key off it is
  `secp256k1_keypair_xonly_pub` and not a multiplication — 0.43 against
  the 10.49 of deriving it a second time. `tests/test_signer.py` holds it
  to `xonly.from_prvkey` and to the key its own signatures verify
  against, parity included.
- **`xonly.from_keypair` is the second wrapper taking a libsecp256k1
  object rather than bytes**, `keys.serialize` having been the only one.
  A MuSig2 session driven through `lib` holds a keypair, which is the
  caller beyond `Signer.pubkey`. There is nothing to check about such an
  argument before the call, so a violated precondition is reachable
  through it: like `keys.serialize` it calls `context.check()`, which
  raises what libsecp256k1 reported *and* takes it off the thread, where
  it would otherwise surface out of the next `check` a MuSig2 caller
  makes. A wiped keypair is the reachable mistake and is reported as the
  zero it holds where the x of a point should be; `tests/
  test_callbacks.py` drives both it and the NULL pointer.
- **`silentpayments` had no inner halves at all**, and its round trip is
  a label: those 33 bytes are a compressed point, so a recipient
  publishing a labeled address paid a square root between `label` and
  `labeled_spend_pubkey`. `label_` answers with the object, `parse_label`
  and `serialize_label` are `keys.parse` and `keys.serialize` for it —
  public now, having been private — and the 33 bytes are still what a
  scan cache is keyed on, so `label` is unchanged and is still what a
  recipient keeping labels as bytes wants.
- **The tables that hold the convention were widened, not trusted.**
  `tests/test_parsed_keys.py` gains a `PRODUCERS` table whose equality is
  `outer(...) == serialize(inner(...))`, and its pairing check now reads
  `ellswift`, `recovery` and `silentpayments` as well, so a producing
  half added and left unpaired fails there; `tests/test_bytes_like.py`
  sweeps the new entry points that take bytes, through a serializing
  wrapper where what they answer is a cffi object, and excuses the rest
  by name.
- **`keys.reserialize` is the validation a caller wants, and the
  conversion nothing here offered.** `serialize(parse(key))` in one call:
  a library proving a public key at its own boundary has `parse` and
  nothing to do with what `parse` returns, and now answers octets instead
  of owning an object's lifetime; a caller holding one serialization and
  needing the other — an uncompressed key to hash compressed, a
  compressed key about to be used several times — had no call to make at
  all, `compressed` being a filter on the form everywhere else rather
  than a conversion to it.

  What makes it worth a name rather than two calls is which form it is
  asked for. `parse` is **0.256 us on 65 bytes against 2.343 on 33**:
  both coordinates are there to read, where a compressed key is a field
  square root. So the uncompressed serialization is a parsed key that
  costs nothing to open, and `reserialize(key, compressed=False)` pays
  the root once and leaves every later call at the price of reading it.
  Measured as the entries above, median of seven alternating rounds of
  20 000 calls, `mult.mult_` control within 0.04.
- **`keys.pubkey_verify` is the validation with nothing kept**, and the
  public-key twin of `prvkey_verify`, which has been there since the
  beginning. A library proving a key at its own boundary has
  `secp256k1_ec_pubkey_parse` and no use for what it produces: `parse`
  hands back an object whose lifetime becomes the caller's, and
  `reserialize` hands back the octets it was given — 0.37 us of
  serialization for an answer that was in the argument. btclib's
  `to_pub_key.pub_keyinfo_from_pub_key` is the caller, and that
  serialization is what it was paying.

  A verdict rather than an exception, as `prvkey_verify` answers one:
  what is wrong with the octets is the caller's to phrase. False for a
  length no serialization has, too, where every other entry point taking
  a key raises — a caller asking whether it holds a public key has asked
  about the length as well.

- **Every entry point taking a public key takes any of its three
  serializations**, and `xonly.parse` is where that is written: 32, 33 or
  65 octets, all of them the same BIP340 key. `02 || x`, `03 || x` and
  `04 || x || y` name one point as far as BIP340 and BIP341 are
  concerned — `lift_x` is the even-y point whatever form the x arrived
  in, and a signer whose point has odd y signs with `n - d` for exactly
  that reason — so the parity is a property of the serialization and not
  of the key. `ssa.verify` and `xonly.tweak_add` used to refuse the 33-
  and 65-byte forms, on the reasoning that a key with odd y "verifies as
  the point that is not the one passed": it is not another point, it is
  the same key, and what the refusal cost was a lift. Which form to hand
  in is now a question of cost alone — the uncompressed one is read
  rather than lifted, so `tweak_add` on it is **4.11 us against the 5.92**
  of the 32-byte form, whose parse is a field square root like the
  compressed one's.

  `xonly.from_pubkey` answers the parity for a caller that wants to know
  which form it held, and 0 for one that arrived x-only. Nothing about
  the arithmetic moves: `tests/test_parsed_keys.py` holds all four
  spellings of one key — x-only, compressed, uncompressed, negated — to
  the same answer from `from_pubkey`, `tweak_add`, `tweak_add_check` and
  `ssa.verify`.

  This is what <https://github.com/btclib-org/btclib-secp256k1/issues/161>
  builds on, with `keys.reserialize` above: a caller validates, converts
  and operates in octets, and the parsed key stops being something an API
  has to hand around.

- **`keys.pubkey_tweak_mul_sum` is the multi-scalar multiplication, with
  no product crossing the boundary.** A term per key and one sum over
  them is the shape of a verification equation, of a MuSig2 aggregate
  key and of BIP352's tweak data, and written with the public halves
  every product is serialized as 65 octets only for `pubkey_sum` to
  parse them back — the one composition above whose crossing is *per
  term*, where sorting-then-adding pays per key and the others pay once.
  Handed over whole, the products stay `secp256k1_pubkey` objects and
  the boundary is one parse per input and one serialization for the
  answer. Measured on this tree, on an Apple M5, macOS 26.6, arm64,
  CPython 3.14.6, best of seven alternating rounds, uncompressed
  throughout, with `pubkey_from_prvkey` as the noise detector (9.2 µs
  across every round):

  | terms | `tweak_mul` each, then `pubkey_sum` | `pubkey_tweak_mul_sum` |
  | --- | --- | --- |
  | 2 | 19.53 µs | 16.90 µs |
  | 3 | 27.63 µs | 23.76 µs |
  | 5 | 43.87 µs | 37.59 µs |
  | 8 | 68.46 µs | 57.90 µs |
  | 20 | 166.22 µs | 142.37 µs |
  | 64 | 536.50 µs | 459.27 µs |

  So about a seventh of the call from three terms up, a little less at
  two, and it does not shrink with the term count the way the per-term
  combine `pubkey_sum` replaced did. That flatness is what it is: the
  naive form, a term at a time and one sum, with none of the shared
  precomputation of Strauss or Pippenger.
  `secp256k1_ecmult_multi_var` exists upstream and is internal, declared
  in `src/ecmult.h` and not in `include/secp256k1.h`, so the public API
  composes to this shape and no other -- what is saved here is the
  crossing rather than the arithmetic, which matters most where the
  caller is BIP340 batch verification and the asymptotic win is the
  point of the exercise. btclib is that caller
  (<https://github.com/btclib-org/btclib/issues/917>), whose
  `curves.curve._libsecp256k1_multi_mult_` is that composition written
  out and is reached by `mult`, `double_mult_var` and `multi_mult_var`
  with one, two and many terms, by MuSig2's `key_agg`, and by BIP340
  batch verification with two terms a signature.

  **It is the second function here that is more than one libsecp256k1
  decision**, `xonly.from_prvkey` being the first, and the README's
  Design section states the rule the two answer to rather than leaving
  them as exceptions: a composition belongs here when what it saves is
  the crossing between its halves, which is the caller's cost and not
  its own choice, and it is named after the calls it makes. Nothing is
  computed here that libsecp256k1 does not: the terms are
  `secp256k1_ec_pubkey_tweak_mul` and the sum is
  `secp256k1_ec_pubkey_combine`, in the order the equation names them.

  The sum at infinity is `pubkey_sum`'s None, and is likelier here than
  there: a verification equation is written to land on it. The two
  sequences must be of one length, which is the one refusal this
  function raises itself — `zip` would otherwise stop at the shorter and
  answer the sum of whatever paired up.

### The half that speaks in objects is private, and is spelled `_foo_`

- **`foo_` is now `_foo_`, everywhere, and the API break is the point.**
  The trailing underscore said "takes the parsed object in place of the
  octets"; what it did not say is that such a call is past the boundary
  that proves anything. An object is a promise no argument check can hold
  a caller to — `ffi.NULL`, a `secp256k1_pubkey` nothing wrote to, a
  keypair already wiped are all the same to a bare pointer — so these
  belong with the leading underscore that says so. The trailing one stays
  and now says which kind of private: `_verify_` takes a parsed object
  where `_parse_der` is an ordinary helper, and
  `tests/test_parsed_keys.py` reads the modules for names spelled that
  way and fails on one no table pairs. The renamed are
  `keys._pubkey_from_prvkey_`, `_pubkey_negate_`, `_pubkey_tweak_add_`,
  `_pubkey_tweak_mul_`, `_pubkey_combine_`, `_pubkey_cmp_`,
  `_pubkey_sort_`, `xonly._from_pubkey_`, `_tweak_add_`, `dsa._verify_`,
  `ssa._verify_`, `ecdh._shared_secret_`, `recovery._recover_`,
  `ellswift._encode_`, `_decode_`, `silentpayments._label_` and
  `_labeled_spend_pubkey_`
- **`mult.mult_` is `mult.mult_bytes`**, for the same underscore and
  nothing it does: it is a public function answering octets, and it was
  the one name in the package whose trailing underscore meant something
  else — the serialized point against the pair of coordinates `mult`
  answers with. `_bytes` is what the rest of this package calls the
  octets of a thing
- **the convention is stated once, in the package docstring**, where a
  rule about every module belongs; `keys.parse` used to carry it and now
  points at it
- **every kind of object has a public `parse`/`serialize` pair now**, so
  the private halves have something to take and something to hand back:
  `dsa.parse_der`, `dsa.parse_compact`, `dsa.serialize_der`,
  `dsa.serialize_compact`, `recovery.parse_compact`,
  `recovery.serialize_compact` and `xonly.serialize` join `keys.parse`,
  `keys.serialize`, `xonly.parse`, `silentpayments.parse_label` and
  `silentpayments.serialize_label`. `dsa.to_der` and `dsa.to_compact` are
  now the compositions they always were, and `xonly.parse`'s "there is no
  `serialize` beside it, and that is not an omission" is gone with the
  omission it excused — `silentpayments` had copied that serialization
  rather than call it
- **and every wrapper with a parse or a serialize to save has a private
  half**, which is what "symmetric" means here: `dsa._sign_`,
  `_normalize_`, `_is_low_s_`, `recovery._sign_`, `_to_der_`,
  `silentpayments._create_outputs_`, `_prevouts_summary_` and
  `_scan_outputs_` are new. The Silent Payments three are the ones that
  pay: a wallet scanning block after block parses its own spend key once
  rather than once per transaction, and `_prevouts_summary_` hands
  `_scan_outputs_` the summary object where the public halves write those
  octets out of one struct and back into another. `dsa._verify_` takes
  the parsed signature too, so asking `_is_low_s_` and then verifying is
  one parse rather than two
- **`keys.PubkeyTweakChain` hands out the point it holds**, `pubkey()` in
  octets and `_pubkey_()` as the object: a caller reaching the end of a
  BIP32 path had no way to ask the chain what it had arrived at except by
  the last `tweak_add`, and none at all to hand the point on

### What answers for an argument that cannot be checked

- **`context.guarded` is that answer, and it is now every such call's.**
  Three docstrings and a test claimed a violated precondition was
  reachable through "two" wrappers, `keys.serialize` and
  `xonly.from_keypair`. It was reachable through every private half, and
  what came back was measured rather than reasoned about: through
  `keys._pubkey_negate_` a bare `RuntimeError` with libsecp256k1's reason
  left on the thread, through `dsa._verify_` a plain `False`, through
  `keys._pubkey_cmp_` a `0` that reads as "equal", and through
  `ecdh._shared_secret_` a success and 32 bytes that are a shared secret
  with nobody. The message left behind is the misattribution the
  `check()` in `keys.serialize` already existed to prevent: the next
  `check()` — a MuSig2 caller's, about a call of their own — inherited it
- **so the guard clears the thread before the call and checks after it,
  whatever the call answered.** Both halves are needed and either alone
  is a bug: without the clearing an older message is raised out of this
  call, without the check a refusal that shows in no return value is
  believed. It is a context manager because the pair has to be
  inseparable, which is the argument `_secret.take` makes for its own
  pair. The eight failures above are eight `ValueError`s now, each
  carrying libsecp256k1's own text, and `tests/test_callbacks.py` no
  longer counts the exceptions to a rule that has none
- **and it costs 0.22 microseconds a call**, which is worth writing
  down because on the cheapest call it is most of the call. Apple M5,
  macOS 26.6, arm64, CPython 3.14.6, minimum of 11 rounds:
  `secp256k1_ec_pubkey_cmp` through `lib` is 0.084 microseconds and
  `keys._pubkey_cmp_` is 0.300, the difference being the guard and
  nothing else. Three spellings were measured. The pair written out at
  each call site is the cheapest, and is not taken: the clearing without
  the check leaves a message for the next caller to be blamed for, the
  check without the clearing raises an earlier call's message out of
  this one, and the two belong in one place. A
  `contextlib.contextmanager` generator is the dearest, putting the same
  comparison at 0.567 — so the generator's guard is 0.48 a call, and the
  0.27 between the two spellings is more than the entire C call on the
  smallest guarded call in the package. The guard is therefore the
  class, `__slots__` and `__enter__` and `__exit__`, which says "the
  clearing and the check are one thing" as well as a `yield` does and
  costs three method bodies of one line each to say
- **and a fifth of `keys.pubkey_sort` is what settles it** (#186). A
  guard is built once per guarded call, so a composed call builds many,
  and a caller wanting those microseconds back through `lib` is
  reimplementing the operation rather than making one call — where on a
  comparison the advice to drop to `lib` costs them nothing, which is
  why the cheap call is the wrong one to decide on. Same machine and
  method: `keys.serialize` of a parsed point is 0.582 against a
  generator's 0.847, and `keys.pubkey_sort` of twenty keys 21.12 against
  26.99. Sharing one instance rather than building one per call measures
  0.567 against 0.582, which is noise, and would have cost every
  `with guarded():` in the package a rewrite to `with guarded:`
- **the `__exit__` is deliberately not a `finally`,** which is the one
  thing the spelling could get wrong. The block holds the guarded call
  and nothing else, so an exception out of it is some other failure, and
  checking anyway would raise the violated precondition over it —
  reporting the wrong failure and losing the right one. `if exc_type is
  None` is what says so, and two tests in `tests/test_callbacks.py` hold
  the pair, each verified against the mutant it exists to kill

### The copy a caller can take back

- **every producer of a secret takes `into`** (#188), a keyword-only
  writable buffer the secret is written to instead of a `bytes`:
  `keys.prvkey_negate`, `prvkey_tweak_add` and `prvkey_tweak_mul`,
  `xonly.prvkey_tweak_add`, `ecdh.shared_secret` and its private half,
  `ellswift.xdh`, `dsa.nonce_rfc6979` and `ssa.nonce_bip340`. Omitted,
  nothing changes and the `bytes` comes back as before. Given, nothing
  is returned, and the copy the caller ends up holding is one they can
  overwrite — which is the entire claim, and SECURITY.md now states it
  beside the limitation it narrows rather than instead of it. It does
  not wipe the buffer for them; a buffer never overwritten is exactly
  the copy `into` was reached for to avoid, and the obligation is
  stated rather than enforced for the reason `ssa.Signer` has no
  finalizer
- **which is not what #87 declined.** That issue asked whether an opaque
  secret *handle* buys assurance and answered no: a handle is a lifetime
  someone has to own and invalidate, the same shape of requirement that
  keeps MuSig2 out, and its entry side still starts from a `bytes` the
  caller already made. Both halves of that stand. What is new is neither
  a lifetime nor an entry: one keyword argument, one call, no object,
  and it addresses the *exit* — where `_secret.take` had nowhere to put
  the secret except an immutable object nothing can zero
- **`into` is keyword-only, and that is not a style choice.** Passed
  positionally to `dsa.nonce_rfc6979` it would land on `aux_rand32`,
  which takes 32 octets and would have accepted the empty buffer as
  entropy — a wrong nonce, silently, from a call that reads right. The
  suite caught it on the way in; keyword-only is what keeps a caller
  from meeting it
- **and the buffer is proved before anything is copied, the wipe
  happening either way.** A wrong length is refused rather than filled:
  too short raises on the assignment anyway, but too *long* would take
  the secret in its first octets and leave whatever was behind it, which
  reads as a secret with a tail. A read-only view cannot be wiped, so
  accepting one would defeat the facility silently. And a view of more
  than one dimension passes every one of those checks and then fails the
  copy with `NotImplementedError`, while a strided one succeeds and
  leaves the secret scattered through an owner twice its size, so both
  are refused as not contiguous octets. Beyond that the buffer protocol
  decides rather than a type: `mmap` and `array.array("B")` are taken,
  an `mlock`ed `mmap` being a plausible destination for exactly this
  caller, and `memoryview` itself is what refuses a non-buffer. That
  breadth is the run time's rather than the annotation's, which stays
  the two named types until `collections.abc.Buffer` is reachable at a
  3.12 floor: a caller under `mypy --strict` passes the rest as
  `memoryview(x)`, and SECURITY.md says so where the mismatch is met.
  `_secret.into_buffer` is annotated `object` and not
  `MutableBytesLike`, that being the annotation it exists to not trust
- **the wipe is in a `finally`, which is the defect this facility could
  have shipped with.** `take` had no failure mode before `into`, and
  with one on the straight line a refused buffer returned through the
  entry point leaving a live private key in cffi memory that is freed
  without being overwritten -- none of the eight has a `finally` of its
  own, and `xonly.prvkey_tweak_add`'s wipes the keypair rather than the
  key. Nothing is lost by wiping on the way out: the value never reached
  the caller, and the call they retry recomputes it
- **the two secrets `silentpayments` answers are left out**, each being
  one member of a returned tuple where an argument could not say which:
  the tweak of `label`, and the per-output tweak `scan_outputs` hands
  back. SECURITY.md names both rather than claiming every entry point
- **and what holds the set is a walk rather than a list.** A hardcoded
  tuple of eight cannot notice a ninth, which is the whole point of the
  test; `tests/test_secret.py` walks the package for the callers of
  `_secret.take`, and then for whatever calls one of those, and requires
  `into` of each. The second pass is what makes the first honest: a
  public half answers the secret its private half read out without
  calling `take` itself, so `ecdh.shared_secret` is asked by its own
  name rather than caught by accident, and a ninth written that way is
  not left to be checked by hand. The two halves of
  `silentpayments.label` are exempt and named. What the walk reads are
  the calls of a syntax tree and not the text of the source, a mention
  not being a call: `keys.pubkey_tweak_add`'s docstring writes
  `prvkey_tweak_add(k, t)` to say what the private-key side does with
  the same tweak, and matched as text it answers that a public-key call
  produces a private key. The limit that is left is written down beside
  it: a secret that never goes through `take` is invisible to this, which
  is exactly how `_found_output` escaped the first draft of that sentence
- **the cost, which is in the type system rather than at run time.**
  Three `@overload`s per entry point, so that omitting `into` still
  types as `bytes` and a downstream `mypy --strict` sees no change; the
  implementation signature is the union. The third is the one a caller
  needs to *forward* an optional buffer through a wrapper of their own,
  which is how btclib would surface this argument, and with only two it
  is that caller who writes the two-branch version or a `cast`. Four
  negative-typing tests moved from `type: ignore[arg-type]` to
  `[call-overload]`, which is
  what an overloaded call reports, and is the one way this is visible
  to a caller who was already type-checking

### The test a stateful object has to pass

- **the rule the outpost section applies is now stated there** (#191),
  rather than only in <https://github.com/btclib-org/btclib-secp256k1/issues/161>
  where it was reached. That section explained the two objects that
  exist and separated them correctly — a keypair is arithmetic, a parsed
  point is a parse — but the reader who needs it is the one proposing a
  *third*, and what they needed was the test, not the two instances of
  it. It is written as one sentence: what an object saves is the cost of
  rebuilding, from octets, whatever it holds
- **and the saving is that cost by construction, not by measurement,**
  which is the stronger form of the same claim and the one the section
  now makes. `ssa.sign` builds the keypair, signs with it and wipes it;
  `signer.sign` is that middle term with the first already paid, so the
  difference between them is `secp256k1_keypair_create` on any machine,
  and the numbers only add that nothing else of consequence sits in it.
  They are the section's own — 15.82 against the signer's 8.27, of which
  the keypair is 7.55, and 15.82 − 8.27 is that 7.55 — rather than a set
  of its own. The chain gets the same treatment: what it saves is the
  parse it holds, and which parse that is depends on the serialization
  its caller carries — the pair the section states four paragraphs
  above, pointed at rather than restated. That is the sharper form of
  the distinction, because it says why this saving is the one a caller
  can make cheap and the keypair's is not
- **and which figures survive a different machine is said**, because a
  section arguing from microseconds should say which of them it is
  arguing from: the identity, and it carries because it is structural,
  not because a ratio travels better than an absolute. The counts are
  one laptop's
- **two objections are answered before they are raised.** What recovers
  a parse is `keys.parse`, not a cheaper serialization: the
  uncompressed-form argument reaches neither an x-only key, which has no
  second serialization, nor a walk starting from the 33 octets an xpub
  carries, where reaching the uncompressed form costs a `reserialize`
  the chain does not pay — which is the finding of
  <https://github.com/btclib-org/btclib-secp256k1/pull/185>, now in the
  same section and pointed at from here. And statelessness is the other
  side of the ledger, the same argument that keeps MuSig2 out, so the
  two paragraphs point at each other. Ergonomics is weighed by neither,
  deliberately: the line a caller does not write belongs in btclib with
  the lifetimes

### One statement of each thing

- **the duplications are gone**, each of them two spellings of one
  call that could drift apart. `_secret.keypair` is the
  `secp256k1_keypair_create` that `ssa`, `xonly` and `silentpayments`
  each carried verbatim, and it lives beside the `wipe` its caller owes
  it. `xonly.serialize` is the x-only serialization `silentpayments` had
  copied. `keys.parse` and `xonly.parse` take the name the exception
  should use, which is what `silentpayments._pubkey` and `_xonly_pubkey`
  existed for. `dsa.serialize_der` is the DER writer `recovery.to_der`
  had inlined, comment pointing at the original included.
  `_scalar.entropy` and `_scalar.optional_entropy` are the "32 bytes or
  none" of `ssa`, `ellswift.create`, `ellswift.encode`, `dsa.sign` and
  `recovery.sign`. `_scalar.in_range` is the small-int check of a
  recovery id, a parity, an ElligatorSwift party and a label index — and
  it refuses a `float`, which `recid not in (0, 1, 2, 3)` accepted as
  `0.0`. `_cdata.array` is the borrowed-pointer array `keys` built inline
  and `silentpayments` had a helper for
- **`keys.pubkey_verify` and `keys.parse` are one parse now** (#164,
  landed while this was open). Both are `secp256k1_ec_pubkey_parse` and
  they differ in what they do with it: `parse` keeps the object and
  raises when there is none, `pubkey_verify` keeps nothing and answers
  the verdict. `_parsed` is that call, answering the key or None, and the
  two are a line of policy each. It costs `parse` a python call, measured
  on an Apple M5, macOS 26.6, arm64, CPython 3.14.6, minimum of 7 rounds
  of 300 000 calls: 0.269 microseconds against 0.256 on the uncompressed
  serialization, 2.326 against 2.310 on the compressed one, where the
  field square root is what is being paid for. The docstrings quoting
  those two numbers are re-measured with it. The other spelling was
  measured too — `pubkey_verify` catching `parse`'s own `ValueError`
  leaves `parse` untouched and costs 0.15 on a refusal — and it was not
  taken: an exception is what this package answers a caller with, not
  how it decides something it already knows
- **the entropy argument is `aux_rand32` in all five**, BIP340's name for
  what libsecp256k1 spells `ndata` in one place and `rnd32` in another.
  What omitting it means still differs, and the difference is what the
  two helpers are named for
- **the octets of a thing end in `_bytes`**: `hashes.tagged_sha256` takes
  `tag_bytes` and `msg_bytes`, and `silentpayments` takes
  `recipients_bytes`, `taproot_pubkeys_bytes`, `pubkeys_bytes` and
  `tx_outputs_bytes` where its private halves take the parsed objects
  under the same names without the suffix
- **`ffi.unpack` is not `bytes(ffi.buffer(...))`, and the vectors said
  so**: unifying the two idioms turned the `unsigned char[32]` tweak of a
  found Silent Payments output into a list of 32 ints, which
  `tests/test_vectors.py` caught in every BIP352 receiving case. The
  reason it is the exception is now written where it is made
- **the messages of a refusal are one shape**: "invalid private key: not
  in [1, n-1]" wherever that is the whole of what was wrong, and "the
  {name} must be in [0, {upper}]" for the four small numbers

### The signature's two serializations

- **`dsa.sign` and `dsa.verify` take a `compact` flag**, false by
  default. A signature is `r` and `s`; DER is what the wire carries, and
  a caller holding the two scalars had to write an ASN.1 structure around
  them for a call whose first act is to take it apart again — and read
  one back the same way on the answer. `parse_compact` and
  `serialize_compact` have been public since the halves were separated,
  but they speak in the parsed signature, which is exactly what a caller
  doing one thing with it does not want to hold.

  btclib is the caller, and pays it at both ends
  (<https://github.com/btclib-org/btclib/issues/922>): building the DER
  is 0.712 us against the 0.077 of `r.to_bytes() + s.to_bytes()`, and
  reading it back 1.250 against 0.320 — the second of those *per grind
  attempt* under low-r grinding, where the loop parses what it may
  discard. Its recoverable path never had the problem:
  `recovery.sign` answers the compact form, and the comment there says
  why.

- **Which form it is has to be said, and cannot be read off the length.**
  A DER signature of 64 octets exists — `r` and `s` of 29 bytes each —
  and it begins with the 0x30 a compact `r` may begin with too. So the
  flag, rather than a dispatch; and each form is refused as the other,
  which `tests/test_core.py` asserts along with the round trip through
  `to_der` and `to_compact` and the `normalize` flag on either form.

### What a caller asks that is not a use

- **`keys.pubkey_sum` answers the point at infinity, where
  `pubkey_combine` refuses it.** They are one C call and differ in what
  they make of its 0: a sum that is the identity is no public key, which
  is an argument error to a caller that wanted a key and a *value* to one
  doing arithmetic — `P + (-P)` is a point of the group whatever
  libsecp256k1 can hold. What tells that 0 from the other one, an object
  the library could not read, is that the second is reported through the
  illegal callback: `context.guarded` raises it, so what reaches the
  return is infinity and nothing else. btclib is the caller
  (<https://github.com/btclib-org/btclib/issues/917>): its
  `_libsecp256k1_multi_mult_` recognizes an intermediate sum at infinity
  by comparing coordinates, and combines per term rather than once at the
  end so that there are coordinates to compare — measured here on eight
  terms, 64.84 microseconds against the 42.71 of a single combine, and
  the 33.59 of a sum whose terms never cross the boundary at all
- **`xonly.pubkey_verify` and `xonly.to_pubkey` are the two x-only twins
  a caller had to write `0x02 || x` for.** The first is
  `keys.pubkey_verify` for an x coordinate; the second is the lift, and
  the lift is that concatenation — libsecp256k1 converts a point to an
  x-only key and has no call back the other way, so the octets have to be
  built somewhere and this is where the rule about them lives. A key that
  arrives with odd y is negated in the field rather than serialized and
  lifted again, which is the difference between reading a y and finding
  one. btclib's `curves.curve._compressed_sec` exists for exactly these
  two questions
- **`dsa.signature_verify` is the verdict a signature had no way to
  answer**, where a key has had `pubkey_verify` since v0.8.0.3's own
  entry above: the same parse, with nothing kept and no exception to
  catch, and the `compact` flag beside it because the serialization
  cannot be read off the octets. The length is part of the verdict, as it
  is for a key: 63 octets are no compact signature, and `False` is what a
  caller asking whether it holds one wants. `parse_compact` says "invalid
  compact signature" for a wrong length now, where it used to say "the
  compact signature must be 64 bytes" — one refusal for one question,
  which is what a key's parse already did
- **all three are one parse with two callers**, `keys._parsed`'s shape
  repeated in `xonly` and `dsa`: the helper answers the object or None,
  the `parse` raises and the verdict compares. What it costs is the
  python call that entry measured, and what it buys is that a check
  cannot move in one spelling and not the other
- **and the conversion between two serializations keeps two names for a
  signature and one for a key.** `dsa.reserialize` was considered and not
  written: `keys.reserialize` reads the input form off the length, and a
  signature's cannot be read at all — a DER signature of 64 octets exists
  and may begin with the `0x30` of a compact `r`. `to_der` and
  `to_compact` name the input form the way `compact` names it on `sign`
  and `verify`, which is the coherence a third name would have broken

### The nonce each signer derives

- **`dsa.nonce_rfc6979` and `ssa.nonce_bip340` are new** (#155).
  libsecp256k1 exports its two nonce functions as callable pointers --
  `secp256k1_nonce_function_rfc6979` and
  `secp256k1_nonce_function_bip340` -- and both headers were already in
  the parse list, so what was missing was the call through the pointer
  and nothing else. No callback into python, which is what makes this
  unlike the ECDH hash function `ecdh.shared_secret` declines to expose
- **each is called with what its signer passes**, so what comes back is
  the nonce of the signature the same arguments make, rather than a
  derivation that resembles it. That is checked rather than asserted:
  `tests/test_nonces.py` signs and re-derives, `r` being the x of `k`
  times the generator reduced modulo the group order and BIP340's `R`
  the same x without the reduction. The four points #155 lists are
  settled that way -- the algorithm tag is fixed to the signer's (NULL
  for ECDSA, `BIP0340/nonce` for BIP340), `attempt` is an argument
  because RFC6979's contract has a counter even though every signature
  takes the first candidate, `ndata` is the `aux_rand32` every other
  entry point calls it, and the answer leaves through `_secret.take`
- **BIP340's key enters negated where the point has odd y**, and the
  x-only public key with it, because that is the key the signature is
  made with: a wrapper taking the caller's key unchanged would answer a
  nonce no signature was built on, which the odd-y parametrization of the
  test would have caught. Both are derived here rather than asked of the
  caller for the same reason
- **and no auxiliary randomness is the aux of 32 zero octets**, which is
  what libsecp256k1 substitutes and what a python implementation has to
  choose between, BIP340 leaving the aux optional. Asserted, because it
  is the kind of fact a reader would otherwise have to read the C for
- **what they are not is a way to sign in python.** A nonce read out of
  libsecp256k1 has left constant-time code, and the docstrings say so
  where a caller meets them: they are an oracle for checking a
  derivation, which is the gap btclib's `ecc/rfc6979_nonce.py` and
  `ecc/bip340_nonce.py` have had
- **and SECURITY.md gains the limit that has an equation.** Its list of
  what libsecp256k1 writes into a cffi buffer now names the nonce, and
  beside it the thing the other members do not have: a nonce published
  beside the signature it made *is* the private key,
  `d = (s·k - h)/r mod n`. The docstrings warn against signing with one;
  what they could not say, the enumeration being elsewhere, is that it
  must not be stored or logged beside a signature either
- **the identity the oracle rests on is asserted, not assumed**:
  `dsa.sign` passes NULL where the nonce function goes, which selects
  `secp256k1_nonce_function_default`, and this wrapper calls
  `secp256k1_nonce_function_rfc6979`. libsecp256k1's header says they are
  "currently the same pointer", and `tests/test_nonces.py` says so too —
  without it, a split upstream would fail the signature comparisons while
  reporting only that a nonce does not match its signature
- **and the published vectors are what the RFC6979 entry point answers
  to.** `tests/test_vectors.py` already carries the RFC6979 cases with
  their `k`, and now asserts that `nonce_rfc6979` reproduces it: the
  signature comparison holds the wrapper to this package's own signer,
  and this holds it to the value RFC6979 publishes

### The surface and the sentence agree

- **the `mult` module is folded into `keys`** (#173). With `mult.mult`
  removed below, what was left was one function that is
  `keys.pubkey_from_prvkey(num, compressed=False)` with the flag fixed
  and the name hiding it — and a module, everywhere else under
  `btclib_secp256k1/`, is a family of calls around one part of
  libsecp256k1. The abstraction did not hold at its own edges either:
  `mult_bytes(0)` raised "invalid private key", the message of the module
  it delegated to, and a caller wanting the compressed answer had to
  leave for `keys` anyway. What it bought was a name for the operation, a
  scalar times the generator rather than the public key of a private key,
  and that name is one line at a call site that already reads the other
  module's refusal. `keys.pubkey_from_prvkey(num, compressed=False)` is
  the spelling everywhere now, in the package's own docstrings and tests
  included. Done in the window #173 names: 0.8.0.3 is unreleased and
  btclib is adapting to the removal below, so the two are one break to a
  released caller
- **`mult.mult` is gone** (#170). The package docstring opens with "every
  entry point takes octets and answers octets", and that call answered
  `tuple[int, int]` — the one place a point of the curve left as numbers
  rather than as a serialization, `pubkey_cmp`'s int and `prvkey_verify`'s
  bool being verdicts and `from_pubkey`'s parity a flag beside the octets
  it comes with. What it did is `int.from_bytes` twice over the two
  halves of `mult_bytes`, and they cost 0.138 microseconds of a call that
  is some 8.5 — 1.6% of it, and the whole of what the exception was
  worth. The first spelling of this entry claimed the conversions were
  *cheaper* inside the function, 8.549 against 8.578, which is noise read
  as a direction: the removed function did those same two conversions
  behind a python frame, so the ordering the code implies is the other
  one, and three alternating rounds put the two within each other's
  spread. What is stable is the 0.138. The module docstring carries the
  two lines a caller writes instead
- **and `xonly.from_keypair` stays, with the rule widened to cover it**
  (#169). It takes a libsecp256k1 object and is not half of a
  parse/serialize pair, which the docstring's "an object crosses only
  where a caller already holds one" did not account for. The reason it is
  not an exception is that a keypair *has* no serialization to make a
  bridge out of: `secp256k1_keypair` holds a private key in
  libsecp256k1's own layout and the C API never writes one out, so a
  caller that built one through `lib` — a MuSig2 signer — holds something
  no octets could have carried here. The rule now names the two kinds,
  the parse and the keypair, and `from_keypair`'s own docstring points at
  it rather than restating it. Making it private instead would have
  broken the MuSig2 path the README documents, `ssa.Signer.pubkey` being
  the same call only for a keypair this package built.

  The fact #169 says the choice depends on — whether anyone outside this
  package drives MuSig2 through `lib` today — was not established, and
  keeping is the conservative half of that uncertainty: it costs a
  sentence in the rule, where making it private costs a caller who may
  exist an entry point that cannot be worked around, a keypair having no
  serialization to reach `keys.parse` with. What would settle it is a
  downstream search rather than an argument, and it is not on this branch
- **the two are one question**, asked in #169 and #170 of the same
  sentence: an exception to "octets in, octets out" is worth keeping when
  octets cannot carry the thing, and worth removing when they can. A
  keypair cannot be serialized; a point can

### Documentation

- **`ssa.Signer` and `keys.PubkeyTweakChain` are presented as what they
  are**, and the chain's saving is now stated against the walk it is
  actually worth measuring against. The section said five steps are 64.62
  microseconds through `pubkey_tweak_add` and 55.14 through a chain,
  which is true and is the compressed walk; the same path walked in the
  *uncompressed* form, compressed in python where BIP32 wants 33 octets
  to hash, is 54.75 — the chain within the noise. So what the chain saves
  is real against one spelling and a rounding error against the other,
  and what it is unambiguously worth is the line a caller does not write.
  The README says both numbers now, and the section opens by separating
  the two objects: a keypair is arithmetic no serialization gives back, a
  parsed key is a parse the caller can make cheap by choosing the form it
  carries. That is <https://github.com/btclib-org/btclib-secp256k1/issues/161>'s
  own principle, and it is what the measurement says of the two
- **and what the three numbers leave unasked is where the walk starts**
  (#161). The two moves the section describes — hold the point, carry the
  uncompressed form — look as though they compose into a fourth and
  faster spelling, `chain.tweak_add(compressed=False)`, and they do not.
  A chain re-parses nothing in either serialization, the point being what
  it holds, so asking it for 65 octets saves no parse and pays a
  serialization and the caller's own compression line at every step.
  Measured on an Apple M5, macOS 26.6, arm64, CPython 3.14.6, five steps,
  medians of nine alternating rounds with a sha256 control and absolutes
  about 5% above this section's: the composition is 59.27 against the
  chain's 58.62 and the uncompressed walk's 58.26 — a loss of 1.01 where
  the section's own numbers predict 0.98, one compressed parse in against
  five uncompressed parses out.

  The comparison that does decide something is the one nothing here
  asked: the uncompressed walk's 54.75 begins from 65 octets a BIP32
  caller does not have. An xpub carries the 33, so reaching that form
  costs `keys.reserialize` once — a compressed parse and a serialization,
  more than the 0.39 that separated the two walks — and counted, the same
  run puts the walk at 61.55 against the chain's 58.62. So the chain is
  ahead of the spelling this section had called it a rounding error
  behind, on the key its caller actually holds. The README says both now:
  the composition is not worth reaching for, and the parse the chain pays
  at construction is the one the caller could not have avoided. What the
  issue left open is unchanged and rests on that rather than on the cost
  of breaking a released caller — the chain shipped in v0.8.0.1 and
  `btclib`'s `bip32.py` adopted it
- **the outpost section is what the README had no name for**: an outpost
  past the boundary. The private halves hand an object from one call to
  the next; these two hold one across many, for the caller that crosses
  again and again with the same key — a signer signing message after
  message, a wallet walking a BIP32 path one index at a time. Each
  crossing used to pay the conversion at its far end, a point
  multiplication for the keypair and a field square root for the
  compressed key, on a key it had already converted.

  The chain was in no section at all before this, so it now has one, with
  the walk it is for: five steps through `pubkey_tweak_add` against five
  through a chain, which is a compressed parse saved four times. The pair
  of timings first written here was superseded by the entry above, which
  re-measured the walk and added the third spelling of it, so the numbers
  live there and not in two places. The signer's own numbers move from
  the section that described the trade to the one that describes the
  saving: 15.82 against 8.27, of which the keypair is 7.55
- **and the two answer differently under threads, which nothing said.**
  `ssa.Signer` is safe to share, libsecp256k1 taking a keypair const, and
  the README and `tests/test_concurrency.py` both said so — while also
  saying a signer was "the one thing here holding a buffer across calls",
  which `PubkeyTweakChain` had made untrue. A chain is the exception and
  is one by construction: `secp256k1_ec_pubkey_tweak_add` takes its key
  as in and out, so every `tweak_add` writes the point the chain holds,
  and two threads sharing one are two writers of a point rather than two
  walkers of a path. One chain belongs to one thread, and
  `test_a_chain_per_thread_walks_the_same_path` is that usage held to the
  answer of a chain alone
- **why there is no `dsa.Signer` is now the reason rather than the
  mechanism.** The README said `secp256k1_ecdsa_sign` takes the private
  key itself, which is true and is the shape of the C function, not the
  argument. The argument is the equation: BIP340 challenges with
  `e = H(R || P || m)`, so the public key is an input to every signature
  and has to be derived — a point multiplication, kept in the keypair
  with the parity that decides between `d` and `n - d`. ECDSA signs
  `s = k^-1(z + r*d)`, in which `P` does not appear, so there is no
  object derived from the key to hold across calls.

  Measured, because the question is "what would it save": on an Apple M5,
  macOS 26.6, arm64, CPython 3.14.6, minimum of 7 rounds of 20 000 calls,
  microseconds per call, `dsa.sign` is 12.93 and the C call inside it is
  11.43. Of the 1.51 that leaves, `serialize_der` is 0.757, `octets` of
  the message hash 0.081 and the `ffi.new` of the signature 0.078 — all
  of them per signature — and `scalar` of the private key is 0.117, which
  is the whole of what is per key and so the whole of what a signer could
  hoist. `ssa.Signer` hoists 7.55 of 15.82 for comparison, and what
  either costs is the same: a second copy of the secret, alive as long as
  the signer. Worth it for half a signature, not for a hundredth of one.

  The README also now says what *does* cost in `dsa.sign`, and that it is
  the entry above rather than a signer that spares it: the DER
  serialization is 0.757 of those microseconds, and `compact=True`
  answers the 64 octets without writing it
- **Four files said a button is how a pull request lands; none of them
  is** (#176). A pull request reaches `main` as a fast-forward push from
  the command line, squashed locally first where it carries more than one
  commit, which is what keeps the commit signed by the maintainer rather
  than by GitHub's web-flow key — and, where the head that lands is the
  one the gates last ran on, keeps that sha, so a branch stacked on it
  goes on applying instead of needing a rebase and a fresh run of the
  matrix per level. `REPOSITORY.md`'s *Merge methods* said "squash is the only
  method enabled", true of the setting and read as a description of the
  landing; `CONTRIBUTING.md` said "a pull request is squashed on merge …
  the only merge button this repository enables"; `RELEASING.md` merged
  the release "with the squash button"; and `CLAUDE.md` said all three
  buttons were enabled, which stopped being true when squash became the
  only one. The twin change for btclib is
  <https://github.com/btclib-org/btclib/pull/944>, whose merge rule
  differs in the multi-commit case: the squash is made locally here
  rather than pressed.
- **and the ruleset that lets that push through had no section at all.**
  REPOSITORY.md documented the classic branch protection and never the
  two rulesets beside it, so the bypass the fast-forward needs was
  reachable from the prose only through one clause of CONTRIBUTING.md.
  It now has one: `main-integrity` carries the four rules with no bypass
  actor, `main-self-merge` carries the pull request rule and names the
  maintainer, and the split is what lets the review be bypassed — GitHub
  refusing a self-approval — while a signature stays required of
  everybody — though not the whole of the permission either, a push to
  `main` needing `enforce_admins` to stay `false` and the pusher to hold
  `admin` before the bypass is reached at all.

  The sequence is there with it, and so is what GitHub does afterwards,
  which is two different things and was written as one. A pull request is
  marked merged when its head becomes reachable from the base branch, so
  what decides is whether the commit pushed to `main` is the sha the pull
  request names at that moment — not whether a rebase happened, a rebase
  force-pushed to the branch leaving it naming the new one. Push the
  squash to the branch before landing it and the squashed branch is the
  reconciled case too, with the matrix running on the object that lands:
  #185 did that and was marked **Merged**, its head branch deleted by
  `delete_branch_on_merge` a second later. Land the squash straight from
  a worktree and nothing is reconciled and nothing is deleted — btclib's
  #953 is **Closed** with `mergedAt: null`, its issue closed by the
  keyword in the *commit message*, which is the reason for putting it
  there. Getting ahead of the reconciliation costs the same thing btclib
  paid on #930: branch deleted first, pull request Closed with its commit
  on `main` all the same. Two counts were stale besides, both saying four
  required checks where the rule has named three since `codeql` left it
- **and CONTRIBUTING.md was the file that pass did not reach** (#200). It
  said "the one force-push that stays right", and there are two: the
  rebase a contributor makes when their base has moved, and the squash
  the maintainer pushes to their branch at the end — which is the one
  they will actually see, arriving on work they thought was finished. It
  is now named there as the second, and the paragraph on the maintainer's
  path carries the step it was missing: the squash reaches the branch
  before it reaches `main`, which is what leaves the pull request naming
  the commit that lands, so GitHub marks it Merged and the `Closes #N` in
  the description fires. A contributor reading only this file would have
  expected the other outcome, and the two pull requests that landed the
  rule went the way it now describes
- **The worktree recipe checks the submodule out** (#223). CLAUDE.md tells
  every session to work in a worktree and gives the commands that get one,
  and what they set up could not build: a worktree isolates files, a
  submodule is a checkout of its own, and `git submodule status` in a
  fresh one answers a leading `-`. What `uv sync --locked` then says is
  forty lines of CMake and traceback naming the empty `secp256k1/`, closing
  on "Build failures usually indicate a problem with the package or the
  build environment" — the two things that are not wrong — and mentioning
  the submodule nowhere, so a reader who does not already know goes and
  audits their toolchain. `git submodule update --init secp256k1` before
  the sync is the whole of the fix, verified in a fresh worktree rather
  than reasoned about: with it the sync exits 0 and the suite passes in
  that worktree's own venv, without it the sync exits 1. Nothing here was
  unknown — CONTRIBUTING.md documents the submodule for a clone and again
  for the documentation build — but the recipe a session actually follows
  is the one in CLAUDE.md, it reads as complete, and it was the one place
  the line was missing. CI never meets it, every checkout there passing
  `submodules: true`

- **The concurrency ceiling is written down, with the column that
  decides it** (#194). REPOSITORY.md's plan-gated section now carries the
  number that has moved these workflows twice, and it is an attribute of
  the organization rather than a setting of the repository: an
  organization on GitHub Free runs twenty jobs at once, **of which five
  may be macOS**. Paying for Team triples the first and leaves the second
  exactly where it is; only Enterprise moves it. So the macOS column that
  queued for tens of minutes was thirty-five jobs asking for five slots,
  and the split that took those cells out of the merge gate is not a
  workaround for a plan but the answer on any plan below Enterprise —
  which is worth having written down before someone reads the first
  column alone and buys a seat expecting it back
- **The sentinel table names `windows` too** (#184). `windows.yml` became
  a workflow of its own two changes after `macos.yml` did, and the table
  in CLAUDE.md kept listing the sentinels without it — so the paragraph
  under the table still called `macos` "the one sentinel a pull request
  would otherwise have waited for" when there are two, each split by a
  measurement of a different kind: a queue for the first, an
  organization's ceiling of concurrent jobs for the second. The
  measurements stay where they were made, in `test.yml`'s header and
  `windows.yml`'s. Two smaller readings of the same omission go with it:
  the static-then-dynamic pair of steps CONTRIBUTING.md attributes to
  `macos.yml`'s cells is `windows.yml`'s too, and `test.yml`'s aggregate
  job explains its name by there being a second workflow over this matrix
  shape, which is now a third
- **cosmic-ray's own defence against a stale `.pyc` is named rather than
  asserted** (#229). CLAUDE.md said "cosmic-ray does not have the
  problem" after two paragraphs on how a hand-applied mutation loses
  one, and did not say why — which is what let the sentence be read as
  an assumption. It is `cosmic_ray/testing.py`, which sets
  `PYTHONDONTWRITEBYTECODE` in the environment of the test command under
  a comment giving this very reason, so no `.pyc` is written during a
  session; measured by looking at `btclib_secp256k1/__pycache__` before
  and after a real `cosmic-ray exec` over `hashes.py`, one file before
  and the same one after, and the baseline step writes none either. Two
  things go in the same clause because each is what the next reader
  would otherwise re-derive: grepping the package for
  `dont_write_bytecode` finds nothing and proves nothing, the string
  being the environment variable's own spelling; and no flag stops a
  *read*, so a `.pyc` from an earlier `pytest` is still used where its
  size and truncated mtime match — the same window as the hand case,
  which is why that recipe wants the control run and not only the
  variable.
- **Both secrets baselines are `--slim`, so a line that moves stops
  rewriting them** (#230). The files carried `line_number` and
  `generated_at`, and over #221 that meant a rewrite on all four pushes
  recording nothing but one entry's number going 40, 48, 49 as a comment
  block above it grew — a file that changes on pushes with nothing to do
  with secrets being one a reader learns to skip. `--slim` omits both
  fields, and it needs a fresh scan: `--baseline` writes the full form
  whatever it read, `save_to_file` calling `format_for_output` with the
  default `is_slim_mode=False`, where `--slim` is honoured only on the
  branch that prints to stdout. So the exclusion the tree baseline's own
  filter used to supply is spelled out in the command, and both baseline
  files are named in it rather than the one `--baseline` would have
  skipped by itself. Verified rather than assumed: 53 findings in the
  tree baseline and 466 in the vectors one before and after, identical
  as sets of filename, hash and type; both hooks pass; and with a line
  inserted above every finding of `hashes.py` a regeneration is
  byte-identical to the committed file, which is the whole of what the
  churn was. The redirect costs two things and both are written where
  they are paid. One field of the diff — a new secret still arrives as a
  new `hashed_secret` under its filename, and finding *where* takes a
  grep — and the merge `--baseline` was doing, which carried an audit's
  own product forward: `is_secret` and `is_verified`, "verification of
  secrets, both automated and manual" in `SecretsCollection.merge`'s
  words. A scan into a file has nothing to merge, so those marks return
  to their defaults, and slim output prints no `is_secret` when it is
  unset, so the loss would show as a diff of nothing. Nothing is lost
  today, all 53 and all 466 findings being unverified and none carrying
  `is_secret`.
- **Ten lines that stopped short mid-sentence are the paragraphs they
  sit in, rewrapped** (#233). Each is the artifact an insertion leaves
  in a block nothing reflows: the qualifier goes in, the line it lands
  on stops early, and the diff of the change that made it shows a line
  that was going to be rewritten anyway. The unit of repair is the block
  and not the line, which #228 established the hard way — fixing the one
  line #225 named left two more of the same shape. Twelve blocks moved
  across `CHANGELOG.md`, `README.md`, `CONTRIBUTING.md`, `RELEASING.md`
  and `HISTORY.md`, every one of them word-for-word identical to what it
  said before, which is asserted rather than eyeballed: the rewrap
  compares the joined words of the block before and after and refuses to
  write where they differ. Three of the thirteen the issue counted are
  not defects at all and stay: a line before a markdown link of 63, 84
  and 125 columns is short because nothing can follow it, and the filter
  measured the link's first word rather than the link. No hook does
  this, which #233 asked about and answers no. The thresholds are a
  heuristic, a false positive has no `# noqa` to be marked with in
  prose, and a gate that is exact everywhere else is the wrong place for
  one that is nearly right — but the stronger half of that is the false
  *negative*, and this change produced one of its own (#240). Correcting
  a sentence in `CLAUDE.md` left a 35-column line mid-sentence under a
  57-column one, and the detector that had just counted ten of exactly
  that shape -- thirteen reported, ten of them defects -- walked past
  it: 35 is under the 46-column ceiling but 57 is under the 65 the line
  above has to reach, and the line at 57 is itself the same shape and
  over the ceiling. A *pair* of short lines hides a widow, because the
  first break is too long to be flagged and the second has no long line
  above it. So what a hook would have missed here is the instance a
  reader found, which is a better reason to decline it than the noise it
  would have added — and the two short lines left in that paragraph
  after the rewrap are token-forced, 47 columns before a 32-character
  path and 58 before a 40-character one, the same shape as the three
  links. Those are columns and not bytes, which is worth saying where
  the figures are: the second line carries an em dash, three bytes and
  one column, so `awk` in a byte locale and `wc -c` answer 60 where the
  detector's own `len` answers 58, and every figure in this bullet is
  the second kind. No consecutive short pair anywhere in it is what says
  the rewrap is complete, and it is cheaper to check by eye than either
  threshold.
- **The worktree recipe costs a submodule clone, and the sentence under
  it counts it now** (#234). It said the venv and the C build "are the
  whole of the cost" and after the submodule line they are not: a linked
  worktree gets a module of its own rather than sharing the primary
  checkout's, measured at 14 MB under `.git/worktrees/<wt>/modules` and
  7 MB of tree, which is the same "minutes, not seconds" argument the
  other two get. `--reference` is what a session asks about next and is
  measured rather than reasoned about: it works, leaves the module
  directory where git puts it, writes one `objects/info/alternates` at
  the primary's `objects`, and comes to 128 KB against those 14 MB with
  the primary's `core.worktree` untouched. What it costs is that pointer
  — no copy of its own objects, so a `git gc` or a repack in the
  primary, or moving it, can leave the worktree's submodule unable to
  find them. What git keeps apart by giving each linked worktree a
  module of its own is the submodule's *state*, so two worktrees can
  have it at two commits; the object store inside that module follows
  from where the state lives rather than from a refusal to share
  objects, which is why `--reference` may share them and leaves
  `core.worktree` alone. For a recipe that removes the worktree anyway
  that is a trade worth declining knowingly. Two facts measured while
  checking that go with it, both about a sharp edge: `core.worktree` is
  a single value that a second checkout of one submodule can rewrite
  under the first, and does not here; and `git worktree remove --force`
  finishes with an initialized submodule inside, exit 0 and nothing left
  for `git worktree prune`, so the recipe's last line needs no
  companion.
- **`silentpayments` says why its two widths are the package's only
  public ones** (#232). Six modules name a buffer width privately and
  this one does not, which after #221 made "the six modules read alike"
  a claim a reader would test against the seventh. The rule is not the
  one `xonly.py` states about its own: those are the size of a buffer
  the module fills and unpacks, where these are lengths this module
  answers a caller with. `SUMMARY_SIZE` has to be public — `ffi.sizeof`
  of a struct, written down by no BIP, moving when libsecp256k1 moves,
  and unknowable to a caller holding what `prevouts_summary` returned.
  `LABEL_SIZE` is 33 and could be worked out, so what keeps it public is
  that it has been since 0.8.0 and taking a released name private to
  tidy an asymmetry is a break charged to a reader who never asked.
  `keys._COMPRESSED_SIZE` is the same 33 and stays private: two callers'
  arguments are checked against this one, `parse_label`'s octets and the
  labels `_fill_label_cache` takes for `_scan_outputs_`, where nothing
  in `keys` checks an argument against a width at all. What
  `serialize_label` does with it is the other kind of use and is named
  as such — unpacking the buffer this module declared, which is exactly
  what `keys` does with its own.
- **`dsa.verify` says whose refusal the lower-s form is** (#249). The
  docstring motivated the default by who wants it -- "what a caller
  enforcing the lower-s form of its own signatures wants" -- which reads
  as this wrapper choosing between two behaviours libsecp256k1 offers. It
  is the other way round: `secp256k1_ecdsa_verify` accepts the lower-s
  form alone, "to avoid accepting malleable signatures", so `False` is
  that call passed through and `normalize=True` is the one way of not
  passing it through. Which is also what makes the flag unlike the rest
  of this module's booleans: `grind` and `verify` weigh a cost against a
  benefit and `compact` picks a serialization, where this one spends no
  measurable time and pays in the malleability itself -- two encodings
  verifying one message under one key, which whatever hashes or stores
  the signature has both to account for. Bitcoin Core makes the same
  refusal a standardness rule, `SCRIPT_VERIFY_LOW_S`, so a signature
  from elsewhere and a signature a transaction can carry are not the same
  set, and "a caller checking signatures it did not make normalizes" is
  now stated with what it accepts in exchange. `_verify_`'s argument
  entry, which has no prose above it to lean on, points at both.

### CI

- **A pull request that changes only prose no longer runs the matrix**
  (#189). Measured on the last full run before this, 48 jobs and 81.8
  runner-minutes, of which the change that added `windows.yml` to the
  table of sentinels — four markdown files and one workflow comment —
  asked for all of them. `changes` is one ubuntu job that lists the pull
  request's files through the API and answers whether anything the matrix
  reads changed; the five root jobs read it in their `if`, and what hangs
  off them skips on its own. `test: every job passed` already carried
  `always()`, so it still runs and reads `skipped`, which it does not
  treat as a failure, and the branch rule keeps naming the same context.
  Three things the job cannot get wrong, all in the comment above it: it
  runs on every trigger and answers `true` on all but `pull_request`,
  because a `changes` that skipped itself would leave every dependent
  reading an empty output and skip the release path too; `README.md` is
  not prose here, being the long description `check-dist` renders with
  twine and rates with pyroma, which is why the allowlist is written out
  rather than inverted from `*.md`; and `test-passed` takes `changes` as
  a `needs`, so an error listing the files fails the gate instead of
  skipping everything and reporting a pass
- **The suite cells are one job per image, not one per interpreter**
  (#190). In the same run, 30 of the 48 jobs were suite cells and they
  were 11.8 of its 81.8 runner-minutes: what they cost is slots, of which
  an organization on GitHub Free has twenty shared across every
  repository in it, and not time. `suite-dynamic` (eight interpreters on
  two images) and `suite-static` (seven on two) are two jobs each now,
  walking their whole list. Per cell the marginal work is an install and
  a suite, both under half a minute, against a checkout, a setup-python
  and an artifact download paid once per job — so the collapse costs
  little wall clock and pays back twenty-six slots. What it trades away
  is that a cell named the interpreter in the check itself, and the loop
  gives that back where it can: every version runs even after one has
  failed, each inside a fold of its own, and the failures are named
  together at the end rather than the first one aborting the job. The
  list is stated once per job and read twice, by setup-python and by the
  loop, so a version in one and not the other is either an interpreter
  installed and never run or a run that fails on a missing executable
- **A pull request builds one wheel on macOS and Windows, and the rest
  after the merge** (#193). Of the 59.5 runner-minutes the six wheel jobs
  cost, 39.0 were the four jobs that are not ubuntu. What a pull request
  needs to know about a platform whose suite it no longer waits for is
  whether this tree still builds there, and the first wheel answers it:
  the toolchain, the CMake build of the vendored library and the cffi
  extension are what differ per platform, and they do not differ per
  interpreter. So on `pull_request` those four build `cp314-*` alone. The
  two ubuntu images keep the whole set because `suite-static` consumes
  it — pip's selection among a directory of wheels tagged for seven
  interpreters is not a question a directory of one can be asked. A push
  to `main`, a release and a rehearsal all build everything, in a called
  workflow `github.event_name` being the caller's and never
  `pull_request`, so no wheel a release publishes was built under the
  shortcut. What is given up is the window between the two: a break
  specific to one ABI tag on macOS or Windows sits on `main` until the
  push run that follows the merge, instead of being refused at it.
  Measured on the change's own run, those four jobs came to 7.2
  runner-minutes: 14.4 and 5.7 on the two macOS images became 1.5 and 1.2,
  8.7 and 10.2 on the two Windows ones became 1.8 and 2.7
- **and the step that does it needs `shell: bash`, which the first run is
  what said.** Without it the two Windows images run it in PowerShell,
  where `"$GITHUB_ENV"` is not the variable but a literal, so
  `echo "CIBW_BUILD=cp314-*" >> "$GITHUB_ENV"` wrote a file of that name
  and cibuildwheel built all seven wheels anyway. Nothing failed: the step
  was green, the log listed `cp310` through `cp314t`, and the only thing
  that said so was a job duration that had not moved — 9.8 and 10.4
  against a 8.7 and 10.2 baseline — while the macOS images, whose default
  shell is bash, had already dropped to 1.5 and 1.2. A step that is green
  while doing nothing is why the comment above it now carries this
- **The vendored library is no longer configured by what happens to be
  installed on the machine that builds it** (#211).
  `SECP256K1_VALGRIND` defaults to `AUTO`, and `AUTO` is
  `find_package(Valgrind)` — the only `find_package` in the vendored
  CMake. Where the header is on an include path, the library is compiled
  with `-DVALGRIND`, which turns the `SECP256K1_CHECKMEM_*` of
  `src/checkmem.h` from no-ops into valgrind client requests, and
  `SECP256K1_BUILD_CTIME_TESTS` takes its default from it besides. So a
  runner that happened to have one shipped a different library from the
  same commit, in a wheel that says nothing about which one it is.
  `scripts/cffi_build.py` passes `-DSECP256K1_VALGRIND=OFF` now.
- **The defect was reproduced before it was fixed** rather than argued
  from the CMake: configured against a directory holding a
  `valgrind/memcheck.h`, `AUTO` reports `-- Found Valgrind`, puts
  `Valgrind_INCLUDE_DIR` in the cache and `-DVALGRIND` in
  `src/CMakeFiles/secp256k1.dir/flags.make`; `OFF` does none of the
  three, `find_package` not running at all. An empty header is enough,
  the module's compile check only rejecting `NVALGRIND`, so the trigger
  is a header on an include path and not an installed valgrind. Every
  wheel job's configure summary carries the answer —
  `Valgrind .............................. OFF` — which is the audit,
  `scripts/` being outside the coverage gate.
- **The instrumentation in such a wheel runs rather than merely being
  present, and the pin is still not about what it costs.**
  `SECP256K1_CHECKMEM_RUNNING()` is itself a client request under
  `VALGRIND` — `src/checkmem.h` defines it as
  `(VALGRIND_MAKE_MEM_DEFINED(NULL, 0) != 0)` deliberately, memcheck
  having to be detected specifically rather than valgrind in general —
  and it is the left operand of the `&&` at `src/secp256k1.c:104`,
  behind no flag and no `VERIFY`. `secp256k1_context_create` reaches
  that line twice, so a wheel built with `-DVALGRIND` executes two of
  them at import and none afterwards: the other call site is
  `secp256k1_declassify` (`src/secp256k1.c:254`), behind
  `ctx->declassify`, which line 104 refuses to set outside memcheck at
  all. Everything else is `CHECK_VERIFY`, `MSAN_DEFINE`, or under
  `#ifdef VERIFY`. A handful of instructions, once — and what the pin is
  about is that the wheel be a function of the source.
- **`SECP256K1_ASM`, `SECP256K1_ECMULT_WINDOW_SIZE` and
  `SECP256K1_ECMULT_GEN_KB` stay at upstream's defaults, and that is now
  written down** rather than left as three options nobody named. The two
  table sizes (15, and 86 KiB reaching the compiler as `COMB_BLOCKS=43
  COMB_TEETH=6`) are what upstream recommends for a desktop. `ASM` asks
  the build machine a question too — `AUTO` is a compile check, and it
  falls back to `OFF` in silence where that check fails, which a pinned
  `x86_64` would turn into a build error — but it cannot be pinned in a
  line: the macOS `universal2` cell compiles two architectures in one
  pass and the mingw one cross-compiles, so naming an architecture there
  would break the cells that are not it. So one machine question stays
  open, by choice, and the headline above is scoped to the one that is
  closed.
- **The vendored library is compiled once per wheel job, not once per
  wheel** (#192). The six wheel jobs were 59.5 of that run's 81.8
  runner-minutes, and each of them built the whole of libsecp256k1 once
  per wheel: seven interpreters on macOS and Windows, twice that on
  Linux, manylinux and musllinux being separate images. The work is
  identical every time, the library not knowing which interpreter the
  extension beside it will be built for. `scripts/cffi_build.py` still
  deletes the CMake directory before every build — a stale CMake cache is
  a configuration nobody asked for, and that is a different failure from
  this one — because ccache does not need it reused: it hashes the
  preprocessed source and the compiler flags, so it cannot serve an object
  built for another configuration. CMake initializes
  `CMAKE_C_COMPILER_LAUNCHER` from the environment variable of the same
  name, so the whole wiring is one `environment` line in
  `[tool.cibuildwheel.linux]` and `.macos` and a `before-all` that
  installs ccache. Measured on its own run, the four jobs it touches went
  from 40.6 runner-minutes to 32.9: 14.4 to 11.1 on macos-26-intel, 9.9 to
  7.7 on ubuntu-24.04-arm, 10.6 to 9.3 on ubuntu-latest, 5.7 to 4.8 on
  macos-latest. The two Windows jobs, which this does not touch, moved
  8.7 to 11.2 and 10.2 to 10.7 in the same run, which is the size of the
  noise these four are measured against — and that all four moved the
  same way is what the reading rests on. Windows is deliberately out, and
  is 18.9 of those 59.5 minutes: ccache's MSVC support is recent and
  partial, and sccache is a second tool to pin for a saving nothing has
  measured there
- **and the fallback lives in `before-all` because `environment` cannot
  hold one.** The first attempt made the launcher
  `$(command -v ccache || true)`, so that an image without ccache would
  configure with an empty launcher and build as before. cibuildwheel does
  not evaluate `environment` in a shell: it parses the value with bashlex
  and runs each command through `subprocess` with `check=True`. Measured
  against that parser rather than argued —
  `X="$(command -v ccache || true)"` is an `EnvironmentParseError`,
  `X="$(command -v ccache)"` raises `CalledProcessError` where there is no
  ccache, and only `X=ccache` survives. So the launcher is the literal,
  and `before-all`, which *is* a shell, carries the chain: whichever
  package manager answers — the manylinux images ship no ccache and keep
  theirs in EPEL — and, if none does, a passthrough of that name written
  on the PATH, `exec "$@"`, so the launcher always resolves. `ccache
  --version` at the end is what makes the log say which of the two
  happened; on every image of that run it was the real one, 3.7.7 on
  manylinux aarch64, 4.11.3 on musllinux, 4.13.6 from brew on macOS
- **`github-release` needed `always()` too, not just an explicit `if`.**
  The previous fix (v0.8.0.2's own CHANGELOG entry, right below) added
  `needs.publish-pypi.result == 'success' && needs.attest.result ==
  'success'` and reasoned that asking only about direct needs would be
  enough — it was not: v0.8.0.2 published clean and was *still* skipped
  with both of those green. GitHub's needs-based skip is structural, not
  a property of which question a job's own `if` asks: a job with a
  skipped job anywhere in its ancestry is force-skipped regardless of its
  condition unless that condition itself starts with `always()`, and the
  override does not clear the taint for whoever depends on the job that
  used it. `attest`'s `always()` keeps attest itself from being skipped
  when `publish-testpypi` is (always, on a real tag); `github-release`,
  needing `attest`, still sat behind that same skipped ancestor and was
  force-skipped in turn until it opted out on its own. `if: always() &&
  needs.publish-pypi.result == 'success' && needs.attest.result ==
  'success'` is what actually breaks the chain. v0.8.0, v0.8.0.1 and
  v0.8.0.2 all published clean and none produced a GitHub release,
  recreated by hand from each run's own `sdist` and `attestation`
  artifacts every time
- **A change to prose no longer rewrites `.secrets.baseline`** (#198).
  The baseline recorded one finding in `CHANGELOG.md`, and this file
  grows above it: of the forty commits before this one, forty rewrote
  the baseline and thirty-three moved nothing in it but that finding's
  `line_number`. What the rewrite costs is not the command that makes it
  — it is that every open pull request then conflicts there with every
  other and with `main`, whatever either of them touches, which is what
  happened to #183 and #185 within the hour they were both open. The
  finding is a false positive this file's own entry above records: the
  `-DSECP256K1_BUILD_BENCHMARK=OFF` it names is quoted there as
  `cffi_build.py` writes it, and a string in straight quotes is what the
  base64 detector reads. A `pragma: allowlist secret` beside it takes it
  out of the baseline without taking the quotes out of the sentence,
  they being why the detector fires and so what the sentence is about.
  Measured against the alternatives: dropping the quotes also clears it
  and says less; the pragma on the previous line does *not* clear it,
  `is_line_allowlisted` reading `context.previous_line` notwithstanding;
  and excluding the file from the hook would take the keyword and
  provider-token detectors off it too. The baseline is now written when
  a file that has a finding changes, which was 7 of those 40 rather than
  all of them
- **`mutation.yml` says what its session cannot ask** (#222). The
  operators replace arithmetic, comparisons, literals, branches and
  decorators; not one of them puts a different expression in an argument
  list, so which argument a `lib` call is handed — the whole of what a
  binding decides — is mutated by nothing in the session, and a green
  Sunday says nothing about it. `core/VariableReplacer` and
  `core/VariableInserter` are the two that come closest and
  `.github/mutation/bindings.toml` instantiates neither, both declaring
  `cause_variable` and `effect_variable` arguments it does not supply;
  configured they would substitute a random number, which cffi refuses
  where a pointer was declared, and a mutant that dies of a `TypeError`
  proves the boundary type-checks rather than that a test read what the
  call wrote. The instance is the first revision of #220: `ffi.NULL` in
  place of the `int *` its caller allocated left the whole suite passing,
  the key having even y and `ffi.new("int *")` zeroing what it allocates,
  so every side of every comparison was 0 either way. A paragraph in the
  header is the change, and it is what would have made that hole visible
  while the test was being written rather than after. An operator of our
  own, replacing each argument of a `lib.*` call with `ffi.NULL` in turn,
  is what a second instance would justify and what nothing yet does: the
  optional out-parameters of the wrapped surface are the two occurrences
  of `Ignored if NULL` in the vendored headers, both in
  `secp256k1_extrakeys.h` and both now exercised over either answer, plus
  `sigout` of `secp256k1_ecdsa_signature_normalize`, for which `dsa`
  passes `ffi.NULL` already
- **`bindings.toml` records the resolution a consolidated width costs**
  (#231). Its preamble already carries the two shapes that were answered
  in the code and the one equivalence that cannot be, each written down
  so a session does not spend itself rediscovering them; a width
  collapsed to one statement belongs in that list for the opposite
  reason. Two modules had several mutable copies of one number —
  `ellswift` three, at `_decode_` and at both of `xdh`'s checks, and
  `ssa` two, at `_verify_` and at `verify` — and `core/NumberReplacer`
  carries `OFFSETS = [+1, -1]`, a position per offset, so `ellswift`'s
  six mutants are two now and either of them changes every site at once,
  dying on whichever test reaches it first. A check that later loses the
  test covering it can therefore no longer surface as a survivor.
  Nothing is hidden today, the seven constants #221 introduced having
  each been mutated both ways before it landed and all fourteen dying,
  and the paragraph says what the ratchet does and does not catch
  instead: a line that stops running is caught, a line still run by
  another test and asserted by none is what neither question sees.
- **The prose allowlist covers the two file kinds nothing built reads**
  (#239). `changes` answers whether the matrix has anything to check,
  and its pattern was the root and `.github` prose alone — so a pull
  request touching one file the matrix cannot read alongside prose ran
  everything. The mutation configuration is on it now, cosmic-ray taking
  that path as an argument from a workflow the matrix does not contain,
  and so are the detect-secrets baselines, which are that tool's own
  output read by a hook and by a workflow that has no changed-file gate
  at all. It is anchored on the file --
  `^\.github/mutation/[^/]*\.toml$` -- and not on the directory, that
  being the same staleness this declines for workflows in the direction
  that looks cheap: a prefix would exempt in advance whatever a later
  change drops there, and two tests already load a script by path one
  directory over, so such a script would skip the matrix and take its
  own test with it. `.toml` rather than the one filename so a second
  configuration needs no edit; a script belongs in `.github/scripts/`,
  where all three are. Measured before and after against the file lists
  of four real pull requests, with `/usr/bin/grep` rather than this
  machine's `grep`: #236's `bindings.toml` and two markdown files went
  from 23 jobs and 45.7 runner-minutes to a skipped matrix, a baseline
  alone likewise, while #237's `silentpayments.py`, a bare `README.md`,
  a file under `docs/` and an empty list all still run everything. A
  workflow is deliberately not on the list, which is the other half of
  #239 answered rather than omitted: which workflows the matrix reads is
  a judgement — this file, what it calls, and `release.yml` — and a list
  of the rest would be right today and stale the first time a sentinel
  is folded into the gate, which skips a matrix that should have run.
  The comment above the pattern carries that reasoning and the figure.
- **and the list that promises to reproduce each gating job was missing
  the job that decides whether the others run** (#242), which is the same
  step again from the other side. Reproducing it by hand answers the
  opposite where the shell's `grep` is ugrep: `-qv` there takes its
  status from whether the pattern matched anywhere and inverts that,
  rather than from whether `-v` selected a line, so a list mixing prose
  with code — the case the step exists to judge — exits 1 and reads as
  "prose only", the direction that skips a matrix that should have run,
  and nothing says it has. Measured on each shape of file list with the
  pattern taken out of the workflow, and against the runner rather than
  against itself: #237's own list answers "everything runs" as its run
  did, and the pull request carrying this entry answers "prose only" with
  its matrix skipped. Nothing in the tree moves, `test.yml`'s `grep`
  being the runner's, which is GNU's. The entry spells the path out,
  lifts the pattern out of `test.yml` so the two cannot drift, and names
  `-q` as the mechanism rather than `-v`: ugrep takes the same
  file-level path when the output is discarded, which is where dropping
  `-q` lands next, and `-cvE` with a numeric test is what agrees with
  both greps. `test: every job passed` gets an entry in the same pass,
  that being the neighbouring gap and the check a contributor sees red:
  it reproduces as nothing, reading the conclusions of the jobs above it.

## v0.8.0.2

### The parsed public key

- **Verification takes the parsed key a caller already holds** (#147).
  `keys.parse` was public and `keys.serialize` took what it returned, and
  `pubkey_tweak_add_` consumed one — but `dsa.verify`, `ssa.verify` and
  `ecdh.shared_secret` took bytes and parsed them, so a caller holding a
  parsed key had nowhere to put it. Two callers pay for that twice: one
  that validates a key before verifying with it, which is
  <https://github.com/btclib-org/btclib/issues/887> and the other half of
  this pair, and one checking several signatures against one key, which
  is the case `PubkeyTweakChain` exists to stop for tweaks. For a
  compressed key the parse is a field square root, so it is not a
  rounding error next to the verification it precedes. `dsa.verify_`,
  `ssa.verify_`, `ecdh.shared_secret_`, `keys.pubkey_negate_`,
  `keys.pubkey_tweak_mul_`, `keys.pubkey_cmp_` and `xonly.from_pubkey_`
  are the inner halves, and `xonly.parse` is public beside `keys.parse`
  because BIP340 verifies against the x-only key and that is the object
  `ssa.verify_` takes.
- **The convention is one sentence, and it is in `keys.parse`**: the
  inner half takes the parsed key in place of the bytes, and the outer
  half is that inner half with a `parse` in front of it. Nothing else
  differs — every remaining argument is checked exactly as before, a bare
  pointer's length being what no C return code can report, which is why
  these are not quite the "already validated, nothing left to redo" shape
  `pubkey_tweak_add_` was documented as. That one is brought to the same
  rule here: it takes `BytesLike | int` and validates the tweak itself,
  where it took 32 bytes on trust and would have read past the end of a
  shorter value. `PubkeyTweakChain` is unchanged in behaviour, its
  `scalar` call now happening one frame further in.
- **`tests/test_parsed_keys.py` holds every pair to that equality**, over
  both serializations of the key, and holds the table of pairs to what
  the modules export: an inner half added and left unpaired fails there
  rather than going untested. `mult.mult_` is named in it as the one
  trailing underscore that means the older thing — the serialized point
  against `mult`'s pair of coordinates — and has no key to be handed
  already parsed.
- **What is deliberately not there**: `keys.pubkey_combine` and
  `keys.pubkey_sort` take sequences, so their inner halves would take
  lists of cffi objects, and no caller has asked; and there is no
  `xonly.serialize` beside `xonly.parse`, nothing here handing back a
  parsed x-only key for one to take.

### ECDSA signature normalization

- **`dsa.verify` and `dsa.verify_` take a `normalize` flag** (#148),
  false by default. `verify` does not accept a signature outside the
  lower-s form, and which of the two forms a signature carries was the
  signer's choice, so a caller checking signatures it did not make always
  normalizes first — and `normalize` takes DER and returns DER, so that
  is a parse, a normalization, a serialization, and then `verify` parsing
  what came out. libsecp256k1 documents `sigout == sigin` for
  `secp256k1_ecdsa_signature_normalize`, so neither the serialization nor
  the second parse is the normalization's own need: with the flag, the
  normalization happens on the signature `verify` has already parsed.
  <https://github.com/btclib-org/btclib/issues/889> is the caller.
- **A flag rather than a public parsed-signature form**, which is the
  other answer #148 offered and the one that would have followed #147
  exactly. The parsed *key* is a thing a caller holds for its own reasons
  — `keys.parse` is how a key is validated — while a parsed DER signature
  is an intermediate nothing here produces or consumes, so publishing it
  would have meant a `parse` and a `serialize` for signatures and inner
  halves of `normalize`, `is_low_s` and `to_compact` besides, for one
  caller that wants none of them. The flag is the whole of what that
  caller needs, and the default keeps today's refusal for the caller
  enforcing the lower-s form of its own signatures. It is not the
  leniency the README's "nothing is normalized into validity" refuses,
  either: that bullet is about a boundary guessing what the caller meant,
  and this is the caller saying it.

### The benchmark

- **`scripts/benchmark.py` moves to
  [btclib-benchmarks](https://github.com/btclib-org/btclib-benchmarks)**,
  as `scripts/libsecp256k1_wrappers.py`, and the `bench` dependency group
  goes with it (issues #144 and #145).

  The group named `btclib`, `coincurve` and `secp256k1`, which put the
  packages being timed into this repository's lock. `btclib` was the
  wrong way round in particular: it is btclib that depends on these
  bindings, so a benchmark comparand made the dependency circular in the
  one direction a lock can express it — and the copy it resolved was
  `btclib_libsecp256k1` 0.7.1.3 from PyPI, an older release of *this*
  package installed beside the tree it was meant to measure.

  What #144 and #145 asked for — narrowing the comparison to
  wrapper-against-wrapper, and adding `electrum-ecc` to it — is work on
  that script, and it moves with the script rather than being done or
  abandoned here.

  `[[tool.mypy.overrides]]` keeps its `secp256k1` entry and loses the
  other two: that name has a second job here, the vendored C tree being
  picked up as a namespace package of the same name without it.

### CI

- **The generated Code Quality analysis is off.** `Analyze (python)` ran
  on every pull request and every push to `main` from a
  `dynamic/github-code-scanning/codeql` workflow no file in this tree
  declares -- some 52 seconds of a slot each time, out of twenty shared
  with every other repository in the organization, where the same setting
  was on. What it produced cannot be read from outside a browser: there is
  no `code-quality/alerts` endpoint and no `code-quality/analyses`, both
  404, the alert list is empty and every analysis carries `codeql.yml`'s
  own category. REPOSITORY.md gains the section and the endpoint that
  reports and sets it, `code-quality/setup`: not
  `code-scanning/default-setup`, and not the Actions API, which answers
  422 for a workflow this repository does not own.

- **A pull request asks for fifty-one jobs instead of seventy-three**, and
  the number that decided it is a ceiling rather than a wall clock: GitHub
  Free gives an organization twenty concurrent jobs, shared across every
  repository in it, so a commit here, one in btclib and one in
  bitcoin-core-rpc compete for the same twenty. Measured on one pull
  request run, this workflow set asked for seventy-three jobs and 112.9
  runner-minutes, its critical path 1713 seconds of which the median cell
  spent 694 queueing. Two changes, each moving an answer off the review
  path rather than dropping it:
    - the twenty-one Windows suite cells become `windows.yml`, weekly on
    Saturday and called by `release.yml`, exactly as `macos.yml` already
    holds the macOS ones and built the same way -- from the tree, in both
    linkages, two steps of one job rather than a wheel rebuilt per image.
    They were 27.3 of the 112.9 runner-minutes, the largest family of jobs
    in the run and ahead of every wheel build. **The Windows wheel builds
    stay in `test.yml`**, for the reason its header gives of macOS: the
    release publishes the artifacts of that run, and `cibuildwheel` runs
    the suite against every wheel as it builds it, so what moves to
    Saturday is pip's *selection* among them. With both Windows rows gone
    so are the three exclusions `suite-static` carried, each of them a
    wheel that is not built rather than a platform not worth running.
    - `codeql.yml` loses its `pull_request` trigger and keeps `main` and its
    Tuesday schedule, so `codeql: every job passed` is no longer one of
    main's required checks -- three now, and REPOSITORY.md carries the rule
    and the `PATCH` that dropped the context. `zizmor` is a `pre-commit`
    hook, so `lint.yml` still audits these workflows for an injected
    expression on every pull request.

- **`github-release` no longer risks a skip on a release that actually
  succeeded.** Its `if` used to be the implicit default, and that default
  has no arguments: it does not stop at this job's own `needs`
  (`[publish-pypi, attest]`), it looks at the whole graph reachable
  through them. `attest`'s own `if` is `always()`, needed so it can run
  past a skipped sibling — `publish-testpypi` is always skipped on a real
  tag, `publish-pypi` on a dispatch — and the implicit default treats a
  skipped job found two hops back through that `always()`-guarded edge
  the same as a failed direct one. That skipped `github-release` on every
  real release regardless of what `publish-pypi` and `attest` themselves
  did: both v0.8.0 and v0.8.0.1 published clean and neither produced a
  GitHub release, found only because the release was missing rather than
  because anything failed loudly. The `if` is explicit now,
  `needs.publish-pypi.result == 'success' && needs.attest.result ==
  'success'`, asking only the two questions this job has a reason to ask.
  RELEASING.md's "Cutting a release" section carries the recovery this
  cost both times — recreating the release by hand from the run's own
  `sdist` and `attestation` artifacts — for a release that predates the
  fix, or for a `github-release` failure of its own that `gh run rerun
  --failed` still reaches directly

## v0.8.0.1

### Public key tweaking

- **`keys.PubkeyTweakChain` adds a sequence of tweaks to a public key,
  parsing it once** (#138), rather than once per tweak. `pubkey_tweak_add`
  parses its argument and serializes its result on every call, which is
  the right cost for one tweak and a wasted one for a caller who is about
  to feed the result straight back in as the next call's argument — a
  BIP32 path walked one unhardened index at a time, reported at
  <https://github.com/btclib-org/btclib/issues/685>, needs exactly that:
  each step's tweak is a hash of the previous step's serialized key, so
  the bytes have to exist at every step, and the point they parse back
  into is the one the step before had already built and only serialized
  because its own caller — btclib's derivation loop — needed those bytes.
  `PubkeyTweakChain` holds the parsed point across the calls instead: the
  first tweak is the only one that pays for a parse, and every step still
  returns the bytes its caller needs. `pubkey_tweak_add` itself is
  unchanged in behaviour and cost, now sharing its point-addition step
  with the chain through the new `pubkey_tweak_add_`, the inner half of
  it that skips parsing and validating what the caller already has.
  btclib decided against holding the parsed key itself and reaching for
  `lib`/`ctx` directly, which would have left `_BIP32KeyData` holding a
  cffi object where "the key is its serialization" is what keeps that
  loop readable — hence the wrapper landing here rather than there.

## v0.8.0

### The name

- **`btclib_libsecp256k1` becomes `btclib_secp256k1`** (#122), the
  distribution and the import package together, with the extension
  (`_btclib_secp256k1`), its stub and the autodoc page following. `lib`
  named the C library, and a python distribution is not that library.
  Renaming both rather than the distribution alone is what keeps one name
  to explain: the alternative is a distribution and a module that
  disagree forever, and 0.8.0 being unreleased is what makes this the
  cheapest it will ever be. Everything inside the API is untouched.
- **The repository is renamed too**, to `btclib-org/btclib-secp256k1`.
  That was left out of the first pass on the `bitcoin-core-rpc`
  precedent, which renamed the same way and kept its repository, so that
  no url naming it would move; it is in now because a repository called
  after a distribution that no longer exists is the same confusion one
  level up. GitHub redirects the old paths, the api included — a `GET` on
  `repos/btclib-org/btclib-libsecp256k1` answers with the new
  `full_name`, and `gh` resolves it to the numeric id — so nothing
  outside this tree breaks on the day, and every url inside it is updated
  regardless: an address that answers through a redirect is still the
  wrong address to publish.
- **Two lines of `release.yml` were the reason to do it carefully**, and
  no redirect covers them: `github.repository == 'btclib-org/…'` guards
  both publish jobs, and an exact comparison against a name the
  repository no longer has does not fail — it evaluates false and the
  jobs are *skipped*. A release would have built the whole matrix,
  collected every artifact, and published nothing, in green.
- **The trusted publisher is bound to the repository**, which is the
  other half of the same care: the OIDC claim carries it, and this file
  already records a stale registration surviving one rename and costing
  0.7.1.2 an `invalid-publisher` at the token exchange. The pending
  publishers for the new distribution have to name the new repository.
- **No published artifact carries a GitHub attestation yet**, so
  `SECURITY.md`'s verify command takes the new name with no caveat:
  measured rather than assumed — `attest` landed in #113 on 11 August,
  two days after v0.7.1.3, and `gh attestation verify` on that release's
  sdist answers 404 under either name. The first attested release is
  0.8.0.
- **What deliberately did not change.** The vendored library keeps its
  own name wherever it is the subject: the submodule, the headers the
  cdef is made of, the `SECP256K1_*` build flags. And the entries of this
  file and of HISTORY.md that describe releases made under the old
  distribution name, or quote a command carrying the old repository,
  still do: they are the record of what happened rather than of what is
  true now.
- **Nothing bridges the two names on PyPI**, by decision. A final
  `btclib-libsecp256k1` depending on the new distribution would make
  `pip install btclib-libsecp256k1` resolve forward; what it would also
  do is put a package on PyPI whose only content is a redirection, and
  one that has to be deprecated and removed later. The old name stops at
  0.7.1.3 and stays installable, wrapping libsecp256k1 0.7.1, and moving
  is a requirement and an import to edit — the README's own "The name"
  section, which is where a user arriving from the old name lands.
- **The `bench` group now resolves a second copy of the old
  distribution.** btclib requires `btclib_libsecp256k1`, which used to be
  this project's own name, so the lock answered it with the editable
  build of this tree; until the rename reaches a btclib release it
  answers with 0.7.1.3 from PyPI instead, installed beside it. It
  collides with nothing — the import package was renamed too — and costs
  the benchmark nothing, whose btclib rows run with dispatch off. The
  comment in `pyproject.toml` says so where the group is declared.
- **Two things a maintainer has to do outside this tree**, and the first
  one blocks the release: the trusted publisher is registered per project
  name, so PyPI and TestPyPI each need a *pending* publisher for the new
  name, or the release run reaches the token exchange and stops at
  `invalid-publisher` having built the whole matrix. RELEASING.md's
  one-time setup section now opens with that. The second is the Read the
  Docs project behind the new slug, which the badge and the
  `documentation` url already point at.
- **`published` will be red until 0.8.0 is out.** It installs what PyPI
  serves under the name this tree declares, and PyPI serves nothing under
  the new one yet. It is a sentinel, named by no branch rule, and the
  release is what turns it green.

### The release path

- **The release tag is signed.** `git tag v0.7.1` made a lightweight tag:
  a name pointing at a commit, with no signature, no tagger and no date of
  its own. That is the wrong shape for the one ref a release is identified
  by — the PEP 740 attestation binds to it, the GitHub release is created
  from it, and `version-check` refuses a tree that does not match it — so
  it is the thing most worth being able to attest, and a lightweight tag
  cannot be attested at all. `git tag -s -m`, with `git tag -v` before the
  push rather than after, the push being what starts the workflow acting
  on it. libsecp256k1 signs its own release tags and documents verifying
  them in `secp256k1/README.md`, so this is the vendored library's
  standard applied to the wrapper.
- **`-s` explicitly, not `tag.gpgsign`.** The setting belongs in a git
  config, where this document cannot show it; the command here is the
  instruction, and it has to be right on a machine whose config nobody
  has checked. `-m` comes with it: signing implies annotating, and an
  annotated tag without a message opens an editor, which a release step
  must not do.
- Checked rather than assumed: nothing in `release.yml` reads the tag as
  anything but `github.ref_name`, which is the same for a lightweight and
  an annotated tag. The one `refs/tags/...^{}` in that file dereferences
  *bitcoin-core*'s tags, not this repository's.
- **Squash is the only merge method the repository enables**, for a release
  pull request and every other one. The merge commit was refused by
  `main`'s required linear history already, so turning it off takes away a
  button that could not have worked; the rebase merge could have, and what
  it would have done is replay a branch's commits onto a trunk where one
  change is one commit. What a single method takes away is the dropdown:
  GitHub preselects whichever was used last and the dialog that switches
  auto-merge on carries the same one, so the answer could be given hours
  before anything merged, by whoever switched it on, with nothing asking
  again -- which is what REPOSITORY.md's auto-merge section warned about
  and now records as gone. `btclib` and `bitcoin-core-rpc` carry the same
  setting and the same prose.

### The wrapped library

- **libsecp256k1 moves from 0.7.1 (1a53f49) to 0.8.0 (6e2c8bc)**, and the
  package version with it, the two tracking each other by the rule in the
  README's Versioning section. The submodule bump is what decides that
  number, so it is what carries it: `pyproject.toml`, this file and
  HISTORY.md all say 0.8.0, and the fourth-number placeholder 0.7.1.4 that
  was open is gone rather than released — nothing had shipped under it.
- **The symbols upstream removed were not used here.** Checked rather
  than assumed: `secp256k1_context_no_precomp` and the
  `secp256k1_schnorrsig_sign` alias appear nowhere in the package, the
  stubs or the tests, `ssa` having always called `sign32` and
  `sign_custom`. The macro `SECP256K1_GNUC_PREREQ` is also gone from the
  headers, which matters here only in that the headers are preprocessed
  into the cffi definitions: `gcc -E` expands what it finds, and it no
  longer finds that.
- **`ellswift.xdh`'s refusal of an out-of-range key is upstream's**, and
  the suite did not have to change for it. The wrapper already raised
  `ValueError("invalid private key")` on a zero return, and the docstring
  already said a key that is not a valid scalar raises; what changed is
  which keys libsecp256k1 calls invalid.

### What the boundary answers

- **A memoryview of items wider than an octet is refused.** `octets` takes
  the three types that state a value and a width, and a memoryview states
  its width in *items*: `memoryview(array("I", [1, 2, 3, 4, 5, 6, 7, 8]))`
  is eight of them, and the 32 octets `bytes` reads underneath them passed
  the size check as a private key nobody wrote — one that a big endian
  build of the same program would have read differently. It is the one
  shape in which the argument for converting rather than refusing does not
  hold, so it raises `TypeError` naming what it is, and `.cast("B")` is how
  a caller says the octets are what they meant. Nothing else about the
  shape is asked: where the items are octets, `bytes` answers the ones the
  view logically holds, through a stride and over every dimension, so the
  length checked is the length libsecp256k1 will read. mypy cannot see any
  of this — `memoryview` is the annotated type whatever its items are —
  which is why the check is at run time, like the `bool` one beside it

### Silent Payments

- **`silentpayments` wraps BIP352**, the module libsecp256k1 0.8.0 adds,
  through five functions rather than the seven entry points it has: the
  label parse and serialize are not API of their own, a label being 33
  bytes on the way in and out like every other key here. The build asks
  for `SECP256K1_ENABLE_MODULE_SILENTPAYMENTS` explicitly and concatenates
  `secp256k1_silentpayments.h` after `secp256k1_extrakeys.h`, whose types
  it needs — the same ordering constraint musig already had.
- **The prevouts summary crosses as opaque bytes.** libsecp256k1 gives no
  parser or serializer for it, guaranteeing only that it is a fixed size
  and safe to copy, so the binding returns the bytes of the struct and
  writes them back into one of the same size. Its length is therefore the
  only thing checkable about it, and `SUMMARY_SIZE` is asked of the struct
  with `ffi.sizeof` rather than written down, so a libsecp256k1 that
  changes it changes this too.
- **The label lookup is a python callback, and the ECDH hash is still
  not.** The two look alike and are not: the ECDH hash callback would put
  python in the middle of a computation that has an entry point of its own
  (`keys.pubkey_tweak_mul` is the shared point), where a labeled output
  cannot be recognized at all without a lookup only the caller can answer.
  So `scan_outputs` takes the label cache as a mapping and calls back into
  it. Every tweak is copied into a buffer this package owns *before* the
  scan starts, because the pointer the callback returns has to stay valid
  after it returns; and the callback body is a `dict.get` over keys already
  normalized, because cffi has nowhere to put an exception raised inside a
  callback — it prints the traceback and returns a default, which for a
  lookup means "no label", indistinguishable from having worked.
- **`ffi.addressof` joins the stub.** A found output carries its x-only
  public key and its label by value, and each has to reach its own
  serializer as a pointer.
- **The secrets are taken back.** A found output holds the tweak that
  spends it, the sender's keypairs and secret keys hold private keys, and
  the recipient's label cache holds the tweak of every label: all are
  wiped, and each collection is filled *inside* the `try` whose `finally`
  wipes it, an entry later in it being able to raise between them. The
  cache is filled entry by entry for that reason and not built by a
  comprehension, which drops the buffers it already made along with the
  exception — a malformed second label left the first one's tweak in
  memory this package had stopped pointing at.

### Mutation testing

- **A session over the new module found three mutants no test killed**,
  and the three are in tests/ now. The scope needed no change —
  `module-path` is the package, so a module added to it is in scope — and
  what the session cost was worth having:
    - `0 <= m < 2**32` mutated to `0 <= m != 2**32` survived a test that
    drove *both ends* of the bound. `-1` fails the first comparison and
    `2**32` fails the second, so both still raise; the one input that
    tells `<` from `!=` is a value above the bound, and `2**32 + 1` is now
    in the parametrization with the reason written beside it.
    - the two `finally` loops that wipe a secret survived being turned into
    `for buffer in []`, which is a new shape here: every other wipe in the
    package is one statement about one buffer, and these are the first
    over a list. The buffers are locals, invisible from any answer, so
    what kills the mutant is a spy on `wipe` — recording each buffer and
    wiping it for real, then asserting one per secret the call was given
    and every one of them zeroed. The sender's refusal path is asserted
    too: an invalid key later in the list has to leave the ones before it
    wiped, which is why both lists are built inside the `try`.
- **Run it with the filter, or read 110 survivors that mean nothing.**
  `cr-filter-operators` between `init` and `exec` is a step of the
  workflow and not of the toml, so a hand-run session that skips it
  reports every `bytes | int` annotation mutant as a survivor — 110 of
  113 on the first pass here. With it: 94 executed, **0 survived**, 110
  skipped.

### External vectors

- **`tests/bip352_send_and_receive_test_vectors.json`**, vendored from
  `bitcoin/bips` and byte-identical to the blob libsecp256k1 vendors
  itself, drives both directions of every case. Two things it taught,
  both of them assumptions this change made and had to drop:
    - the published `outputs` of a sending case are **alternative output
    sets, not orderings of one**. Where several recipients share a scan
    public key, which of them gets k = 0 is not determined, and each
    assignment gives different keys; comparing with the first entry
    passes 26 cases and fails 15 and 17. What is asserted is that the set
    produced is one of the sets accepted.
    - an input's public key cannot be matched to it by containment alone.
    Case 22's third input is a bare multisig whose redeem script names the
    key of the *first* input, so a key already claimed gets claimed twice
    and the sum comes out wrong. The keys are consumed in order instead,
    which is the order the file publishes them in.
- **The eligibility rules are not reimplemented.** BIP352 states them
  over scripts — a bare multisig, an uncompressed key, a NUMS-point script
  path — and reading scripts is what this package does not do. The vectors
  publish the extracted keys of exactly the eligible inputs, so the test
  walks those and the inputs in step; the one script question left is
  whether a prevout is P2TR, which is what decides between the two key
  arguments and cannot be read off anything else.
- **The three failure cases assert their own message.** No eligible input
  is refused here (`at least one private key`), input keys summing to zero
  is refused by libsecp256k1 (`silent payment output creation failed`),
  and on the recipient's side both are `prevouts_summary` refusing to make
  one — keyed on the vector's own published null `shared_secret`, which is
  what distinguishes them from the case whose scan simply finds nothing.

### CI

- **`version-check` refuses a tag whose release notes are still titled
  "work in progress".** The check it replaces asked only that
  `HISTORY.md` had a section for the tag, and
  `## v0.8.0 (work in progress, not released yet)` *is* a section for the
  tag: it matches `github-release`'s heading regex too, the tag being
  followed by a space, so a forgotten step 2 of RELEASING.md would have
  published the release notes with the five words still on them and
  nothing would have said a word. Measured on this very tree before the
  retitle, where the old check passed and the new one fails on
  `HISTORY.md:8`. It now asks three things of `HISTORY.md` **and**
  `CHANGELOG.md` — a section for the tag, a heading carrying the tag and
  nothing else, and a body that is not empty — and it is btclib's and
  bitcoin-core-rpc's step verbatim, so the three repositories refuse the
  same tag for the same three reasons. The string comparison rather than
  a regex is what keeps `v0.8.0` from matching `## v0.8.0.1`, which here
  is the neighbouring heading rather than a hypothetical: the fourth
  number a release opens as its placeholder. Release-only, like the tag
  comparison beside it: a rehearsal is what runs *before* the retitle.
- **The sdist attached to a GitHub release carries provenance** (#97),
  where only the copy on PyPI did: the publish job generates a PEP 740
  attestation for what it uploads to the index, and the byte-identical
  file on the releases page carried nothing, so whoever pinned to a
  release asset url or mirrored the page had no way to check where it
  came from. `release.yml` gains an `attest` job — `actions/attest`, one
  SLSA build provenance statement, signed with a short-lived Sigstore
  certificate — and `gh attestation verify <file> --repo
  btclib-org/btclib-libsecp256k1 --signer-workflow …` is what checks it,
  the last flag being what makes the answer name a workflow rather than
  accept any attestation this repository has. The signed bundle is
  attached to the release too, as `<tag>.attestation.jsonl`, so
  `--bundle` verifies the same signature without asking the attestations
  API for it. The digest is the index's own, the job downloading the
  `sdist` artifact rather than rebuilding it. The wheels are not signed
  a second time: they are attached to no release, so their only public
  copy is the one PyPI already attests. A job of its own and not two more
  permissions on `github-release`: `id-token: write` and `attestations:
  write` stay off the job that writes releases, and further off the
  matrix that compiles the vendored library. It runs after whichever
  publish job ran, so a dispatch from an arbitrary branch signs nothing
  an environment approval did not let through — and the TestPyPI
  rehearsal exercises it, which on the release path would otherwise
  happen for the first time after PyPI has the files and the tag can no
  longer be moved. `github-release` names both `publish-pypi` and
  `attest` in `needs`: naming `attest` alone would let a dispatch cut a
  release, that job running in a rehearsal too. Not the
  `attest-build-provenance` wrapper the issue proposed, which is a
  composite whose only step is `actions/attest` pinned there to v4.2.1 —
  calling the action directly is what leaves the version that signs
  pinned here.
- **The macOS suite cells left the merge gate for `macos.yml`.** Over six
  pull request runs of `test.yml`, ninety-eight jobs each and thirty-five of
  them on the two macOS images, a macOS job waited 20.8 and 19.0 minutes on
  average for a runner against 2.1 to 2.6 elsewhere — and the wait grows
  with the number of cells asking at once, so in the slowest of the six the
  thirty-one macOS suite cells took the last thirty places before the
  aggregate, their queue rising from 16.7 to 70.2 minutes and the run taking
  95 minutes for 105 minutes of work. The command that re-derives all of it
  is in `test.yml`'s header, next to the matrices those cells left. What
  moved is the suite; the macOS
  *wheel builds* stay, because the release publishes the artifacts of that
  run and the same measurement clears them — they finished at 24.6 minutes
  against the 23.5 of the ubuntu-latest build beside them. Four macOS jobs
  queue, thirty-one contend. `macos.yml` runs the two images over every
  interpreter `test.yml` ran there, half an hour before `latest.yml` on the
  same morning, so the pair reads as a difference: red in both is the
  platform, red in `latest` alone is the upgrade. It builds from the tree
  twice per cell, static and then dynamic, rather than rebuilding the
  wheels the cells used to install — ten minutes of `cibuildwheel` per
  image, and artifact names a release must not confuse with `test.yml`'s.
  It gates nothing, so a macOS regression can sit on `main` for a week;
  `release.yml` calls it, so it cannot be published.
- **The documentation build is `docs.yml`, not the second job of
  `lint.yml`.** A failed docs build and a failed hook are two different
  verdicts about two different things, and one badge and one line in the
  checks list each is what says so — the badge being a `docs` one added
  to the second README row, beside `test` and `lint`, where the row
  already ends with what read the docs makes of the same source. The
  job's display name is unchanged, which is what let it move without
  touching the branch rule: a required context is matched by name, not
  by the workflow that reported it.
- **Every job is named for the question it answers, and the aggregate is
  `test: every job passed`.** `Coverage` said which job it was rather than
  what it gates; the two suite matrices were *both* named
  `Test <version> on <os>`, so every run produced pairs of check runs with
  one name between them, which is the ambiguity a branch rule cannot see
  past — the linkage is in the name now. Renaming the aggregate renames a
  required check, the one change a pull request cannot make on its own:
  REPOSITORY.md carries the `PATCH` that moves the rule first.
- **`release.yml` calls every gate, and the published sentinel after
  itself.** It called `lint` and `test`; `docs` and `macos` are gates it
  was not waiting for, and `published` answers, at the one moment its
  answer changes, whether what was just uploaded can be installed. That
  last one waits for the index to serve the version the tag names before
  installing anything, so it cannot report a pass for the release before
  this one. A call rather than a `workflow_run` trigger, which zizmor rates
  dangerous and rightly: that one runs the default branch's copy of a
  workflow with a token nobody reviewed. The workflow also has a
  concurrency group at last, and it is the one here that must not cancel:
  a version is consumed by the upload that carries it.
- **`published.yml` is monthly, where it was weekly.** What it watches is
  external rot, which nothing in this repository moves, so a week was a
  sample rate without a reason — and the release now asks immediately,
  which is what the weekly was standing in for.
- **The workflows no longer name `master` and `dev`.** Neither branch
  exists. Two of those references were not merely stale: `branches:
  [master]` meant no push to `main` ran the gate at all, and the release
  workflow's ancestry check runs `git merge-base --is-ancestor
  "$GITHUB_SHA" origin/master`, which fails on a ref that is gone — the
  next tag would have been stopped by it. The draft exception that let the
  release pull request through (`github.base_ref == 'master'`) can never be
  true again and is gone with them.
- **CodeQL is `codeql.yml`, not code scanning's default setup.** It was the
  one required check on `main` whose definition no diff could review: a
  repository setting, so the languages it scanned, the queries it ran and
  the day it ran them were readable only through
  `gh api repos/{owner}/{repo}/code-scanning/default-setup`. The workflow
  reproduces exactly what that reported — `actions` and `python`, the
  `default` query suite, weekly — one job per language so a failure names
  the language, `github/codeql-action` pinned to a commit SHA like every
  other action here, and `security-events: write` declared on that job
  alone. The category is spelled as the setting spelled it,
  `/language:<language>`, which is what carries the existing alerts across:
  an upload under a new category closes every one of them as fixed and
  opens a copy. The aggregate is `codeql: every job passed`, for the reason
  `test.yml`'s own is: a branch rule must name an outcome and not a matrix
  cell. Turning the setting off and moving the rule are two steps only a
  maintainer can take, in an order REPOSITORY.md gives — while default
  setup is enabled the workflow still runs and the SARIF is refused at
  processing, so the jobs are red rather than absent, and the rule has to
  stop naming a context nothing produces before it can name the one this
  file does. That exchange has been made; what outlives it is a generated
  `dynamic/github-code-scanning/codeql` workflow uploading *code quality*
  results, which is a separate setting the `code-scanning` endpoint does
  not report.

### The gate

- **The submodule pin is checked on every commit, and its signature
  monthly** (#126). `version-check` in `release.yml` resolved the release
  `README.md` names against upstream and refused to publish a tree pinned
  to anything else — the last gate before publication, and until now the
  only one, so a bump reaching `main` waited for a release to be compared
  with the version the prose claimed. That is the window in which the
  changelog and the release notes about that version get written. The
  check now exists twice more, split by what each half needs:
  `.github/scripts/check_submodule_pin.py` resolves the tag in the
  vendored clone's own refs, which is offline and therefore a hook —
  `submodule-pin`, on every commit, because a `files` pattern cannot
  reach it: pre-commit drops from its file list everything that is not a
  regular file, and a submodule is a directory, so a hook filtered on
  `secp256k1` would never have run on the one commit it is for. Measured
  rather than assumed, by staging a bump and asking for the hook by name.
  GitHub's `paths:` filter is other code and does see the gitlink, which
  is what the sentinel keys on; and a `pin` job in
  `vendored-vectors.yml` fetches the tag object from upstream and runs
  `git tag -v` against the three maintainer fingerprints recorded from
  libsecp256k1's own `SECURITY.md`, which nothing here had ever verified.
  That half is a sentinel because a keyserver that is down is nothing a
  pull request did, and it runs on the pull request that moves the pin
  regardless: a gitlink is a path like any other in a `paths` filter, as
  #106 shows, having `secp256k1` among its changed files. It opens no
  issue where its neighbour does, and the reason is the subject: a vector
  file drifts because upstream edits it in place, while a pin moves only
  in a commit of this repository. `lint.yml` checks out the submodule
  unshallow for the hook, tags being what a `--depth=1` clone has none of
- **`submodule-pin` is skipped on pre-commit.ci**, which is the second
  entry that list has ever had and was found the way the first one's
  reason would have been: the pull request adding the hook went red
  there, with the hook's own message, while every other hook passed
  (#130). Skipping was the cheap answer, and #131 asked for the other
  one — `submodules: true`, a documented key of the `ci:` block — so it
  was tried rather than argued about (#132). With it the clone arrives
  and the hook fails all the same: **the vendored clone is shallow and
  carries no `v0.8.0` tag**, and there is no `fetch-depth` key to ask
  that service for. So the key bought a clone nothing can use and is not
  kept, the skip stays, and REPOSITORY.md now records the gap beside the
  checks the branch rule deliberately leaves out — one third-party check
  this repository cannot make agree with `lint.yml`. What it costs is one
  of the hook's two runners: the required one, `Lint and type-check`,
  checks the submodule out with `fetch-depth: 0` precisely so it has what
  the hook needs, and a developer's own commit has it too
- **The hook says which of the three states a clone without the tag is
  in**: not checked out, checked out but shallow, or a full clone that
  simply lacks the tag — one sentence each, each naming what would change
  it. One message covered all three and told them apart for nobody, which
  is fine for a developer, who has one of them and knows which, and not
  fine for a checkout somebody else makes, where which one it is *is* the
  finding. That is exactly how the pre-commit.ci answer above stopped
  being an inference: the second run of #132 came back naming `shallow`
- **Every required check names the app that produces it.** `test: every
  job passed` and `codeql: every job passed` carried `app_id: 15368` and
  the other two carried none, which REPOSITORY.md recorded as a rule that
  was not uniform in this. An unbound context is satisfied by *any* app
  reporting a check run of that name, so anything installed on the
  organization with `checks: write` could turn `Lint and type-check` green
  with no workflow having run. Both are Actions checks -- the check-runs
  endpoint answers 15368 for each -- so the binding changes nothing a run
  can see, and closes that. The `PATCH` this file already documented is
  what applied it; btclib and bitcoin-core-rpc are bound the same way, so
  the three now read `app_id: 15368` for every context they require
- **`pinned-rev` refuses a `rev` that does not name a released version.**
  Nothing but `pre-commit autoupdate` writes a `rev`, and it offers
  whatever tag the remote's HEAD carries: twice that was not a release —
  `v1`, a floating major tag its owner moves under the pin, and `5.1b1`, a
  prerelease with no `5.1` behind it — and both were merged before anybody
  read the diff, so the review is not the check. pre-commit says as much
  itself for the moving tag, a `[WARNING]` about a mutable reference, and a
  warning is not an exit code. A `pygrep` hook, so the pattern is the whole
  hook, and it was verified in both directions: it names no `rev` this file
  holds, and it names those two by line when they are put back.

- **The bytes-like sweep grew a mapping and a tuple.** `retyped` now
  descends into both, which is what `create_outputs`' pairs of keys and
  `scan_outputs`' label cache need. A mapping has its values retyped and
  its keys left alone, and that is the signature rather than the test
  being lenient: `Mapping` is invariant in its key type, and neither a
  `bytearray` nor a `memoryview` is hashable, so `labels` is declared
  `Mapping[bytes, BytesLike]` — bytes is the only one of the three a
  mapping key can be. mypy is what said so.
- **`silentpayments` is in `MODULES`**, so `test_the_sweep_is_whole` holds
  the new entry points to the sweep the way it holds every other.
- **Both detect-secrets baselines were regenerated.** The tree's picked up
  only line-number shifts; the vendored one picked up 68 `Secret Keyword`
  findings, every one of them a `private_key` or `priv_key` field of the
  new BIP352 file, which is what a published vector file is made of.

### Documentation

- **Three statements that were not true, found by an audit of the package
  rather than by a failure.** Each is the kind this repository's own rule
  is about, a comment saying *why* and the why having stopped being the
  reason: `context._randomize` invited a caller to re-randomize "whenever
  it wants fresh blinding", which is the one call that would take the
  README's thread-safety guarantee away — libsecp256k1 requires exclusive
  access to a context to mutate one, so the invitation now carries the
  condition, and the README says the same where a user reads it.
  `silentpayments._array` explained its NULL by "cffi will not make an
  array of length zero", which cffi does quite happily, `keys.pubkey_sort`
  passing one for an empty sequence; the real reason is libsecp256k1's own
  `ARG_CHECK`, and the same wrong reason was in
  `test_scanning_refuses_an_empty_output_list`. CLAUDE.md said the
  sentinel crons "are on different mornings" while the table under it
  showed two on Wednesday and two on the 1st — corrected when the
  cadences were, and the sentence left behind.
- **The prose stops naming `dev` and `master`, which no longer exist.**
  The workflows were corrected when the branches went; the files that
  describe how this repository is worked on were not, so RELEASING.md
  still told a maintainer to merge `dev` into `master` and to read
  `gh run list --commit "$(git rev-parse origin/master)"` — a command
  that now fails on a ref that is gone, in the one file a release is
  executed from. Two of its twelve steps described work that cannot be
  done and are gone: realigning `dev` onto `master` after a release, and
  opening the draft release pull request between the two branches, whose
  job — somewhere to describe the cycle as it lands — the open sections
  of `CHANGELOG.md` and `HISTORY.md` already do. What replaced the
  release merge is stated rather than implied: the release pull request
  is an ordinary one against `main`, and the ninety-two-commit squash of
  0.7.1 cannot recur, every change now reaching `main` in its own pull
  request as it lands. CONTRIBUTING.md, CLAUDE.md, REPOSITORY.md and the
  pull request template follow, and REPOSITORY.md's branch protection
  section describes `main` — where it said "the three checks", the rule
  has named four since `docs` became one of them.
- **Seven README links, the `changelog` metadata url and the Sphinx
  source links pointed at `blob/master`.** They resolve, GitHub
  redirecting a renamed branch, so nothing was broken and the `links`
  sentinel stayed green; the `changelog` one is what an index puts behind
  "Changelog" on the project page, and `docs/source/conf.py` builds every
  "source" link on Read the Docs from the same string. The pre-commit.ci
  badge was the one that had stopped meaning anything: pinned to
  `master.svg`, it answers `passed` for a branch that has not existed
  since the rename and can never turn red again — measured against a
  branch name that never existed, which answers `unknown`.
- **This file's own preamble says where it starts, not what it holds.**
  "Only v0.7.1.2 is here" was true for exactly one release, and v0.7.1.3
  landing under it made it false without anything failing; every release
  after would have done the same. Where the file starts is the fact it
  was reaching for, and that one does not move.
- **Read the docs builds on the interpreter `docs.yml` builds on**, 3.14,
  which is what `.python-version` says. These docs are built twice, once
  for the website and once as a required check, and two interpreters make
  those two different questions -- a docstring that renders under one and
  fails `-W` under the other is found after the merge, on the service
  whose failure is not a check on the pull request. The file already said
  it matches btclib's, and btclib's moved.
- **Two documented cadences the schedules contradicted.** CLAUDE.md said
  "Dependabot is monthly here on purpose", where
  `.github/dependabot.yml` has declared `interval: weekly` with
  `day: thursday` on all three ecosystems since it was moved there to
  match btclib; and RELEASING.md's step 7 said `published` "runs weekly
  on its own", where its cron is `23 6 1 * *` and this file's own v0.8.0
  entry records the move from weekly to monthly. Neither is a claim
  anything checks, which is why both survived the change they describe.
  The CLAUDE.md sentence was making an argument as well as a statement —
  that `latest` covers for an infrequent Dependabot — and the argument
  was the wrong way round: `latest` runs on the Wednesday *before*
  Dependabot proposes on the Thursday, so what it buys is a diff whose
  result is already known. What it covers that nothing else does is
  `[build-system] requires`, resolved at build time and pinned by no
  lock file, so Dependabot never moves it at any interval.

### Packaging metadata

- **`.gitignore` matches a versioned environment, and the sdist stops
  shipping one.** `.venv`, `venv/` and `venv*/` between them do not
  match `.venv-3.10`, which is what `UV_PROJECT_ENVIRONMENT=.venv-3.10
  uv run --python 3.10 --no-cache pytest` creates — the way of trying
  another interpreter that keeps the default environment rather than
  replacing it, and CONTRIBUTING.md now gives it beside the run that
  replaces one. Nothing downstream caught the leftover: uv writes a
  `.gitignore` holding `*` inside the environment it creates, so `git
  status` was clean, while hatchling builds the sdist from the root file
  alone and shipped the directory — 377 paths against 297 and 13,132,264
  bytes against 3,076,714, measured on `38ee75b` with the environment
  present either way (`tar -tzf dist/*.tar.gz | wc -l`), the rest of the
  archive identical. The totals move with the vendored library and the
  difference does not: it is the environment's `bin` and the four files
  beside it, `lib/` being matched already by the Distribution section
  above. `twine check --strict` passed on it; `pyroma --min 10` raised
  `tarfile.AbsoluteLinkError` on `.venv-3.10/bin/python`, the tarfile
  data filter refusing a link to an absolute path, so the packaging gate
  failed on one symlink rather than on the stray paths, which are the
  difference between those two counts. `check-manifest` names every one
  of them — it compares the sdist with what git tracks — and is not in
  the `check` group; the pattern states the same fact where a file
  becomes invisible rather than where an archive is built. It is
  `.venv*/`, in place of the `.venv` beside `venv*/`: a directory of
  that exact name is matched by it, and by the stock `# Environments`
  block above.

## v0.7.1.3

### Documentation

- **The README badges are the ones that can turn red**, in the order the
  reader asks for them: version, downloads, development status, license
  and supported interpreters on the first line; test, lint, pre-commit.ci
  and the documentation build on the second; the repository and the Slack
  channel on the third, "where is the code" and "where do I ask" being the
  two questions a reader has once the first two lines have answered
  theirs. That third line is where the repository link was already, a
  sentence between two horizontal rules of its own; as a badge beside the
  others it needs neither rule, and the plain-text link that read "Browse
  GitHub Code Repository" now names the repository it opens. The badges
  that report no state — `uv`, ruff, mypy, markdownlint-cli2 and
  `pre-commit enabled` — name a choice rather than measure anything, so
  they open CONTRIBUTING.md, which is the file that says how each choice
  is enforced and what the command for it is, rather than sitting inside
  its "Building and testing" section. ruff is three of them, its
  formatter, its linter and its docstring rules being three gates with
  three documentation pages and three ways to fail, where one badge
  announced them as one; `pre-commit` closes that run because it is what
  runs the others, and the repository and Slack badges close the line, a
  contributor wanting both. The alternative text says what each badge
  means — "PyPI version", "supported Python versions", "test workflow
  status" — rather than naming the site that serves the image: it is the
  accessible name of the link, and a flat list of badges has nothing else
  to carry the meaning. btclib and bitcoin-core-rpc carry the same three
  lines and the same CONTRIBUTING.md run, which is what makes the three
  comparable; the badge sets differ only where the projects do, this one
  having no calendar version to declare.
- **`pubkey_from_prvkey`'s two libsecp256k1 calls are two calls for a
  stated reason** (#89). The Design section claimed every function is one
  libsecp256k1 call, without saying that a function returning a key or a
  signature is two: libsecp256k1 hands one back as an opaque object, and
  only a second call serializes it into bytes. `pubkey_from_prvkey` names
  its two — `secp256k1_ec_pubkey_create`, `secp256k1_ec_pubkey_serialize`
  — as the shape every other producer of a key or a signature shares.
- **The MuSig2 section names what already guards a reused nonce** (#91).
  It said the signing state "already lives" in btclib without naming what
  lives there, which read as an open gap rather than a settled fact.
  `btclib.ecc.musig2.sign` and `btclib.psbt.musig2.partial_sign` are named,
  both zeroing the secret nonce on use, which refuses reuse deterministically
  before a second signature exists.

### Import diagnostics

- **A dynamic wheel's `ImportError` says what it tried, and why each
  attempt failed** (#90). `_load_lib` searches the shared object shipped
  beside a dynamic (cffi ABI) build, and silently dropped every rejected
  candidate's `OSError` while doing it — a wheel repaired by `auditwheel`
  or `delocate` can ship more than one match, only one of which is the
  library, so a directory holding a wrong-platform library alongside the
  right one surfaced only "no loadable shared libsecp256k1 found", with
  nothing said about what was there or why it did not load. Each rejected
  candidate's name and error are now kept, joined into the message when
  none loads, and the last one chained as the exception's cause; a
  directory with no matching candidate at all still gets the shorter
  message, that case never having had one to blame. Closes #88.

### Mutation testing

- **A session run ahead of this release, `_load_lib` having changed
  since 0.7.1.2, found one survivor shape on `rejected[-1]`** — six
  mutants of the same index, all reporting `TestOutcome.SURVIVED`,
  because `test_load_lib_unloadable_candidate` checked only
  `isinstance(exc_info.value.__cause__, OSError)`, true of any candidate
  chained, and because with two rejected candidates `rejected[-1]` and
  `rejected[1]` name the same element regardless, one mutant unkillable
  by any assertion at that length. A third candidate, and an assertion
  that the last name in the `ImportError`'s own message is the one
  `__cause__` reports, killed all six: `path.glob`'s order being
  undocumented, the test pins it with `sorted`, the same way this
  project fixes what a test cannot otherwise hold constant about an
  external call. The session that measured that: 667 jobs, 385 skipped
  by the operator filter, 0 survivors of the 282 that ran.

### The gate

- **The copyright-notice hook is retired for ruff's own `CPY001`** (#85).
  `leoll2/copyright_notice_precommit` existed for exactly one check — a
  missing or altered notice at the top of a source file — that
  `flake8-copyright` already does, selectable under this project's
  existing `explicit-preview-rules` gate rather than needing anything new
  turned on: one less repo to pin, one less hook environment for
  pre-commit(.ci) to install. It also needs no `files:` pattern of its
  own the way the retired hook did, widened from `\.py$` to `\.pyi?$` only
  after `stubs/_btclib_libsecp256k1.pyi` kept a pre-MIT header for as long
  as the narrower pattern missed it — ruff lints `.pyi` files by default.
  And it checks whatever files it is given the same way regardless of who
  is asking, unlike the retired hook, which intersected the files
  pre-commit handed it with newly *added* staged files unless given
  `--enforce-all`, silently checking nothing under `pre-commit run
  --all-files` — the exact invocation the lint workflow runs, and the
  incident this file already records above. `notice-rgx` is COPYRIGHT's
  text as one anchored regex rather than a substring search over the whole
  file, the design rationale moving to `pyproject.toml` beside it.

### Dependencies

- **`cryptography` moves to 50.0.0, closing CVE-2026-69247** (#92).
  Dependabot alert #9 (GHSA-g6cj-pr64-35w5, high) flagged 49.0.0, pulled in
  transitively on Linux via `twine`'s `keyring` → `secretstorage`
  dependency, as inside the range vulnerable to a PKCS#7 `EnvelopedData`
  decryption oracle. Neither this package nor `twine` decrypts PKCS#7, so
  the oracle was unreachable here, but there was no reason to stay in the
  vulnerable range. `secretstorage` only requires `cryptography>=2.0`, so
  no other package needed to move with it.
- **Every other locked dependency moves to its latest compatible
  version** (#93): `uv lock --upgrade`, ahead of the `latest` sentinel's
  own schedule rather than waiting for it. Notable moves: `btclib`
  2023.7.12 → 2026.8.7, pulling in a new transitive `bitcoin-core-rpc`
  dependency (both `bench`-group only, no part of `test`, `lint`, `check`
  or the default group), `ruff` 0.16.0 → 0.16.2, `cibuildwheel` → 4.2.0,
  plus patch bumps to `coverage`, `filelock`, `packaging`, `platformdirs`,
  `setuptools` and `virtualenv` among others. No `pyproject.toml` change.

### Packaging metadata

- **`keywords` names what this package wraps and what it reaches**, where
  it said `bitcoin` and `libsecp256k1` and left the searchable name of the
  curve out along with every wrapped module: `secp256k1`, `cryptography`,
  `python-bindings`, `cffi`, `ecdsa`, `schnorr`, `bip340`, `ecdh`,
  `ellswift`, `public-key-recovery` and `rfc-6979`, which is the nonce
  `dsa.sign` uses. `RFC-6979` is spelled lowercase, as a GitHub topic has
  to be: the list is the repository's topics in the same order, and one
  spelling across the two is what lets them be compared. The order is by
  relevance rather than alphabetical, PyPI showing keywords as the metadata
  gives them and GitHub sorting its own.
- **`musig2` and `bip324` are in that list, and neither is a wrapped
  module.** The vendored library is built with
  `SECP256K1_ENABLE_MODULE_MUSIG` and `secp256k1_musig.h` is among the
  headers the cdef is made of, so all of `secp256k1_musig_nonce_gen`,
  `_nonce_agg`, `_nonce_process`, `_partial_sign` and their neighbours are
  reachable through the `lib` this package exposes -- what MuSig2 has no
  module for is the session its two rounds need, which is the reason
  README's Design section gives for leaving one out. `bip324` is the
  `ellswift` module beside it: the encoding and the x-only ECDH that BIP's
  handshake needs of its keys, and not its transport, which is a cipher and
  a framing layer this package has no part of. The comment beside the list
  states both limits, so a keyword found on PyPI leads to what is here
  rather than to what a reader would assume from the name.
  `elliptic-curves` is the one candidate left out: this is one curve, and
  `secp256k1` names it.
- **the repository now carries those entries as its topics**, where it
  carried none: the pull request above could write the list and not apply
  it, the repository settings living outside the tree. REPOSITORY.md has
  them, as it has every other setting nothing in the tree can recover, and
  with the command that diffs the two lists and exits nonzero when they
  have drifted apart — sorted on both sides, GitHub returning an order of
  its own.
- **this file relaxes MD024 (no-duplicate-heading) for itself**, a group
  heading repeating under every release that has an entry in that group:
  the rule reads that repeat as the accident it usually is, and
  `siblings_only` is what tells the two apart, a duplicate under one
  release heading still failing. It is a `markdownlint-configure-file`
  comment here rather than a line in `.markdownlint.jsonc`, which is
  shared with btclib and bitcoin-core-rpc and says itself that a rule one
  file needs belongs to that file; bitcoin-core-rpc's CHANGELOG.md carries
  the same comment.

## v0.7.1.2

Grouped, and the order runs from what a caller sees to what only
maintainers do. The wrapped
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
is the same 0.7.1 (1a53f49). What the public API gained is one function
and two `compressed` flags; what it lost is `recovery.COMPRESSED` and
`ellswift.COMPRESSED`, two copies of a flag macro that `keys.COMPRESSED`
still declares — the one removal here, and the one entry a caller
importing either has to act on. What it also gained is a wider door:
every argument that takes octets takes a `bytearray` and a `memoryview`
as well as `bytes`, which is a widening and breaks nothing. Three things
changed behaviour: the text of one error message, the class
`keys.serialize` raises for an argument no valid caller passes, and the
exception a wrong *type* meets, which is now the boundary's and names
the argument instead of cffi's a call later. Each has its entry below.
Neither file counts its entries:
`grep -c '^- '` does that, whereas a stated number is a line every open
branch has to edit.

### What the boundary answers

- **`keys.pubkey_from_prvkey` is the public key of a private key, in
  either serialization** (#41, #68). One `secp256k1_ec_pubkey_create`
  plus one `keys.serialize`, which is the shape `pubkey_negate`,
  `pubkey_tweak_add`, `pubkey_tweak_mul`, `pubkey_combine` and
  `pubkey_sort` already had — a C operation on a `secp256k1_pubkey`, then
  the serialization with its flag as an argument. Generator
  multiplication was the exception: `mult.mult_` wrote that serialize
  inline with the flag as the literal `2`, so the one producer whose
  input is a private key rather than a point was also the one that could
  not answer the compressed form `keys`' own docstring promises. Put
  structurally, the package could create a `secp256k1_pubkey` from a
  private key, and could serialize one compressed, and never let the same
  caller do both: `serialize` takes a pointer only `parse` hands out,
  that is, bytes already serialized. `mult_` is the `compressed=False`
  case of the new function now and has lost the inline serialize, the one
  duplication of `serialize` the package had, so the API gains a name
  while the code at the cffi boundary shrinks. What it saves a caller who
  had been composing it, measured per call over 2000 random keys, best of
  nine: 7.67 µs, against 7.75 for the byte slice btclib ships, 8.13 for
  `keys.serialize(keys.parse(mult_(q)))` — which pays a
  `secp256k1_ec_pubkey_parse` to undo a serialization the same library
  has just done — and 8.90 for the composition through the coordinates,
  which turns 64 bytes into two ints and re-proves on curve a point
  libsecp256k1 had just produced. Against the slice that is 0.8%, and it
  was not treated as the argument: the argument, with its alternatives,
  is in #41 — the compressed encoding stops being written outside the
  wrapper. btclib reads `sec[64]` rather than `sec[-1]` so that a 33-byte
  answer raises instead of passing off a byte of x as a parity, and keeps
  a test pinning this package's 65-byte serialization from outside it;
  making `mult_` the uncompressed case of one function is what keeps that
  contract true by construction rather than by a downstream test.
  Validated against what is published rather than against the bindings:
  the BIP340 vectors' *public key* column is the x of this call for every
  vector carrying a secret key, 1G is pinned in both forms against the
  generator of SEC 2 v.2 section 2.4.1 and 6G for the odd y no smaller
  key exhibits, and the 128-key sweep compares what libsecp256k1
  serializes with the compression `tests/test_properties.py` composes
  itself, both parities occurring across it. The README quickstart, which
  had been composing `keys.serialize(keys.parse(mult.mult_(prvkey)))` on
  the package's own front page, is the one call now.
- **The `ValueError` of a generator multiplication names a private key**
  where it said scalar, which is the one behaviour a caller can see
  change. `secp256k1_ec_pubkey_create` calls its argument a seckey and is
  what refuses anything outside `[1, n-1]`, so the message names what the
  library refused rather than what the mult module calls it; `mult_`
  answers exactly the 65 bytes it did, opening with `0x04`, and
  `tests/test_core.py` asserts the new text so that the next change to it
  is deliberate.
- **`keys.serialize` raises what libsecp256k1 reported, and takes it off
  the thread** (#73). It is the one wrapper whose argument is a
  libsecp256k1 object rather than bytes, so it is the one place where
  nothing can be checked before the call and a precondition is
  libsecp256k1's to violate: a NULL pointer, or a `secp256k1_pubkey`
  nothing has written to, reached the illegal-argument callback. What
  came back was `RuntimeError("point serialization failed")` — the class
  reserved here for what no input can provoke — while the message
  libsecp256k1 had just written stayed recorded on the thread. The next
  `context.check()` found it and raised it, and that caller is the MuSig2
  one going through `lib`: they were told `pubkey != NULL` about a call
  they never made. That is what `test_check_clears_what_it_reported`
  exists to prevent, and it was reachable from the public API.
  `serialize` calls `check()` on the failing branch now, which raises the
  message as the `ValueError` a caller's mistake is and, raising it,
  clears it; the `RuntimeError` remains for a failure that reported
  nothing. Two docstrings had claimed the case away — `check()`'s own,
  and `test_illegal_argument`'s *"which the bindings' own wrappers cannot
  do"* — and describe it instead.
- **An argument is checked for its type where it is checked for its
  length** (#73, #74), those being one question about a bare pointer.
  `len` answers for a `bytearray` and a `memoryview` as readily as for
  bytes, so both passed every size check and reached cffi, which refused
  them a call later in its own words and about a ctype — `initializer
  for ctype 'unsigned char *' must be a cdata pointer` — naming neither
  the argument nor what was wrong with it; a `float` came back as
  `object of type 'float' has no len()`; and `_scalar.scalar`, annotated
  `-> bytes`, returned the bytearray it was handed. `_scalar.octets` is
  that one check, and every size check across the eight wrapper modules
  is now that call. `keys.pubkey_sort(pubkey)` — one key where a
  sequence of them goes, which bytes being a sequence made silently
  wrong — now says `the public key must be bytes, not int`.
- **And what crosses is octets, not `bytes` alone** (#74): a `bytearray`
  and a `memoryview` are converted rather than refused, and `BytesLike`
  is what the signatures say. #73 had refused them, on the argument that
  converting would widen what every signature promises; the answer is
  that the signatures widened. They are not the leniency a short value
  is — each states a value *and* a width, so nothing has to be
  disbelieved and nothing supplied, which makes them a narrower door
  than the `int` this package has always taken, whose 32-octet width is
  the curve's rather than the caller's. And a caller who holds a secret
  in memory they can overwrite, which is the reason to want a mutable
  buffer and is what SECURITY.md now describes this package doing with
  its own, had been meeting a `TypeError` for it. The conversion is a
  copy taken at the boundary, never a pass-through, so overwriting that
  buffer cannot change what libsecp256k1 is about to read.
  `tests/test_bytes_like.py` drives every entry point taking such an
  argument with each of the three types and asserts one answer, which is
  what makes a call site that checks without assigning fail there rather
  than in a caller's code; a `test_the_sweep_is_whole` holds the list to
  what the modules export, so a function added and not swept is an
  absence that fails.
- **A `bool` is refused where a scalar goes** (#73). `isinstance(True,
  int)` is true, so `True` was the scalar 1 and `False` the scalar 0:
  `keys.prvkey_verify(False)` answered False, the correct verdict on
  zero and not distinguishable from the correct verdict on whatever was
  meant, and `keys.pubkey_from_prvkey(True)` answered the generator.
  That is what separates it from a `float` in the same place, which
  raised then and raises now — the acceptance was invisible in the
  answer, and invisible to mypy too, `bool` being a subtype of `int`.
  For the scalars alone: `recid`, `party` and the y parity are flags
  whose domain is `{0, 1}`, and a bool there is the 0 or 1 it is.
- **The libsecp256k1 buffers a secret passes through are overwritten**
  (#73). SECURITY.md records the python side as inherent, and it is: a
  `bytes` is immutable, so what a caller hands in and what is handed back
  stay until the collector gets to them. The copy in the middle is not
  that — it is memory cffi allocated and this package owns, it is
  writable, and nothing outside these wrappers sees it, so leaving a
  private key in it was an omission rather than a limit. Read out and
  zeroed now: the keys of `keys.prvkey_negate`, `prvkey_tweak_add` and
  `prvkey_tweak_mul`, the taproot signing key of
  `xonly.prvkey_tweak_add`, the shared secrets of `ecdh.shared_secret`
  and `ellswift.xdh`, and the `secp256k1_keypair` of the two BIP340
  signing calls and of the taproot tweak, wiped in a `finally` because
  `_aux_rand32` can raise between its creation and the signature. The
  length is asked of `ffi.buffer` rather than of `ffi.sizeof`: on a
  `secp256k1_keypair *` the latter answers 8, the size of the pointer,
  and wiping 8 octets would clear the first quarter of a private key and
  report success — written that way the new test fails. One copy taken
  back, not safety, and SECURITY.md says which.
- **`recovery.recover` and `ellswift.decode` answer in either
  serialization** (#73), through `keys.serialize` rather than through a
  copy of it. Both wrote the same block — a `char[33]`, a length derived
  from it, the `SECP256K1_EC_COMPRESSED` flag redeclared at the top of
  the module, and a comment pointing at `keys.serialize` for the
  reasoning, which was the argument for calling it. Each takes the
  `compressed` flag every producer in `keys` has, defaulting to the 33
  octets they always returned; reaching the uncompressed form meant
  `keys.serialize(keys.parse(...))` in the caller before. The two
  duplicated `COMPRESSED` constants go with the block, `keys.COMPRESSED`
  being the one that carries the comment explaining why a flag macro is
  written out at all.
- **Three smaller things the same audit turned up** (#73). `noncefc` was
  a typo of `noncefp`, which is what the header calls the nonce function
  pointer, in both signing modules. `ndata`, annotated `bytes | None`,
  was reassigned to `ffi.NULL` before being passed — mypy allowed it only
  because `ffi` is `Any` — and has a name of its own now, with the
  comment saying why a python nonce function is not offered: it would put
  the secret through a python object on every call from inside the
  signature. And `test_safe_abort` created a context on every run and
  never destroyed it, with the flag `769`, which is `SIGN|VERIFY`,
  deprecated since libsecp256k1 0.2 as `context.py`'s own comment says.

### The documented boundary

- **`xonly.tweak_add_check` says what it does with a tweaked key that is
  no point** (#73). Its contract promised `ValueError: if either key is
  not 32 bytes or not a valid x coordinate`. Only the internal key is
  parsed; the tweaked one is compared against the serialization of the
  recomputed point, so 32 bytes which are the x coordinate of nothing
  return False. That is the right behaviour — bytes that are no point are
  the tweak of nothing, and comparing rather than parsing is the whole of
  what this saves over recomputing the tweak — and Returns now says it,
  with Raises naming the key that really is parsed. Nothing in the gate
  could have caught it: `pydoclint` checks that a `Raises` section is
  there, not that it is true, which is the concession recorded below, and
  the suite had asserted the two keys only where both were points.
- **Every function of the package documents its arguments, its return
  value and what it raises.** What lengths are accepted, what is refused
  rather than padded, which failure is a `ValueError` and which a
  `RuntimeError`: that is the most valuable thing this package has, and
  it was prose in the README's *What the boundary checks*, several
  hundred lines away from the functions it applies to. For a package
  shipped as a compiled wheel that was the whole of it — there is no
  source beside the extension for a reader of `help()` or of an IDE
  tooltip to fall back on. The sections are Google style, which the
  `napoleon` already enabled in `docs/source/conf.py` renders, so the
  published reference gained them at the same time. `mult.mult_` and
  `mult.mult` carried the same docstring verbatim — *"Multiply the
  generator point."* — while one returns 65 uncompressed bytes and the
  other a `tuple[int, int]`; each now says which.
- **A `pydoclint` hook holds it**, over `btclib_libsecp256k1` only, with
  its configuration in `pyproject.toml` beside ruff's. It asks for an
  `Args` entry per parameter and a `Returns` section, which is what
  ruff's `D` rules cannot do: they check that a docstring exists, not
  what it says. Two settings carry their reasoning where they are set.
  `skip-checking-short-docstrings` is off, against the tool's default,
  because the default skips a docstring that is only a summary line —
  which is exactly the state this ends, so with the default the gate
  would hold nothing. `skip-checking-raises` is on, which is the one
  concession: pydoclint compares a `Raises` section with the `raise`
  statements of the *body*, and these wrappers raise mostly through what
  they call (`_scalar.scalar`, `keys.parse`, `keys.serialize`), so the
  check would force each docstring to document its own body instead of
  its contract. `Raises` is therefore written and reviewed, not gated;
  ruff's `DOC` rules have the same limitation, so the choice was not
  between tools. Verified by handing it something bad: an argument added
  to `tagged_sha256` and left undocumented is `DOC101` and `DOC103`.
- **The README opens with a Quickstart**, which did not exist: sign and
  verify, ECDSA and BIP340, for someone who has just typed
  `pip install`. It is written as doctests, so it is executed rather
  than only read.
- **Every example is executed**, by `tests/test_examples.py`, over every
  module of the *installed* package and over `README.md`. Through the
  standard library's `doctest` rather than pytest's `--doctest-modules`,
  and the reason is what this package is: `testpaths` is `tests`, and
  widening it to the package would collect the *source* tree — right
  locally, where the extension is an editable build of it, and wrong in
  the wheel jobs, where what has to be exercised is the module inside
  the installed wheel. Importing the package by name gets whichever of
  the two is installed, on every one of the kinds of wheel this project
  ships. The price is that an example has to be deterministic: fixed
  keys, and a verification rather than a signature wherever the value
  depends on randomness that is not pinned. Verified by breaking one
  expected value in the README and one in a docstring, and watching both
  tests fail.
- CONTRIBUTING.md's *Documentation and comments* says both of the above,
  since that is the file contributors read.

### What the wheels are built with

- **Two failures of the build hook say what went wrong** (#75).
  `get_ext_object` raised a bare `RuntimeError` -- no message at all --
  for a `cffi_modules` entry naming an object its script does not define;
  it now names both halves of the entry, which is the only thing that can
  be wrong there, and matters the more because the line is excluded from
  the coverage measure. And `dynamic_platform_tag` subscripted a dict
  literal of three Windows architectures, so a fourth answered `KeyError`
  -- `win-arm32`, which `scripts/cffi_build.py` does aim CMake at, being
  the one the two files disagreed about. It is in the map now, and
  anything else raises a `RuntimeError` naming the architecture, which is
  the policy `shared_library_extension` beside it already had.

- **The static Unix extension is compiled with the interpreter's own
  `CFLAGS`.** `CC`, `CFLAGS`, `CCSHARED` in that order is what
  `customize_compiler` composes for the extensions the interpreter
  builds for itself; `CFLAGS` was dropped entirely, which was two
  defects at once. The cffi glue was compiled with **no optimization**,
  unlike everything CMake builds beside it — on macOS `CFLAGS` carries
  `-O3 -DNDEBUG`, and the `-fPIC` that lives there rather than in
  `CCSHARED`. And on a **universal2** interpreter `-arch x86_64 -arch
  arm64` lives in `CFLAGS` while `LDSHARED` carries them too, so the
  object was compiled single-arch and linked dual-arch: precisely the
  configuration `target_architecture_options` exists to support, and one
  nothing exercises, CI building one architecture per runner. Measured
  by building the static wheel with and without the change, macOS arm64,
  cp314: the object goes 218 104 → 502 944 bytes, `-g` being in `CFLAGS`
  too, and the bundle 1 519 640 → 1 480 072, which is `-O3` reaching the
  compiler. Nothing is filtered out of the flags: on macOS `sysconfig`
  has already run them through `_osx_support`, which is what rewrites an
  `-arch` the toolchain cannot build and an `-isysroot` pointing at a
  missing SDK. What was missing was the splitting — `CCSHARED` went in
  as a single argv element, empty on a mac (clang tolerates it, gcc
  reads it as a missing input file) and wrong the day it holds two
  flags — so `CC`, `CCSHARED` and `LDSHARED` all go through
  `shlex.split` now.
- **A wheel whose extensions disagree on static or dynamic is refused.**
  The tag is a property of the whole wheel, so a wheel holding both
  kinds has no tag that is true of it: `py3-none-<platform>` over a
  `cpNN` extension installs on any interpreter of that platform and
  fails to import on most of them. It used to print and carry on.
  Nothing downstream inspects a tag against the contents it labels,
  which is the argument for refusing rather than reporting, on the one
  place in the build backend where a silent fallback produced a wrong
  artifact instead of a failed build. The running flag it replaces also
  caught one of the two orders only: it started `True` and was cleared
  by a dynamic module, and the message was printed by a *static* module
  finding it already cleared — with the modules the other way round the
  wheel came out `py3-none` with a static extension in it and nothing
  said so at all. A set of the modes has no order to get wrong, and its
  empty case is the same failure from the other side: `pure_python`
  cleared and no extension in the wheel. Verified by planting
  `{True, False}` before the check and watching the build stop, with a
  control build before and after.
- **The dynamic-wheel command documents its deployment target.** A
  dynamic wheel compiles no extension, so nothing derives its platform
  tag from a toolchain: without `MACOSX_DEPLOYMENT_TARGET`,
  `hatch_build.py` falls back to `platform.mac_ver()` and the documented
  command produces `macosx_26_0_arm64` on a macOS 26 machine — a tag pip
  refuses on every older macOS the file would in fact have loaded on.
  Documented rather than defaulted in `hatch_build.py`, and the reason
  is that the tag is not the only thing the variable decides: CMake
  reads it too, so a default applied to the tag alone would claim a
  floor the vendored library was not built for, which is worse than the
  narrow tag. Left unset the two agree. Measured both ways on macOS 26
  arm64: `macosx_26_0_arm64` without it, `macosx_11_0_arm64` with
  `MACOSX_DEPLOYMENT_TARGET=11.0`.

### Packaging metadata

- **The classifiers say what the package is.** `Operating System :: OS
  Independent` said the opposite of a package whose whole purpose is
  platform-specific compiled wheels; it is replaced by the three systems
  they are built for, `POSIX`, `MacOS` and `Microsoft :: Windows`.
  `Typing :: Typed` was absent although `btclib_libsecp256k1/py.typed`
  is in every wheel and the typed cffi boundary is the design point
  README.md leads with; it is the classifier PyPI users filter on.
  Checked on the built sdist, which is what the `check-dist` job rates:
  `twine check --strict` passes and `pyroma --min 10` still says 10/10,
  so the ratchet is unmoved.

### External vectors

- **The vendored-vector re-checker reports a path upstream has deleted,
  rather than raising on it** (#75). `repos/{repo}/commits?path=` answers
  `[]` with a 200 when no commit touches that path any more -- renamed,
  moved or deleted -- and `(commit,) = json.loads(...)` unpacked one
  commit out of that. The `ValueError` took `find_drift` down with it and
  `report` was never reached: the monthly run turned red and no issue was
  opened, which is the one outcome the workflow exists to prevent, on the
  one drift a vendored file nobody re-reads would otherwise hide.
  `_latest_commit` answers None there now, `Drift` carries a
  `path_is_gone` reading that encoding in one place, and the issue body
  and stdout say GONE with the reason instead of naming a tip that does
  not exist. Called with no README, or two, it prints its usage on stderr
  and exits 2, where `Path(args[0])` had answered `IndexError: list index
  out of range` about a list the caller never saw. btclib's copy of this
  script is the same code and has the same fix, with the tests: this
  repository has no test module for it, `.github/scripts` being outside
  the coverage source here, so what holds it is btclib's suite and the
  hand check in the session log.

- **ellswift is held to BIP324's published vectors.** The tests encoded,
  decoded and agreed with themselves, which says nothing about the map
  being the one BIP324 defines: two wrong implementations of one
  function agree with themselves too. `ellswift_decode_test_vectors.csv`
  pins every published `(ellswift, x)` pair, the degenerate cases among
  them — `u` or `t` zero, `u**3 + t**2 + 7` zero, and the vectors landing
  on x2 or x3 rather than x1. Only x is compared: BIP324 defines the map
  into a field element, so the y libsecp256k1 recovers with it is a fact
  about the library, and the prefix comes out `02` for some vectors and
  `03` for others. `packet_encoding_test_vectors.csv` pins
  `ellswift.xdh`, the path this module exists for and the one nothing
  independent checked: `in_priv_ours` and the two encodings to
  `mid_shared_secret`, with `in_initiating` settling the argument order
  — ours first with `party = 0`, theirs first with `party = 1` — and the
  same rows pinning `decode` again through `mid_x_ours` and
  `mid_x_theirs`. Bitcoin Core's own `ellswift_xdh` vectors were not
  needed for it. `xswiftec_inv_test_vectors.csv` is deliberately not
  vendored: libsecp256k1 exposes no entry point for the inverse map,
  `secp256k1_ellswift_encode` choosing its case from the randomness it
  is handed, so there is nothing here those vectors could be compared
  against.
- **MuSig2 aggregation is held to BIP327's vectors.** The MuSig2 test
  verified an aggregate signature against an aggregate key these
  bindings computed, which validates the round trip and not the
  aggregation: a wrong-but-self-consistent key or nonce aggregation
  passes it unchanged. Four files pin the four steps — the aggregate key
  with its error cases, the aggregate nonce with three invalid public
  nonces, the published partial signatures, and the aggregate signature
  with the tweaked taproot cases, which is then verified as a plain
  BIP340 signature of the *tweaked* key. Two limits are recorded rather
  than left to be rediscovered. The signing direction is not drivable at
  all: libsecp256k1 has no parser for a serialized secret nonce, by
  design — a secnonce that can be loaded is a secnonce that can be
  reused — so the `sk` and `secnonces` of `sign_verify_vectors.json`
  have no entry point, and what is pinned is the verification, which
  reads the same equation from the other side. And two valid cases are
  an empty message and a 38-byte one, which BIP327 allows and
  `secp256k1_musig_nonce_process`, taking a `msg32`, cannot be handed.
  `key_sort`, `nonce_gen`, `tweak` and `det_sign` are not vendored, each
  for a reason `tests/README.md` gives.
- **`ssa.sign_custom` is signed against the only external values it
  has.** The vendored BIP340 csv gated signing on `len(msg) == 32`, so
  rows 15 to 18 — messages of 0, 1, 17 and 100 octets, each with a
  secret key and an `aux_rand` — were verified and never signed. They
  are exactly the domain of the feature 0.7.1 introduced, and without
  them it was tested only against this package's own output, which
  CONTRIBUTING.md says proves nothing. Every row carrying a secret key
  now goes through `sign_custom`, and the 32-byte ones through `sign` as
  well: that `sign_custom` answers a 32-byte message with the signature
  `sign` returns is itself part of what the vectors check.
- **Recovery ids 2 and 3 are exercised, and so is a high-s signature
  through recovery.** `recovery.py` accepts `recid in range(4)` and
  every test fed it 0 or 1, so half the accepted domain reached
  libsecp256k1 from no test. The high bit says the x coordinate of the
  nonce point was reduced modulo the order on the way into r, and that
  recovery has to add the order back before decompressing it. No search
  finds such a signature — `x(kG)` lands in `[n, p)` with probability
  about `2**-128`, and aiming a `k` there is the discrete logarithm
  problem — so the point comes first and the signature is built around
  it, which needs no `k`: recovery is `r**-1 (sR - eG)`, an equation in
  R and not in its logarithm. The x is `n + 2`, the smallest on-curve
  value above the order, which the test proves rather than asserts, `n`
  itself being on the curve and giving `r = 0` while `n + 1` is a
  quadratic non-residue. Nobody holds the private key of that signature
  and nothing needs to: nothing publishes recid 2/3 vectors, so the
  recovered key is compared against the same equation computed in
  python, by point arithmetic the test file now does, which is the
  standard `der_decode` already set there. The second half is `to_der`,
  which documents that it does not normalize s and was held to it by
  nothing: negating s is the malleability ECDSA has, giving a second
  valid signature under the same key with the parity of the nonce point
  flipped, so it is the *other* recovery id that answers it; `to_der`
  keeps the high s, `dsa.verify` refuses what it produced, and
  `dsa.normalize` gives back exactly what `dsa.sign` returns.
- Every vendored file is pinned to a commit and a git blob SHA-1 in
  `tests/README.md`, as the ones before them are, so the monthly
  `vendored-vectors` workflow re-checks them.

### Mutation testing

- **The inert third of a session is skipped before it runs, not counted
  after it does** (#70). Every module here opens with
  `from __future__ import annotations`, so a mutant of the `|` inside a
  `bytes | int` signature — `bytes >> int` and ten more — is unreachable
  by any test, nothing ever evaluating the annotation as an expression.
  Unfiltered, a session paid the whole suite for that shape on 352 of 777
  mutants before reaching the 13 that were real: 365 survivors in five
  minutes, against 352 skipped and the same 13 in two once
  `[cosmic-ray.filters.operators-filter]` excluded the `BitOr` family by
  operator — in `bindings.toml` itself, which already says what is
  mutated and what judges it, rather than a `# pragma: no mutate` on each
  of the 26 lines it would otherwise mark and on every one a later
  signature adds. `cr-rate` cannot report a filtered session: its
  `is_killed` counts a skip as a kill, so it divided by every enumerated
  mutant and read 1.67%, where the 13 that survived the 425 that ran are
  3.06% of them. `.github/scripts/mutation_counts.py` prints killed,
  survived and skipped instead, with the rate over what actually ran, and
  fails on a worker outcome that is no verdict at all rather than
  reporting it as either.
- **Two of the three real shapes a session survivor list held are
  answered in the code instead of read past** (#71). Six of the 13 #70
  measured were an output buffer whose size was written more than once —
  a serialization, the capacity handed to libsecp256k1 and the length
  unpacked back, as up to three separate literals where `keys.serialize`
  already wrote it once; the other seven were `secrets.token_bytes(32)`,
  a length not observable in an aux value or a shared secret hashed
  before use. `ffi.sizeof` now derives every buffer size across the
  eighteen call sites in eight modules that used to write it by hand, and
  where the randomness is copied into a fixed-size array instead of hashed
  — `ssa.sign_`'s `char[32]` — the longer half of that pair already died
  on cffi's own bound, `ffi.new` there refusing 33 octets and taking 31.
- **A third, unrelated shape survived a private module's own size
  check.** `_scalar.octets`'s `len(value_bytes) != size` mutated to
  `is not` passed the whole suite, no wrapper here ever asking for a size
  past CPython's cached range for small ints, where an equal pair is the
  same object and the two operators cannot be told apart.
  `test_octets_size_check_compares_by_value` drives the check directly at
  300 octets — past the cache, and past every size a wrapper reaches —
  where `!=` and `is not` stop agreeing.

### The gate

- **The README quickstart is executed again** (#74). Fencing the
  indented blocks put the closing ``` flush against the last line of
  each example, and doctest reads the line after an example as the
  output it expects: three of the ten stopped passing, two of them
  expecting `True` followed by a fence. A blank line before each closing
  fence is what says an example's output ends there. The suite caught
  it, which is what it is for — `test_the_readme_examples_run` was added
  in this same release because *"an example nobody runs is documentation
  that stops being true silently"* — and this is the first thing it
  caught. `markdownlint-cli2` stays clean over the result: a blank line
  inside a fenced block is not a blank line around one.
- **The benchmark measures btclib's python arithmetic, which it had
  stopped doing** (#75). Two of its eight rows are labelled *"through
  btclib's pure python arithmetic"*, and `dsa.verify_` and `ssa.verify_`
  delegate to these very bindings for secp256k1 with sha256 -- which is
  exactly the fixture the script sets up. Traced, the two rows called
  `btclib_libsecp256k1.dsa.verify` and `.ssa.verify`: the same C as the
  package's own rows with a python wrapper in front, 22.5 and 24.9 us
  against 13.9 and 13.8, where the python path is 1214 and 1270.
  `python_arithmetic_only` turns the dispatch off before the rows run,
  and it does so in three namespaces because `_libsecp256k1_applicable`
  is imported *by name* into `ecc.dsa`, `ecc.ssa` and `curves.curve`:
  patching one leaves the other two delegating, which is a partial patch
  that still measures C and still looks like python -- the first
  measurement taken for this entry was wrong that way. The two rows drop
  to `mult=1`, a thousand calls of a millisecond being a second of clock
  where they had been sized for twenty microseconds, and the loop reads
  `perf_counter` rather than `time`, a wall clock being the one thing a
  benchmark should not use.

- **The entropy detectors of `detect-secrets` run over the tree.**
  `.secrets.baseline` was generated with `HexHighEntropyString` and
  `Base64HighEntropyString` off, and it is the baseline that decides
  which plugins run — so the two were off *everywhere*, not just over
  the two json vector files that motivated turning them off. A
  high-entropy credential in a workflow, in `scripts/` or in a package
  module was seen by nothing, on a repository whose plan gives it no
  generic secret scanning server-side and where this hook is the
  surrogate. The reason not to exclude those files stands — an AWS key
  planted in one of them went unseen while they were excluded — so the
  split is by plugin set rather than by scan, one baseline each, and the
  hook runs twice: `.secrets.baseline` with every plugin over everything
  else, and `.secrets.vectors.baseline` with the entropy pair off over
  `tests/*.csv` and `tests/*.json`, which are 64-character hex and
  nothing else, so with the detectors on a new vector is
  indistinguishable from a new secret. The keyword, private key and
  provider-token detectors — the ones that caught the planted AWS key —
  keep running over them. The first hook's exclusion is the filter its
  own baseline records, so the pattern is stated once, in the second
  hook's `files`; it names the second baseline too, that one being
  40-character hashes by the hundred, and `detect-secrets` skipping only
  the baseline `--baseline` points at. The newly recorded findings were
  reviewed one by one: hex constants written inline in
  `tests/test_vectors.py` and `tests/test_properties.py`, and
  `"-DSECP256K1_BUILD_BENCHMARK=OFF"` <!-- pragma: allowlist secret -->
  in `scripts/cffi_build.py`, which the base64 detector reads as a
  secret. Verified by planting a 64-character hex constant in a test
  module and an AWS access key in a vector file, and watching each hook
  name its own.
- **The copyright-notice hook reads files at all.** Without
  `--enforce-all` the tool intersects the filenames pre-commit hands it
  with `git diff --staged --name-only --diff-filter=A`: newly *added*
  staged files, and nothing else. On a clean checkout that set is empty,
  so `pre-commit run --all-files` — the run the `lint` workflow makes,
  and the one that gates a pull request — was checking **no file at
  all**, whatever the pattern matched. The hook had been green since it
  was added because it never read a file. `files` is `\.pyi?$` now, one
  extension wider, `stubs/_btclib_libsecp256k1.pyi` being a source file
  of this project — named in `mypy_path`, force-included in the sdist.
  With both fixed exactly one file failed: that stub, whose header was
  still the pre-MIT btclib one, five lines about copying and propagating
  where `COPYRIGHT` has two about the MIT license. The two commits that
  shortened the header and lowercased the `(c)` moved every `.py` and
  could not have moved this one, which is the whole argument for the
  hook. Verified by stripping the notice from the stub and from
  `btclib_libsecp256k1/mult.py` and watching it name both.

### The release path

- **A release tag that is not on `master` fails before anything is
  built.** CONTRIBUTING.md and RELEASING.md both say a release is a tag
  on the merge commit on `master`, and nothing enforced it. The
  deployment tag policy of the `pypi` environment does not: it admits
  the ref pattern `v*`, so a tag on a branch head, on an old `dev` state
  or on a fork-synced commit reaches the environment exactly as the
  release tag does, and the reviewer approving sees the tag name rather
  than its ancestry. GitHub matches a ref pattern and not an ancestry,
  so there is nothing to tighten there; `version-check` refuses a tagged
  commit that is not an ancestor of `origin/master` instead. Its
  checkout takes the whole history for it, and the step reads
  `origin/master` rather than fetching one of its own, so a missing
  `origin/master` fails the step, which is the safe way round.
  REPOSITORY.md and RELEASING.md both stated the tag policy without
  saying what it does not cover, which is how it comes to read as this
  check; both now say which one holds which half.
- **The `HISTORY.md` section is checked before the matrix builds.**
  Three of the release invariants were checked in `version-check`; the
  fourth was discovered in `github-release`, after PyPI had accepted the
  upload, as a `::warning::` with generated notes as the fallback —
  correct there, there being nothing left to stop, and no use at all as
  the place an omission is found. The same `awk`, on the same push path
  as the tag comparison. The fallback downstream stays: it covers a
  release deleted by hand and recreated.
- **Every attempt of a rehearsal gets a version of its own.** The
  suffix was `.dev<run number>`, unique per dispatch and identical
  across the re-runs of one, and the collision surfaced as a TestPyPI
  400 after the three-quarters of an hour the matrix takes.
  `github.run_id` does not help — GitHub's own wording is *"This number
  does not change if you re-run the workflow run"* — so it is
  `run_number * 100 + run_attempt`, computed in `version-check` rather
  than in the `with:` expression, expressions having no arithmetic and
  concatenation being unique only while the two digit counts line up.
  The two digits reserved for the attempt are checked in the same step
  rather than assumed. The discipline that stood in for the fix,
  *"dispatch a fresh run instead"*, is deleted from `release.yml` and
  from RELEASING.md.
- **The release path stays out of the branch concurrency groups.**
  `github.ref` inside a called workflow is the *caller's* ref, so a
  rehearsal — a `workflow_dispatch` of `release.yml` on a branch, which
  is what RELEASING.md prescribes — computed the very groups a push to
  that branch or a direct dispatch of `test.yml` computes, and with
  `cancel-in-progress` one killed the other either way round. Both
  reusable workflows take a `concurrency-suffix` input now and
  `release.yml` passes one. A tag run was already unique and stays so; a
  second rehearsal of the same branch still supersedes the first.

### CI

- **`PYTHON_VERSION` and `OS_NAME` are gone from the two test jobs.**
  Nothing read either one, and in a workflow where every choice carries
  its reasoning, dead configuration reads as load-bearing: the next
  person to refactor those jobs preserves it because it looks
  deliberate. Both values are already in the job name, which is where a
  reader of a failed run looks for them.
- **The matrix was cut to `ubuntu-latest` and CPython 3.14 for the
  duration of this work, and restored at the end.** GitHub Actions was
  degraded on the day, and the pull requests of this release were merged
  without waiting for it; the cut kept the runs that did start cheap and
  the red cells attributable. The restoring pull request is the first
  one that runs the matrix over any of it, which is why it is the one
  that has to be read rather than merged on sight.

### Issues closed without a change

- **#23, `ssa.verify` and the parity of a 33- or 65-byte key**, and
  **#24, entropy arguments left-padded**: both were fixed by `9563ebb`,
  the 0.7.1 release, which landed after the issues were filed.
  `ssa.verify` takes the 32-byte x-only key and only that; the four
  entropy arguments are 32 bytes or `None`, with `is None` rather than
  truthiness, so `b""` raises where it used to mean "not supplied". Both
  are pinned by tests.
- **#22, the per-platform test jobs as required status checks**: the
  aggregating `tests-passed` job exists and is on `master`, and the
  required contexts are `tests-passed`, `Lint and type-check` and
  `CodeQL`, each bound to an `app_id`. The five matrix-derived contexts
  are gone, and REPOSITORY.md carries the `gh api` call that restores
  the set.

# Security policy

## Reporting a vulnerability

Please do not open a GitHub issue. Provide responsible disclosure
either privately through GitHub, from the Security tab of this
repository ("Report a vulnerability"), or by emailing
*security at btclib dot org*, as for every btclib project.

## What belongs here, and what belongs upstream

This project is a thin binding layer: the cryptography is
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), vendored as a
submodule and built from source. A flaw in the library itself is not
ours to fix, and it has its own
[security policy](https://github.com/bitcoin-core/secp256k1/blob/master/SECURITY.md)
and its own address, *secp256k1-security at bitcoincore dot org*.

Report there anything affecting the C library. Report here anything
affecting how these bindings drive it:

- the validation of the arguments crossing the cffi boundary. Every
    wrapper checks lengths and ranges before a pointer reaches C, which
    reads a fixed number of bytes from it and cannot know it was handed
    less
- the libsecp256k1 default callbacks, which this project replaces with
    do-nothing stubs so that an illegal argument does not `abort()` the
    hosting Python process. The consequence is that nothing catches an
    illegal argument on the caller's behalf: `context.check()` reports
    what was recorded, and calling it is the caller's to do. Code
    reaching the raw `lib` bindings directly is on its own, and so is
    code calling a private `_foo_` half with a libsecp256k1 object of
    its own — an object no argument check can vouch for, where a refusal
    can reach the caller as a `False`, an ordering or 32 bytes of ECDH
    rather than as an exception. The entry points taking octets are not
    in that position: they parse what they are given
- the build: which optional modules are compiled in, and the commit of
    libsecp256k1 the submodule is pinned to
- the distributions published to PyPI and their provenance

## Supported versions

Only the latest release is supported. Version numbers track the wrapped
libsecp256k1 (release M.N.P wraps libsecp256k1 vM.N.P, with a fourth
number appended for binding-only releases); a fix is published as a new
release, and nothing is backported.

Wheels and sdist are published with PEP 740 attestations, so that a
distribution can be traced back to the workflow run and the commit it
was built from.

The sdist is also attached to the GitHub release, and that copy carries a
build provenance attestation of its own, signed in the run that built it:

```shell
repo=btclib-org/btclib-secp256k1
gh attestation verify btclib_secp256k1-<version>.tar.gz \
  --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml"
```

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has. The signed statement
is attached to the release as well, as `<tag>.attestation.jsonl`, so
`--bundle <tag>.attestation.jsonl` runs the same check reading it from
disk instead of asking GitHub for it — the form for whoever mirrors the
releases page rather than trusting it live. The wheels are on PyPI and
nowhere else, so what verifies them is their PEP 740 attestation there.

## Limitations of the binding layer

These are known and inherent, not vulnerabilities:

- secret material handed to these bindings lives in Python objects,
    which are immutable and not zeroized: it stays in the process memory
    until garbage collection, and may be copied by the interpreter. The
    constant-time properties of libsecp256k1 apply to the C side of the
    boundary, not to what the caller does before and after it.
    The copy in the middle is not a Python object and is overwritten: a
    private key or a shared secret libsecp256k1 writes into a cffi buffer
    — the output of a tweak or a negation, an ECDH secret, the
    `secp256k1_keypair` a BIP340 signature is made with, the nonce
    `dsa.nonce_rfc6979` and `ssa.nonce_bip340` answer with — is read out
    and the buffer zeroed before it is dropped. That is one copy taken back,
    not safety: the `bytes` handed to the caller holds the same secret
    and cannot be overwritten
- **`into` moves that last copy somewhere the caller can overwrite,**
    and is the whole of what it does. A named set of entry points take a
    keyword-only `into` — a writable buffer of exactly the secret's
    length, contiguous and one octet an item, `bytearray` and
    `memoryview` and `mmap` and `array.array("B")` alike — write the
    secret there and return None, so no `bytes` of it is ever made.
    That breadth is the run time's: the annotation is a `bytearray` or a
    `memoryview`, `collections.abc.Buffer` being python 3.12 where the
    floor here is 3.10, so a caller running `mypy --strict` passes
    anything else as `memoryview(x)`, which copies nothing. They are
    `keys.prvkey_negate`, `keys.prvkey_tweak_add`,
    `keys.prvkey_tweak_mul`, `xonly.prvkey_tweak_add`,
    `ecdh.shared_secret`, `ellswift.xdh`, `dsa.nonce_rfc6979` and
    `ssa.nonce_bip340`. **The two secrets `silentpayments` answers do
    not**, each being one member of a returned tuple, where an argument
    could not say which: the tweak of `label`, and the per-output tweak
    `scan_outputs` hands back. Both are `bytes` and neither can be
    zeroed, which is the limitation above and not this narrowing of it.
    What the caller then does with the buffer is theirs: this does not
    wipe it for them, and a buffer they never overwrite is exactly the
    un-zeroizable copy `into` was reached for to avoid. The obligation is
    stated rather than enforced, for the reason `ssa.Signer` has no
    finalizer: a guarantee nothing keeps is worse than none

    ```python
    prvkey = bytearray(32)
    keys.prvkey_tweak_add(parent, tweak, into=prvkey)
    try:
        ...                       # use it
    finally:
        prvkey[:] = bytes(32)     # the caller's wipe, and only theirs
    ```

- the two buffers whose zeroing is the caller's to ask for are
    `ssa.Signer`'s keypair and `musig.SecretNonce`'s secret nonce.
    Everything above is wiped inside the call that made it — read out and
    zeroed in the one operation, or wiped in a `finally` where it is a
    keypair; a signer holds its `secp256k1_keypair` across calls, which is
    what it is for, and a `SecretNonce` holds a `secp256k1_musig_secnonce`
    between `musig.nonce_gen` and `partial_sign` for the same reason.
    `partial_sign` wipes it as the last thing it does with it, whatever
    that call answers; short of that, both wipe when told — `wipe`, or the
    `with` statement that calls it on the way out of the block. Either one
    told neither is dropped with the secret still in it, and cffi frees
    that memory without overwriting it. There is no finalizer behind
    either on purpose: one would run at a time nothing specifies, which
    reads as a guarantee and is not one. `with` is the guarantee
- a nonce is the private key, given the signature it made. The two nonce
    entry points exist so that an implementation of RFC6979 or of BIP340's
    derivation can be checked against libsecp256k1's own, and what they
    answer is not a value to publish, log or store beside a signature.
    Each scheme has its own equation: ECDSA signs `s = k⁻¹(h + r·d)`, so
    `d = (s·k − h)/r mod n`, and BIP340 signs `s = k + e·d` with
    `e = H(R ‖ P ‖ m)`, so `d = (s − k)/e mod n` — for the `k` and `d`
    BIP340 negates to an even-y point, which is a parity whoever holds
    the nonce computes rather than a step that stops them. Reading a
    nonce also takes it out of constant-time code, which is the limit
    above; this is the one that has the arithmetic to show for it
- a scalar passed as an `int` leaks its magnitude. A Python integer is a
    variable-length object, so serializing one — and any arithmetic that
    produced it — takes a time that depends on the value; the argument
    checks in front of the call add no leak of their own, branching on a
    type, a length or a magnitude and never on the content of a secret.
    Everywhere an `int` is accepted `bytes` is too, and for a secret that
    is the form to use
- **the entry side takes one form that is not a copy**: where a scalar is
    accepted, so is a cffi array of 32 octets —
    `ffi.new("unsigned char[32]", ...)`, or any other item type an octet
    wide — and where the call only reads it, it reaches libsecp256k1 as
    it stands. That is the whole of the difference: a `bytes` or a
    `bytearray` is copied at the boundary, deliberately, so that nothing
    can change what libsecp256k1 is about to read, and the copy of a
    secret is an immutable object nothing can overwrite. A caller signing
    again and again under one key can therefore hold it in memory it
    owns, wipe that memory when done, and have no `bytes` of the key made
    per call. What this does not change is what came before: the value
    the buffer was filled from existed already, and the arithmetic that
    produced it happened where this package cannot see — which is why
    filling one from an `int` buys nothing the bullet above does not
    already refuse. And the wipe stays the caller's, as it is for `into`:
    a buffer never overwritten is the same un-zeroizable copy under
    another name.

    **What the caller takes on is three things, and `_scalar` names them
    where it refuses the shapes it cannot take.** The octets must stay
    put for the whole call, which is more than one read — libsecp256k1
    loads the scalar and then derives the nonce from the same pointer, and
    grinding and the check read it again — so a write in between yields a
    nonce and a signature under two different keys, reported as the fault
    it is indistinguishable from. The memory must outlive the call, which
    no python argument has had to promise: a cffi *view*, a slice or a
    cast, does not keep its owner alive, and a dangling one reads freed
    memory as a private key. And the length is the declaration's word:
    `ffi.cast("unsigned char[32]", ...)` over 8 octets is accepted, cffi
    having no way to report what was really allocated.

    Four calls copy the octets into a buffer of their own instead, and
    have to: `keys.prvkey_negate`, `keys.prvkey_tweak_add`,
    `keys.prvkey_tweak_mul` have libsecp256k1 write the answer through
    that pointer, and the sender side of `silentpayments` wipes it on the
    way out — so passing the caller's memory would negate or zero the key
    they handed in. Each of those answers a *new* secret, which is what
    `into` above is for

    ```python
    prvkey = ffi.new("unsigned char[32]", secret_octets)
    try:
        sig = dsa.sign(msg, prvkey)   # no bytes of the key is made
    finally:
        ffi.buffer(prvkey)[:] = bytes(32)   # the caller's wipe
    ```

- randomness comes from `secrets.token_bytes`, i.e. from the operating
    system, both for the context randomization and for the auxiliary
    randomness of BIP340 signing and of ElligatorSwift encoding

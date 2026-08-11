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
    hosting Python process. The consequence is that nothing downstream of
    the wrapper modules catches an illegal argument: code reaching the
    raw `lib` bindings directly is on its own
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
repo=btclib-org/btclib-libsecp256k1
gh attestation verify btclib_libsecp256k1-<version>.tar.gz \
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
    `secp256k1_keypair` a BIP340 signature is made with — is read out and
    the buffer zeroed before it is dropped. That is one copy taken back,
    not safety: the `bytes` handed to the caller holds the same secret
    and cannot be overwritten
- a scalar passed as an `int` leaks its magnitude. A Python integer is a
    variable-length object, so serializing one — and any arithmetic that
    produced it — takes a time that depends on the value; the argument
    checks in front of the call add no leak of their own, branching on a
    type, a length or a magnitude and never on the content of a secret.
    Everywhere an `int` is accepted `bytes` is too, and for a secret that
    is the form to use
- randomness comes from `secrets.token_bytes`, i.e. from the operating
    system, both for the context randomization and for the auxiliary
    randomness of BIP340 signing and of ElligatorSwift encoding

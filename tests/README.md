# Vendored test vectors

Where the files under `tests/` that are not this package's own tests
came from, and whether the copy here still matches it. The docstring of
`test_vectors.py` already cites the same upstreams, against `master`: a
citation like `bitcoin/bips/blob/master/bip-0340/test-vectors.csv` names
a file that changes under us and says nothing about the revision that
was actually copied. Here each citation is pinned to a commit, and each
blob is compared.

Nothing in this file restates what a vector tests -- `test_vectors.py`
already says that. This says which revision of it is held, and for the
two `secp256k1-py` files the answer is "the same JSON values, ours
reformatted", which the verdict accounts for.

## Reading an entry

Each entry gives the upstream repository, the path in it, the commit
the citation is pinned to, the git blob SHA-1 that was compared, and a
verdict:

- **identical** — the file here and the upstream blob are the same
  bytes.
- **reformatted** — same parsed JSON value, different whitespace.

`pulled` is the date the file entered this repository, from
`git log --follow --diff-filter=A`. `behind` counts upstream revisions
of that path since the pin -- a staleness figure, not a defect: a
vector file is a fixed set of cases, and refreshing it is a decision,
not a chore.

## Re-checking a pin

```shell
git hash-object tests/bip340_test_vectors.csv
gh api repos/bitcoin/bips/git/trees/<commit>:bip-0340 \
    --jq '.tree[] | select(.path == "test-vectors.csv") | .sha'
```

The comparison is on git blob SHA-1, not sha256: it is what a tree
entry already carries, so nothing has to be downloaded twice. Where
upstream is CRLF and this comparison still holds -- every csv here from
`bitcoin/bips` is the case -- the entry says so, this repository not
being LF throughout the way btclib's is: `.pre-commit-config.yaml`'s
`mixed-line-ending` hook excludes `tests/bip3(40|24)_*.csv`, byte for
byte against `bitcoin/bips` being the point.

## bitcoin/bips

### `tests/bip340_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0340/test-vectors.csv
commit  200f9b26fe0a2f235a2af8b30c4be9f12f6bc9cb  2023-04-20
blob    672339129a844a060591bb22f444158ff45438ed
pulled  2026-08-01
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, CRLF included. All 19 vectors, all eight
columns. Four of the 19 are messages of 0, 1, 17 and 100 bytes, which
BIP340 accepts and `ssa.sign` does not: those four are what
`ssa.sign_custom` is signed against, the only published values it can be
held to, while `ssa.sign` takes the 32-byte rows. Every row carrying a
secret key is therefore signed and compared byte for byte, and the
32-byte ones twice, once through each function -- `sign_custom`
answering a 32-byte message with the signature `sign` returns is itself
part of what is checked. btclib's own copy of this file takes the
pure-Python path for the same four, having the fallback this package
does not.

### `tests/bip324_ellswift_decode_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/ellswift_decode_test_vectors.csv
commit  cc177ab7bc5abcdcdf9c956ee88afd1052053328  2023-01-11
blob    1bab96b721e2f3ab90142c318523551eb520f753
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, CRLF included. Every vector, all three columns.
The `comment` column names the degenerate case each one is -- `u%p=0`,
`t%p=0`, `u^3+t^2+7=0`, and which of x1, x2, x3 the map lands on -- and
`test_vectors.py` uses it as the test id, so a failure says which case
broke.

### `tests/bip324_packet_encoding_test_vectors.csv`

```text
repo    bitcoin/bips
path    bip-0324/packet_encoding_test_vectors.csv
commit  713f000a20421a54b29cd8ab89e711eef1fbccb9  2025-10-23
blob    1588b066b4792d0b03f30d4f7f18e57ccde1f525
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**, CRLF included. Vendored whole, and read in part:
this is BIP324's packet encoding suite, whose later columns are the
ciphers built on top of the handshake. What these bindings compute is
the `in_priv_ours`/`in_ellswift_ours`/`in_ellswift_theirs` inputs
through `ellswift.xdh` to `mid_shared_secret`, plus `mid_x_ours` and
`mid_x_theirs` through `ellswift.decode`. The whole file is held rather
than the six columns, so that the pin above is a pin on something
anybody can fetch and diff.

### `tests/bip327_key_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/key_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    b2e623de60f302c4004a6d656581bdba1f4e1e05
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Every case, the error ones included: an
unparsable key, a key whose x exceeds the field size, a tweak out of
range, and a tweaking that lands on the point at infinity.

### `tests/bip327_nonce_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/nonce_agg_vectors.json
commit  87394eaeb436d02e0a68b38a1e94bc526d50056e  2023-03-27
blob    1c04b8818f340a5fe2e10eaf73c17a2c9e020f46
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Every case; the error ones are all refused at
the parse of the public nonce, which is where libsecp256k1 puts that
check.

### `tests/bip327_sign_verify_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sign_verify_vectors.json
commit  508e3a6a40a6e73c73cbfa8a33aa18a2bc7b9d91  2024-05-14
blob    f71c8dd9d935c8c5f398e6a3888943e1e68b729d
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Read in part, and the part is the verification:
libsecp256k1 has no parser for a serialized secret nonce, by design, so
the `sk` and `secnonces` of this file have no entry point to be fed to
and the signing direction cannot be driven from it. The `expected`
partial signatures are verified instead, which reads the same equation
from the other side. Two of the valid cases -- an empty message and a
38-byte one -- are skipped as well: BIP327 allows a message of any
length and `secp256k1_musig_nonce_process` takes a `msg32`.

### `tests/bip327_sig_agg_vectors.json`

```text
repo    bitcoin/bips
path    bip-0327/vectors/sig_agg_vectors.json
commit  1c6ac0c4cf1f39ea806b8594d6060b6d52fd1439  2024-07-19
blob    519562c343b6e4bf686ba6e3eda8cee5c8e8b55d
pulled  2026-08-06
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Every case, the tweaked ones included: the
aggregate signature is compared with the published value and then
verified as a plain BIP340 signature of the tweaked aggregate key.

Not vendored from `bip-0327/vectors/`: `key_sort_vectors.json`,
`nonce_gen_vectors.json`, `tweak_vectors.json` and
`det_sign_vectors.json`. The first two and the last pin functions
libsecp256k1 either does not expose or does not take the inputs of
(`secp256k1_musig_nonce_gen` generates its own randomness rather than
reproducing a published nonce); `tweak_vectors.json` drives signing,
which is the same secret-nonce obstacle as above.

Not vendored from `bip-0324/`: `xswiftec_inv_test_vectors.csv`. It pins
the inverse map, and libsecp256k1 exposes no entry point for it --
`secp256k1_ellswift_encode` chooses a case from the 32 bytes of
randomness it is given, and the case is not an argument -- so there is
nothing here those vectors could be compared against.

### `tests/bip352_send_and_receive_test_vectors.json`

```text
repo    bitcoin/bips
path    bip-0352/send_and_receive_test_vectors.json
commit  c2ac36f48f71615984087fd151f410457edfed72  2026-04-16
blob    3a189757ddbc90e5ec538d643f7ac238a51704e8
pulled  2026-08-11
behind  0 revisions; that commit is the tip of the path
```

Verdict: **identical**. Every case, both directions of each. It is also
the blob libsecp256k1 vendors, at
`src/modules/silentpayments/bip352_send_and_receive_test_vectors.json`
in the submodule: byte for byte the same file, which is worth saying
because it makes the copy here look redundant and it is not. The wheel
test jobs check out without `submodules: recursive` -- what they exercise
is the module inside an installed wheel, not a build -- so a test reading
the submodule would silently not run there.

Read in part, and the part is a decision rather than a limit. Each case
carries its transaction as scriptSig, witness and prevout scriptPubKey
hex, and BIP352's eligibility rules are rules about those; this package
reads no script, so `test_vectors.py` takes the `input_pub_keys` the file
publishes for the eligible inputs and pairs them with the inputs in
order. The one script question left is whether a prevout is P2TR, which
is what decides between the x-only and the full key argument and can be
read off nothing else.

Two shapes of this file are worth knowing before its assertions are
read. A sending case's `outputs` is a list of alternative output *sets*,
not orderings of one: where recipients share a scan public key the
assignment of k among them is undetermined and each assignment gives
different keys, which is why cases 15 and 17 have entries that are not
permutations of each other. And a receiving case's published
`shared_secret` is null exactly where the transaction is not a Silent
Payments one, which is what tells "the recipient skips it" apart from
"the recipient finds nothing in it".

## rustyrussell/secp256k1-py

### `tests/ecdsa_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_sig.json
commit  ead56b92a8229e16941318d953c6444268beaa1a  2015-09-18
blob    af16179725c10c409c7929ac0576161c1f5e72ad
pulled  2026-08-01
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal to the upstream blob;
ours is pretty-printed at four spaces -- byte-identical to btclib's own
copy of the same file, which vendored it independently from the same
upstream.

### `tests/ecdsa_custom_nonce_sig.json`

```text
repo    rustyrussell/secp256k1-py
path    tests/data/ecdsa_custom_nonce_sig.json
commit  3caf31d20c668cf54a1621e21b7f1d943f0db048  2016-03-30
blob    e9d61e267f2e8fcd21c660aab17fe5de44cae0f0
pulled  2026-08-01
behind  0 revisions; still the blob on master
```

Verdict: **reformatted**. 199 vectors, JSON-equal, and again
byte-identical to btclib's own copy.

## Summary

Against a pinned upstream blob, in the tree today:

```shell
git ls-files 'tests/*.csv' 'tests/*.json'
```

- identical byte for byte, CRLF included: `bip340_test_vectors.csv`,
  `bip324_ellswift_decode_test_vectors.csv`,
  `bip324_packet_encoding_test_vectors.csv`.
- identical byte for byte: `bip327_key_agg_vectors.json`,
  `bip327_nonce_agg_vectors.json`, `bip327_sign_verify_vectors.json`,
  `bip327_sig_agg_vectors.json`,
  `bip352_send_and_receive_test_vectors.json`.
- JSON-equal, reformatted: `ecdsa_sig.json`, `ecdsa_custom_nonce_sig.json`.

Not vendored, and outside the scope of this file: `test_vectors.py`
also self-checks the RFC6979 `(k, r, s)` triples in its own docstring
against `r == x(k*G)`, which is not a citation to a vendored file, and
constructs the recovery id 2 and 3 signature published nowhere, holding
it to arithmetic it does itself.

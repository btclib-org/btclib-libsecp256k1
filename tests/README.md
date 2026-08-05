# Vendored test vectors

Where the three files under `tests/` that are not this package's own
tests came from, and whether the copy here still matches it. The
docstring of `test_vectors.py` already cites the same three upstreams,
against `master`: a citation like `bitcoin/bips/blob/master/bip-0340/
test-vectors.csv` names a file that changes under us and says nothing
about the revision that was actually copied. Here each citation is
pinned to a commit, and the two blobs are compared.

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
upstream is CRLF and this comparison still holds -- `bip340_test_vectors.csv`
is the case -- the entry says so, this repository not being LF
throughout the way btclib's is: `.pre-commit-config.yaml`'s
`mixed-line-ending` hook excludes that one file by name, byte for byte
against `bitcoin/bips` being the point.

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
columns. Four of the 19 are messages of 0, 1, 17 and 100 bytes: BIP340
accepts a message of any size, and `ssa.sign`/`ssa.verify` insist on a
32-byte hash (issue 169), so `test_vectors.py` skips these four rather
than failing them -- the same four btclib's own copy of this file takes
the pure-Python path for, having the fallback this package does not.

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

- identical byte for byte, CRLF included: `bip340_test_vectors.csv`.
- JSON-equal, reformatted: `ecdsa_sig.json`, `ecdsa_custom_nonce_sig.json`.

Not vendored, and outside the scope of this file: `test_vectors.py`
also self-checks the RFC6979 `(k, r, s)` triples in its own docstring
against `r == x(k*G)`, which is not a citation to a vendored file, and
the BIP327 constants any MuSig2 code answers to, which this package
does not implement.

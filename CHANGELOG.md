# Changelog

Every change of a release, in full: what changed, why, and what it cost.
[HISTORY.md](./HISTORY.md) has the release notes, which say what a user has
to act on; this file is the record behind them, and is where a claim in
those notes can be checked.

Only v0.7.1.2 is here. The releases before it were documented at
release-notes length in the first place, and are still in
[HISTORY.md](./HISTORY.md) rather than duplicated here.

## v0.7.1.2 (work in progress, not released yet)

Grouped, and the order runs from what a caller sees to what only
maintainers do. Nothing here breaks a caller: the wrapped
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.7.1)
is the same 0.7.1 (1a53f49), no wrapper changed behaviour, and nothing in
the public API moved. Neither file counts its entries: `grep -c '^- '`
does that, whereas a stated number is a line every open branch has to
edit.

### The documented boundary

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

### The gate

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
  `"-DSECP256K1_BUILD_BENCHMARK=OFF"` in `scripts/cffi_build.py`, which
  the base64 detector reads as a secret. Verified by planting a
  64-character hex constant in a test module and an AWS access key in a
  vector file, and watching each hook name its own.
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

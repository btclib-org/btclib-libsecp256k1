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

## v0.8.0 (work in progress, not released yet)

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
  spends it, and the sender's keypairs and secret keys hold private keys:
  all are wiped, and the two key lists are built *inside* the `try` whose
  `finally` wipes them, an invalid key later in the list being able to
  raise between them.

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
  checks list each is what says so — the badge being a `docs` one added to
  the second README row, beside `test` and `lint`, where the row already
  ends with what read the docs makes of the same source. The job's display
  name is unchanged,
  which is what let it move without touching the branch rule: a required
  context is matched by name, not by the workflow that reported it.
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

### The gate

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

- **This file's own preamble says where it starts, not what it holds.**
  "Only v0.7.1.2 is here" was true for exactly one release, and v0.7.1.3
  landing under it made it false without anything failing; every release
  after would have done the same. Where the file starts is the fact it
  was reaching for, and that one does not move.

### Packaging metadata

- **`.gitignore` matches a versioned environment, and the sdist stops
  shipping one.** `.venv`, `venv/` and `venv*/` between them do not match
  `.venv-3.10`, which is what
  `UV_PROJECT_ENVIRONMENT=.venv-3.10 uv run --python 3.10 --no-cache pytest`
  creates — the way of trying another interpreter that keeps the default
  environment rather than replacing it, and CONTRIBUTING.md now gives it
  beside the run that replaces one. Nothing downstream caught the leftover:
  uv writes a `.gitignore` holding `*` inside the environment it creates, so
  `git status` was clean, while hatchling builds the sdist from the root file
  alone and shipped the directory — 377 paths against 297 and 13,132,264
  bytes against 3,076,714, measured on `38ee75b` with the environment present
  either way (`tar -tzf dist/*.tar.gz | wc -l`), the rest of the archive
  identical. The totals move with the vendored library and the difference
  does not: it is the environment's `bin` and the four files beside it,
  `lib/` being matched already by the Distribution section above.
  `twine check --strict` passed on it; `pyroma --min 10` raised
  `tarfile.AbsoluteLinkError` on `.venv-3.10/bin/python`, the tarfile data
  filter refusing a link to an absolute path, so the packaging gate failed
  on one symlink rather than on the stray paths, which are the difference
  between those two counts. `check-manifest` names every one of them — it
  compares the sdist with what git tracks — and is not in the `check` group;
  the pattern states the same fact where a file becomes invisible rather
  than where an archive is built. It is `.venv*/`, in place of the `.venv`
  beside `venv*/`: a directory of that exact name is matched by it, and by
  the stock `# Environments` block above.

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

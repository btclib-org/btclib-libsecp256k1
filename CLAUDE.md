# Working on btclib_secp256k1

Python bindings to a vendored [libsecp256k1](secp256k1/), built from
source. The package is thin: the cryptography is upstream, and what lives
here is the wrapping, the argument validation at the cffi boundary, and
the packaging — one wheel per platform and linkage, which is where most of
the complexity is. How many that comes to is a question for the release
that asks it, and `gh run view <id> --json artifacts` answers it; a number
here would be a line every matrix change has to edit, and nothing would
fail when it was not edited.

Repository configuration — branch protection, required checks, token
permissions, publishing environments, Dependabot, secret scanning — is in
[REPOSITORY.md](REPOSITORY.md). Read that file before changing a workflow,
a branch rule or a repository setting. Writing code does not need it.

Reviewing a pull request — what a review establishes before it gives
an ack, what a finding must contain, and why everything it notices
that the diff is not about becomes an issue rather than a comment — is
[REVIEWING.md](REVIEWING.md), and `/review` is that file as a command.

This file is for what is not written down elsewhere. The documentation is,
and stays, in:

- [README.md](README.md) — design, wrapped modules, build, and the
  static/dynamic/sdist distinction
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to build and test
  locally, how to reproduce each CI job, and what a change has to satisfy
- [RELEASING.md](RELEASING.md) — the release, and the rehearsal
- [scripts/README.md](scripts/README.md) — the build backend, one file at
  a time
- the comments in `.github/workflows/*.yml` and `pyproject.toml`, which
  carry the reasoning behind their choices

## Architecture

One thing decides how this package behaves, and it is decided at import
time by `btclib_secp256k1/__init__.py`: `_load_lib` returns
`module.lib` when the extension has libsecp256k1 linked into it (a static
build) and otherwise `ffi.dlopen`s the shared object shipped beside it (a
dynamic, cffi ABI mode build). Only one of those two branches exists in a
given wheel, which is why `_load_lib` takes the module as an argument
rather than reading it from the enclosing scope: the branch this build
does not have is testable only with a stand-in, and that is how coverage
still reaches every line. Every question of the form "why does this differ
between platforms" comes back here.

Above it, one module per libsecp256k1 module wrapped: `dsa`, `ssa`,
`ecdh`, `recovery`, `ellswift`, `silentpayments`, plus `keys`, `xonly`,
`hashes`, `context`, `_scalar`, `_secret` and `_cdata` for what crosses
the boundary. No module is one call of another: `mult` had become that
-- `pubkey_from_prvkey` with a flag fixed -- and was folded into `keys`.

MuSig2 is deliberately *not* wrapped: its two-round protocol needs a
session whose secret nonce cannot be reused, which belongs where the
signing state lives, in btclib; it is reachable through the raw `ffi`
and `lib` this package exposes. See the Design section of the README
before adding a module.

Below it, `scripts/cffi_build.py` builds the vendored library with CMake
and then compiles the extension by one of three paths — static with
MSVC, static with the interpreter's own toolchain, or dynamic with no C
compiled at all — chosen by `BTCLIB_LIBSECP256K1_DYNAMIC`,
`BTCLIB_LIBSECP256K1_CROSS_COMPILE` and `CFFI_PLATFORM`.
`stubs/_btclib_secp256k1.pyi` is what lets strict mypy typecheck a
module that only exists after a build.

## The gate is one file

`.pre-commit-config.yaml` is the single definition of what "clean" means.
The `lint` workflow runs that very file, so what CI enforces is what a
commit enforces:

```shell
uvx pre-commit run --all-files
```

Never add a check that exists only in a workflow, and never leave a hook
weaker locally than on a runner: a hook that needs a tool the developer
may not have carries it in `additional_dependencies` (this is why
`actionlint` ships `shellcheck-py` and `zizmor` is a `local` hook pinned
to a version). A check discovered by CI after a push is a check in the
wrong place.

## The primary checkout is the maintainer's

**Never work in it.** No edit, no `git add`, no commit, no branch switch,
no rebase, no `git stash`, no `pre-commit run` — the hooks fix files in
place. It is the maintainer's window on the tree: whatever is open in
their editor, whatever they have half-staged, and the branch they are
looking at are theirs, and one working tree has one index and one HEAD to
lose. Reading it is fine — `git log`, `git show`, `git diff`, `gh`, and a
`git fetch`, which writes refs and leaves the work tree alone.

**Every session works in a worktree**, its own, from the first edit:

```shell
WT=<scratchpad>/wt<issue>
git worktree add -b <branch> "$WT" origin/main
cd "$WT"
git submodule update --init secp256k1  # a worktree isolates files, and a
                                       # submodule is a checkout of its
                                       # own that it does not inherit
uv sync --locked                       # a second venv, and a second build
                                       # of the extension: minutes, not
                                       # seconds
# edit, gate and commit here, then
git push origin HEAD:refs/heads/<branch>
git worktree remove --force "$WT" # removing it is part of finishing
```

The venv, the C build and a second clone of the submodule are the whole
of the cost, and they buy the thing that matters: a commit cannot
contain work that was never in it, and the maintainer's branch does not
move under them. The clone is the third of those because a linked
worktree gets a submodule module of its own rather than sharing the
primary checkout's — `secp256k1/.git` there reads `gitdir:
…/.git/worktrees/<wt>/modules/secp256k1` — which was measured at 14 MB
under `.git/worktrees/<wt>/modules` and 7 MB of tree. `--reference`
against the primary's module is what a session asks about next, and it
works: `git submodule update --init --reference
<primary>/.git/modules/secp256k1 secp256k1` leaves the module directory
exactly where git puts it, writes one `objects/info/alternates` pointing
at the primary's `objects`, and measures **128 KB** against those 14 MB,
with the primary's own `core.worktree` untouched and its submodule
clean. What it costs is the pointer: the worktree's submodule then has
no copy of its own objects, so a `git gc` or a repack in the primary —
or moving or deleting it — can leave this one unable to find them. What
git is keeping apart by giving each linked worktree a module of its own
is the submodule's *state*, so that two worktrees can have it checked
out at two commits; the object store sitting inside that module is a
consequence of where the state lives rather than a refusal to share
objects, which is why `--reference` is allowed to share them and why it
changes nothing about `core.worktree`. For a recipe whose last line
removes the worktree anyway that is a trade worth declining, and
declining knowingly is the point of the paragraph.

**The submodule line is what makes the rest of the recipe run**, and
leaving it out costs a session rather than a build: `git submodule status`
answers a leading `-` in a fresh worktree, and `uv sync --locked` then dies
inside CMake naming the empty `secp256k1/` and closing on "Build failures
usually indicate a problem with the package or the build environment" —
the two things that are not wrong. CI never meets it, every checkout there
passing `submodules: true`. It is the same sentence as the one below about
`refs/stash`: a worktree isolates files, and neither a submodule checkout
nor a ref is one.

**Two things the recipe leans on, both measured rather than assumed**, and
worth knowing because a submodule inside a linked worktree is a known sharp
edge. `core.worktree` in `.git/modules/<name>/config` is a single value, so
a second checkout of one submodule can rewrite it under the first — and
does not here, git giving the linked worktree its own module: the primary's
`core.worktree` still reads `../../../secp256k1` and `git -C secp256k1
status` there stays clean through the whole sequence. And `git worktree
remove --force` still finishes with an initialized submodule inside: exit
0, tree gone, `.git/worktrees` gone with it, nothing left for
`git worktree prune`. So the recipe's last line needs no companion.

**Never `git stash`, in the primary checkout or in a worktree:
`refs/stash` is shared.** A worktree isolates files, not refs, so
`git stash push` pushes onto the same stack every other session pops
from — and on a clean tree it creates nothing, so the `git stash pop`
that follows applies and *drops* whatever another session shelved. Commit
to your own branch instead. What is already lost is still in the object
store: `git fsck --unreachable` names the commit and `git stash store
<sha>` puts the ref back.

**`git checkout -- <file>` is the other way to lose work**, and it does it
quietly: it restores from the index, so an edit made and not staged is
gone with no output at all. Reverting a deliberate experiment is what a
copy is for — `cp file file.bak`, then put it back.

## Model

The default model for this repository is Sonnet. Switch to Opus only
for architectural decisions with conflicting constraints -- design
choices with non-obvious trade-offs, refactors with unclear
dependencies, diagnosis where the symptom does not point to the
cause. Use `/model opus` for the session, then switch back to Sonnet.

Do not use Fable unless explicitly instructed.

## Commands whose flags are load-bearing

```shell
# the suite, as the coverage job runs it: uv run syncs by itself, and
# without these flags it installs the whole dev set
uv run --locked --no-default-groups --group test pytest --cov

# another interpreter; --no-cache because the cached extension
# belongs to one ABI
uv run --python 3.10 --no-cache pytest

# the packaging gates, pinned by uv.lock rather than fetched by uvx
uv build --sdist
uv run --locked --only-group check twine check --strict dist/*
uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz

# after touching pyproject.toml; the uv-lock hook does it too
uv lock

# after adding a hex constant to a test module; the vendored vector
# data has a baseline of its own, whose command is in CONTRIBUTING.md.
# Neither file is excluded from the scan, only recorded as reviewed.
# --slim and a redirect, not --baseline: the flag is what keeps a moved
# line from rewriting the file, and --baseline writes the full form
# whatever it read -- it also merges, so a redirect drops what an audit
# marked; CONTRIBUTING.md carries both halves
uvx --from detect-secrets detect-secrets scan --slim \
    --exclude-files '^(\.secrets\..*baseline|tests/.*\.(csv|json))$' \
    > .secrets.baseline
```

## The workflows that gate, and the ones that do not

`lint`, `docs`, `test` and `codeql` are the gate, and `release` reuses the
first three. It does not reuse `codeql`, and does not have to: a tag is an
ancestor of `main` before the matrix builds anything (`version-check` in
`release.yml`), so the tree it publishes is one the merge gate has already
scanned — and `codeql` is weekly besides, which is what covers the code
nobody touched. The rest are sentinels: each is a workflow of its own, has
no aggregate job, is named by no branch rule, and opens no issue on failure
(`vendored-vectors` excepted, for the reason its own header gives). That is
deliberate in every case — each is expected to go red for a reason no pull
request introduced, and a red check nobody can act on from a branch is
noise. Their crons are spread out, because sentinels landing in one inbox
on one morning are one sentinel, and `codeql` keeps a morning of its own
for the same reason. Two pairs share a morning even so. `macos` and
`latest` do it deliberately, and both cron comments say why: half an hour
apart on Wednesday, they answer halves of one question and are worth
reading together. `published` and `vendored-vectors` are the other pair,
both monthly on the 1st.

| workflow | asks | when |
| --- | --- | --- |
| `links` | do the URLs in the prose still resolve | Mon |
| `macos` | does the suite pass on macOS | Wed, and a release |
| `latest` | does the tree survive every dependency at its newest | Wed |
| `windows` | does the suite pass on Windows | Sat, and a release |
| `mutation` | would the suite notice a wrong line | Sun |
| `published` | can the world install what PyPI serves | 1st, a release |
| `vendored-vectors` | do the vendored vectors still match upstream | 1st |

`macos` and `windows` are the two sentinels a pull request would otherwise
have waited for, and each left the gate on a measurement rather than a
preference — the macOS runners queue for tens of minutes where every other
platform queues for two, and the Windows cells were the largest family of
jobs in a run asking for more of them at once than an organization on GitHub
Free is given. `test.yml`'s header carries the first measurement and
`windows.yml`'s the second. A release calls both, so what a merge no longer
waits for a publication still does.

`latest` is the one that covers a gap nothing else does. Every uv command
elsewhere passes `--locked`, the dependency groups declare no version, and
the one runtime dependency is cffi — which this package does not merely
import but *compiles against*, so a cffi, setuptools or cmake release can
break the build rather than a test — and none of those three is something
Dependabot moves, `[build-system] requires` being resolved at build time
and pinned by no lock file. Dependabot is weekly, on the Thursday after
this runs, which is the other half of the arrangement: the sentinel
answers on Wednesday, so the pull requests that arrive the next morning
are a diff whose result is already known. `.github/dependabot.yml` carries
that reasoning where the day is set.

`mutation` is scoped by `.github/mutation/bindings.toml`, which is also
what a local run reads, so there is one statement of what is mutated and
what judges it. Two things to know before starting one: it mutates the
source in place and restores it, so nothing else may read the tree while it
runs, and `cosmic-ray baseline` comes first — without it a stale test
command fails every mutant identically and the session reports a perfect
kill rate, which is the one failure mode that looks like good news.

## What this repository expects

- **the prose style is CONTRIBUTING.md's "Documentation and comments"
  section**, stated once there because contributors read that file and not
  this one. Its shortest form: comments say why, the what being in the
  diff; a change that makes a comment untrue updates the comment, in the
  workflows and the build scripts as much as in the package; and never
  state a count that nothing checks
- **tests validate against external vectors.** A test that compares these
  bindings with themselves proves nothing. `tests/test_vectors.py`
  documents where each vendored file comes from
- **coverage is a ratchet at 100%,** with `raise RuntimeError` excluded:
  see the reasoning in `pyproject.toml`
- **warnings are errors** (`filterwarnings`), because the 3.10 to 3.14
  spread turns a deprecation into a breakage
- **the version is declared once,** in `pyproject.toml`; `__version__`
  reads the installed metadata. Never bump it in an ordinary change:
  releases are cut by a maintainer, and the release workflow checks the
  tag against it. The one bump that is not a release is the fourth number
  opened straight after one, so that the tree stops claiming the version
  it shipped: step 10 of RELEASING.md, and the reason it is a step
- **the `secp256k1` submodule moves in a change of its own,** with the
  version named in `README.md` and `HISTORY.md` moved with it
- **`main` is the only long-lived branch**, so a pull request targets it
  and a tag on it is a release; it is protected, and every change gets
  there through a pull request, and through nothing else — a direct push
  is refused for everyone. Squash is the only merge button enabled, and
  auto-merge is what presses it once review and checks are in: one
  commit regardless of how many the branch carried, composed and signed
  by GitHub, whose signature is what the rule asks for, a valid one
  rather than a particular signer's. GitHub therefore reconciles every
  landing — Merged, `Closes #N` in the description fires, and the head
  branch goes — with no case left where a commit arrives that no pull
  request names. REPOSITORY.md has the settings that make that true. A
  pull request stacked on another is rebased once its parent lands, and
  pays a fresh run of the matrix for it. The `dev` this repository used
  to develop on, and the
  release merge into `master` that went with it, are gone; RELEASING.md
  is the file that describes what replaced them

## Conventions the workflows hold to

Each of these was arrived at by something going wrong, and `actionlint`
and `zizmor` are hooks precisely so they stay true. Both must report zero
findings.

- every action pinned to a commit SHA, with the tag in a trailing comment
- every workflow declares `permissions: contents: read`, and a job that
  needs more declares it itself
- every job declares `timeout-minutes`
- `concurrency` groups are named literally (`test-${{ github.ref }}`),
  never through `github.workflow`: in a called workflow what that resolves
  to is undocumented, and if it is the caller's name the two workflows a
  release calls would cancel each other. `github.ref` in a called workflow
  is the *caller's* ref, so a reusable workflow also takes a
  `concurrency-suffix` input, and `release.yml` passes one: without it a
  rehearsal dispatched on a branch shares a group with a push to that
  branch, and one cancels the other
- `actions/checkout` passes `persist-credentials: false`, so the token
  does not stay in `.git/config` where an artifact upload could carry it
- uv commands pass `--locked`, never `--frozen`: the second takes
  `uv.lock` as it finds it and never checks it
- the packaging tools come from the pinned `check` group, not from `uvx`,
  which would fetch whatever the index holds when the job runs
- a hook that needs a tool carries it in `additional_dependencies`, with
  a version: unpinned it is whatever existed when each environment was
  built, and nothing ever moves it

## Facts that would otherwise cost a session

- **`uv run --python 3.10 …` replaces `.venv`** with an environment built
  on that interpreter, and leaves it there. Going back is another
  `uv sync`, plus `--reinstall-package btclib_secp256k1 --no-cache` if
  the extension in the cache belongs to the ABI just left. The README
  says so, at the end of a long section
- **`uv run` syncs the environment itself.** Without
  `--no-default-groups --group test` it installs the whole dev set, which
  is how the coverage job came to install twenty-nine packages after
  deliberately installing ten
- **the settings that cannot be enabled are in REPOSITORY.md**, with the
  API call that shows each still off: the two secret-scanning extensions
  are the ones that answer a PATCH with 200 and change nothing. Do not
  spend a session rediscovering them
- **every `schedule` and `workflow_dispatch` here is inert off `main`**:
  both only run from the default branch, so a rehearsal of `release.yml`
  cannot be dispatched from a branch, and `macos.yml`, `latest.yml` and the
  other sentinels are reachable there through nothing at all until merged
- **a hand-applied mutation can outlive its restore.** `(0, 1, 2, 3)` and
  `(0, 1, 1, 3)` are the same length, so restoring the file with `cp` in the
  same second leaves mtime *and* size matching what the `.pyc` recorded, and
  python reuses the mutated bytecode — silently, in the next unrelated run.
  `PYTHONDONTWRITEBYTECODE=1`, with a passing baseline run before and a
  passing control run after, is what makes a hand verification mean
  anything. **cosmic-ray does not have the problem, and the mechanism is
  worth naming rather than trusting** (#229): `cosmic_ray/testing.py`
  sets that very variable in the environment of the test command, under a
  comment giving this reason, so a session writes no `.pyc` at all — the
  baseline included, both measured by looking at `__pycache__` before and
  after a real `cosmic-ray exec`. Grepping the package for
  `dont_write_bytecode` finds nothing and means nothing: the string it
  sets is the environment variable's own spelling. What no flag stops is
  a *read*, so a `.pyc` already on disk from an earlier `pytest` is still
  used where its size and truncated mtime match — which is the same
  window as above, and the reason the hand recipe wants the control run
  and not only the variable
- **`detect-secrets` runs twice, over two baselines**: the tree with the
  entropy detectors on, and `tests/*.csv`/`tests/*.json` with them off,
  those files being hex and nothing else. Adding to either side fails its
  hook until that baseline is regenerated; both commands are in
  CONTRIBUTING.md, and reading the diff is the point of a baseline
- **the `published` workflow went green with 0.7.1**, on 4 August 2026,
  nineteen cells out of nineteen, having been nineteen out of nineteen red
  the day before: 0.4.0 had no arm64 wheel and its sdist no longer built,
  so that red was a fact about what users could install rather than a
  broken workflow. A red there still means the outside world moved, which
  is why it is a workflow of its own and not a job of `release`

## Verifying, rather than reasoning about, a change

The build matrix is expensive — tens of jobs compiling C — and this
package exists to behave identically everywhere, so a claim about it is
worth a command:

- run the thing. A local `pre-commit` pass is not evidence that CI passes
  if the runner has a tool this machine lacks
- when adding a check, hand it something bad and watch it fail. Every hook
  here was verified that way
- prefer reading a log to predicting one: `gh run view <id> --log-failed`
- read exit codes, not filtered output: `… | grep -v Passed` is a habit
  that eventually reports a failure as a success
- a claim about another repository, or about what a published version
  does, is measurable too: install it in an isolated environment and look

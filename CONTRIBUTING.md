# How to contribute

Thank you for investing your time in this project. What follows is how to
build, test and benchmark these bindings, and what this repository
expects of a change. What the build itself does on each platform is in
the [Build](README.md#build) section of the README, which is not repeated
here.

Please read the [Code of Conduct](CODE_OF_CONDUCT.md) too.

## Which project is this

These are thin python bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). Three
repositories are easy to confuse, and an issue in the wrong one is slow
to route:

- the cryptography is upstream, in
  [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1/issues).
  It is vendored as the `secp256k1` submodule and only ever read from: a
  flaw in the library itself is not ours to fix
- anything with state of its own — a wallet, a transaction, a signing
  session — belongs in
  [btclib](https://github.com/btclib-org/btclib/issues), which is what
  these bindings are for. The Design section of the README says where the
  line is
- what belongs here is how the bindings drive the library: the wrapping,
  the argument validation at the cffi boundary, the packaging, and the
  wheels

A vulnerability is never an issue: see the
[security policy](SECURITY.md).

## Opening an issue

Search the [issues](https://github.com/btclib-org/btclib_libsecp256k1/issues)
and [pull requests](https://github.com/btclib-org/btclib_libsecp256k1/pulls)
first, then use one of the
[forms](https://github.com/btclib-org/btclib_libsecp256k1/issues/new/choose).
The bug form asks which of the three artifacts is installed — a static
wheel, a dynamic one, or a build from the sdist — because they differ in
how libsecp256k1 is linked and a bug is rarely in all three.

Issues are not assigned to anyone: if one interests you, you are welcome
to open a pull request for it.

## Building and testing

The btclib_libsecp256k1 project includes
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
as submodule in the secp256k1 folder.
By default, when cloning a project you get the directories that contain
submodules, but none of the files within them.
You must run `git submodule init` to initialize
your local configuration file,
and `git submodule update` to fetch the submodule data
and check out the appropriate commit.

<!-- markdownlint-disable MD013 -->
    $ git submodule init
    Submodule 'secp256k1' (https://github.com/bitcoin-core/secp256k1.git) registered for path 'secp256k1'
    $ git submodule update
    Cloning into 'secp256k1'...
<!-- markdownlint-enable MD013 -->

The project uses [uv](https://docs.astral.sh/uv/) to manage the
development environment. The interpreter it is built on is pinned in
`.python-version`, and uv installs it if missing: neither pyenv nor a
hand-made virtualenv is needed. The development dependencies are the
PEP 735 groups declared in `pyproject.toml`.

    uv sync

This also builds and installs the extension in editable mode, so the
C toolchain the README describes must be available.

To build:

    uv build --sdist
    uv build --wheel

To test:

    uv run pytest

To measure the code coverage provided by tests:

    uv run pytest --cov

Coverage is measured in branch mode and gated by the `fail_under`
ratchet in `pyproject.toml`; the same check runs in CI.

To run everything CI checks before a PR, i.e. the formatter, the
linters and the type checker:

    uv run pre-commit run --all-files

To time these bindings against the other python wrappers of
libsecp256k1, and against the pure python implementation of btclib:

    uv run --group bench scripts/benchmark.py

That group is not part of `dev`, and installing it is a choice: btclib
depends on this package, so it cannot be a dependency of developing it,
and `coincurve` and `secp256k1` build a libsecp256k1 of their own, which
needs `pkg-config` besides the C toolchain.

To test against another supported interpreter, bypass the build cache:
uv keys it on the sources, which do not tell it that the compiled
extension belongs to one ABI version only.

    uv run --python 3.10 --no-cache pytest

On a Windows arm64 machine, mind which interpreter that request gets:
uv installs an x86-64 one unless the architecture is named
(`--python cpython-3.13-windows-aarch64`), reporting that support for
the native architecture is not yet mature. Both work — the build follows
the interpreter — but only the native one exercises what the `win_arm64`
wheels are.

Beware that this replaces `.venv` with an environment built on that
interpreter, and leaves it there. Going back is another `uv sync`, and
`--reinstall-package btclib_libsecp256k1 --no-cache` if the extension it
finds in the cache is the one of the ABI just left behind. Requesting a
free-threaded interpreter (`--python 3.14t`) has a second effect: it
installs it as a managed one, and `uv sync` then prefers it to a system
3.14, so `uv python install 3.14` is what makes the default environment
reproducible again.

### Running what CI runs

Each job of the `lint` and `test` workflows, and the local command that
reproduces it. Two of them cannot be reproduced on a machine that is not
the runner, and that is worth knowing before trying.

- `Lint and type-check`

      uvx pre-commit run --all-files

- `Coverage`

      uv run --locked --no-default-groups --group test pytest --cov

- `Test <version> on <os>`, one row of the matrix

      uv run --python 3.10 --no-cache pytest

- `Build wheels on <os>`, for this platform only

      uv run --only-group build cibuildwheel

  the Linux wheels of that job are built in a manylinux container, so
  reproducing them needs a container runtime (`colima` on macOS)

- `Build dynamic wheel on <os>`

      BTCLIB_LIBSECP256K1_DYNAMIC=true uv build --wheel

- `Build sdist`, and `Test sdist install on <os>` after it

      uv build --sdist
      python -m pip install --verbose dist/*.tar.gz   # in a fresh venv

- `Validate distributions`

      uv run --locked --only-group check twine check --strict dist/*
      uv run --locked --only-group check check-wheel-contents dist/*.whl
      uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz

- `Build on Linux for Windows` needs `mingw-w64`, and a Linux host to be
  faithful: the cross-compilation CI does is from ubuntu, not from macOS

- `Build the documentation`, the same command `.readthedocs.yaml` runs
  and `docs/README.rst` documents. Needs the submodule checked out,
  unlike btclib's own equivalent job: every `automodule` directive
  imports this package, which means compiling libsecp256k1 first

      git submodule update --init
      uv run --locked --no-default-groups --group docs \
          sphinx-build -W --keep-going -b html docs/source docs/build/html

The `published` workflow has no local equivalent by design: what it
installs is what PyPI serves.

The three sentinels beside it gate nothing, so a red one is read in the
Actions tab rather than fixed on a branch. Each is dispatchable, and two of
them run locally.

- `latest`, which resolves every dependency at its newest before running
  the suite. The upgrade rewrites `uv.lock`, so restore it afterwards with
  `git checkout uv.lock`:

      uv lock --upgrade
      uv run --locked --no-default-groups --group test pytest

- `links` needs a tool uv does not provide, lychee being a rust binary, so
  the workflow uses the action. `.lycheeignore` holds the URLs a checker
  cannot judge, each with the reason it cannot be checked rather than the
  reason checking it is inconvenient

- `mutation`, scoped by `.github/mutation/bindings.toml`, which is what the
  workflow reads too:

      uv run --locked --no-default-groups --group test --group mutation \
          cosmic-ray baseline .github/mutation/bindings.toml
      uv run --locked --no-default-groups --group test --group mutation \
          cosmic-ray init .github/mutation/bindings.toml bindings.sqlite
      uv run --locked --no-default-groups --group test --group mutation \
          cosmic-ray exec .github/mutation/bindings.toml bindings.sqlite
      uv run --locked --no-default-groups --group test --group mutation \
          cr-report --surviving-only --show-diff bindings.sqlite

  `baseline` first, always: it runs the configured test command against the
  unmutated tree, and without it a stale command fails every mutant
  identically and the session reports a perfect kill rate — the one failure
  mode of a mutation run that looks like good news. The session mutates the
  source in place and restores it, so nothing else may read the tree while
  it runs: no second session, no `pytest` in another shell, and a
  `git status` in the middle is a working tree with a mutant in it. `exec`
  is resumable, so interrupting one costs only the mutant it was on, and the
  `.sqlite` is the artifact the workflow uploads — `cr-report`, `cr-html`
  and `cr-rate` all read one.

  `--surviving-only` is the whole of what anybody acts on, a killed mutant
  being the suite doing its job. Read the list expecting two shapes that are
  not holes: `core/ReplaceBinaryOperator` on a signature line is an
  annotation, which `from __future__ import annotations` leaves unevaluated,
  and an output buffer or a piece of internally generated randomness has a
  size nothing observable depends on. Anything else is a test nobody has
  written yet.

## What a change has to satisfy

Development happens on `dev`, so that is what a pull request targets;
`master` only ever receives merges from it, and a tag on `master` is a
release.

- **the pre-commit hooks pass.** `uv run pre-commit run --all-files` runs
  the formatter, the linters and the type checker; the `lint` workflow
  runs that very configuration, so what CI enforces is what the hook
  does. `uvx pre-commit install` makes it a commit hook
- **the tests pass with full coverage.** `uv run pytest --cov`; the
  `fail_under` ratchet in `pyproject.toml` is what makes the number mean
  something, so new code arrives with the tests that cover its branches
- **the secret-scanning baseline follows the vectors.** The test data is
  private keys, so `detect-secrets` would report all of it; the known
  findings live in `.secrets.baseline`, reviewed once. Adding to
  `tests/ecdsa_sig.json` or `tests/ecdsa_custom_nonce_sig.json` therefore
  fails that hook until the baseline is regenerated:

      uvx --from detect-secrets detect-secrets scan \
          --baseline .secrets.baseline

  read the diff before committing it, which is the whole point of the
  baseline: what appears there is what nobody has looked at yet
- **new wrapped functionality is validated against external vectors.**
  A test that compares these bindings against themselves proves nothing.
  `tests/test_vectors.py` documents where each vendored vector file comes
  from — BIP340, RFC6979, trezor-firmware — and a new wrapper should
  reach for something published elsewhere in the same way
- **a new wrapper checks sizes and delegates the rest.** What the
  boundary is for is stopping a short buffer from reaching a bare
  pointer; whether the bytes are a valid key, point or signature is
  libsecp256k1's answer to give, and an argument of the wrong size or
  form raises rather than being padded or reinterpreted into a valid one.
  The reasoning is in the README, under What the boundary checks
- **the prose satisfies the section below.** The workflows, the build
  scripts and the configuration files in this repository carry the
  reasoning behind their choices, because that is the part a reader
  cannot recover, and a hook can check that a docstring exists but not
  what it says
- **the vendored submodule moves on purpose.** Bumping `secp256k1` is a
  change of what this package wraps: it belongs in its own pull request,
  with the version named in the README and in `HISTORY.md` moved with it.
  Dependabot signals upstream movement but tracks the default branch, so
  a release always needs the tagged commit

### Documentation and comments

What "satisfies" means for the prose is written down here, because a hook
can check that a docstring exists and not what it says. It governs the
workflows, `pyproject.toml` and `.pre-commit-config.yaml` as much as the
package: the reasoning with its negative results is what makes those
files reviewable rather than merely readable.

**Tone of voice: neutral, factual, dry.** The same register everywhere:
no jokes, no salesmanship, no emphasis where the fact is enough.
Explanatory detail is wanted; decoration is not.

**A docstring states the contract.** What the function takes, what it
returns or raises, and the rule the behaviour comes from — not a
restatement of the name. A test's docstring states what it verifies: the
property, the published vector, the failure mode, and which side of the
assertion is the independent one. That last part is why a docstring is
required of a test at all — the name says which call is under test, which
is not the same as what is being claimed about it.

**A comment carries the reasoning, including the negative result.** Say
why the code is as it is and why *not* the obvious alternative. The second
half is what stops the next reader from "fixing" a deliberate choice, and
it is why this repository's configuration files are as long as they are.

**Cite the authority.** Where behaviour comes from a BIP, an RFC, or
libsecp256k1 itself, name it rather than asserting the behaviour as if
these bindings had decided it. Where they deviate, say so and say why.

**Measure, don't assert.** A number in prose comes from a command, and the
command belongs beside it, so the next reader can re-measure instead of
trusting a figure whose date they cannot see. Never state a count that
nothing checks — an unchecked number drifts into a false claim — and never
state how many of anything a file or a matrix holds: a stated total is a
line every open branch has to edit, and two branches moving it to the same
wrong number merge without a conflict. A dated measurement is the
exception, and it is dated for exactly that reason.

**One fact in one place.** Two files stating the same thing become two
files disagreeing about it; the second one points at the first. That is
why [REPOSITORY.md](REPOSITORY.md) holds the repository settings and
CLAUDE.md points at it.

**No history in the prose.** Comments and docstrings say why the code is
as it is, in the present tense; they do not tell the story of what it used
to be. "This is here rather than X because X breaks Y" stays, whatever
prompted it; "this used to be X, until Z" goes — unless the old spelling
is something a caller can still encounter, in which case it is not history
but the present. History has a file of its own,
[HISTORY.md](HISTORY.md), and the commit messages.

## Pull requests

The whole build and test matrix — tens of jobs, each compiling
libsecp256k1 from source — runs on every pull request and on every push
to it, which is deliberate: this package exists to be identical
everywhere. It does mean a draft pull request is the polite place for
work in progress.

Link the issue the pull request solves, allow maintainer edits so the
branch can be updated for a merge, and mark review conversations
resolved as you address them.

**A correction is a commit of its own, never an amend.** Once a branch is
pushed and under review, `git commit --amend` and a force-push replace the
commits the review is attached to: the reviewer loses the diff they read,
"changes since your last review" has nothing to compare against, and every
one of those matrix jobs starts again from a commit nobody has seen. Add
the fix on top, with a message saying what it fixes, and reply to the
comment with the sha. The one force-push that stays right is the one
carrying no new work — a `git rebase origin/dev` on a branch whose base has
moved — and it wants the gates re-run after it, not only before, and a note
in the pull request saying the head moved.

Nothing is lost in `dev`'s history by working that way, because a pull
request is squashed on merge: the branch lands as one commit whose subject
is the pull request title with its number, so the review's commits are the
record of the review and `dev` keeps one commit per landed change. All
three merge buttons are enabled on this repository, so which one is used
is a choice made at the merge rather than one GitHub enforces — check it
before clicking, `dev` into `master` being the case that wants a different
answer, a release having to keep the commits a tag was cut from.

Releases are cut by a maintainer, following [RELEASING.md](RELEASING.md);
nothing about a version needs to be touched in a pull request.

Once merged, your contribution is visible on the
[contributors page](https://github.com/btclib-org/btclib_libsecp256k1/graphs/contributors).

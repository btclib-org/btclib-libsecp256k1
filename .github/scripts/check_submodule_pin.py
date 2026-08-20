# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The vendored libsecp256k1 is the release README.md says it is.

`version-check` in .github/workflows/release.yml asks this of upstream,
over the network, and refuses to publish when the answer is no. That is
the last gate before publication and it stays. What this is, is the same
question asked of every commit instead of every release, so that a
submodule bump and the prose about it cannot disagree for the length of
a cycle -- which is the window in which CHANGELOG.md, RELEASE_NOTES.md
and README.md are written about the version nobody has confirmed.

Offline is what makes it a hook rather than a workflow step. The tag is
resolved in the vendored clone, whose refs are already on the machine, so
nothing here reaches the network and nothing goes red because github.com
is unreachable. The half only the network can answer -- that the tag is
upstream's, and that its signature is a maintainer's -- is the job of the
same name in .github/workflows/vendored-vectors.yml, which is a sentinel
for exactly that reason.

Two commands, and what they answer:

    git ls-tree HEAD secp256k1          the commit this tree pins
    git -C secp256k1 rev-parse <tag>^{commit}   what README.md's tag is

Run by the `submodule-pin` hook of .pre-commit-config.yaml, and so by the
lint workflow, on every commit rather than on the two paths that can
break the agreement: pre-commit cannot filter on the gitlink, for the
reason that hook's own comment gives, and two git invocations are cheap
enough that it does not have to.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# resolved once: a bare "git" in a subprocess list is what S607 is about,
# the same way .github/scripts/check_vendored_vectors.py resolves gh
_GIT = shutil.which("git") or "git"

# what git puts in the environment of a hook, and what has to come back
# out of it before git is run anywhere else. These name *this*
# repository, and `-C secp256k1` does not override them: with GIT_DIR set
# the tag is looked for in the wrong repository and is not found. It
# shows only from the git hook -- a `pre-commit run` in a terminal sets
# none of them, and passed on the very tree the commit then refused
_INHERITED = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_PREFIX",
    "GIT_NAMESPACE",
)

_ROOT = Path(__file__).resolve().parents[2]
_SUBMODULE = "secp256k1"

# the release README.md names, as the url of an upstream release tag. The
# same expression release.yml reads it with, which is what keeps the two
# checks about one line of prose rather than two
_NAMED = re.compile(r"secp256k1/releases/tag/(v[0-9][0-9.]*)")


def named_release(readme: str) -> str | None:
    """Return the libsecp256k1 release README.md names, or None.

    Args:
        readme: the text of README.md.

    Returns:
        The first release tag it links to, or None where it links to no
        upstream release at all -- which is a failure of its own and not
        a check that passes vacuously.
    """
    match = _NAMED.search(readme)
    return match[1] if match else None


def _git(*args: str, cwd: Path | None = None, disown: bool = False) -> str | None:
    """Run git and return its stdout, or None where it failed.

    A failure is an answer here rather than an exception: an unknown tag
    and an uninitialized submodule both come back as one, and each is
    reported by the caller in its own words.

    Args:
        *args: the git arguments, the executable excluded.
        cwd: the directory to run in, the repository root by default.
        disown: whether to drop the repository git names in the
            environment, which a run against any other one has to.

    Returns:
        The stripped stdout, or None if git exited non-zero.
    """
    env = None
    if disown:
        env = {k: v for k, v in os.environ.items() if k not in _INHERITED}
    result = subprocess.run(  # noqa: S603
        [_GIT, *args],
        cwd=cwd or _ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def pinned_commit() -> str | None:
    """Return the commit the index pins the submodule to.

    The index, and not `HEAD`: a hook runs on what is about to be
    committed, and the commit that moves the submodule is the one this
    check exists for. `git ls-tree HEAD` would read the pin of the
    commit *before* it and compare that with a README.md already saying
    the new release -- failing every bump, and for a reason that is not
    the one it would report. The two agree in a clean tree, which is
    every run of the lint workflow.

    Read from the index rather than from the submodule's own HEAD for a
    second reason: the gitlink is in this repository's tree, and it is
    there whether or not the submodule has been checked out.

    Returns:
        The 40-hex commit, or None if the index has no such gitlink.
    """
    line = _git("ls-files", "--stage", "--", _SUBMODULE)
    if not line:
        return None
    fields = line.split()
    # mode, object, stage, path -- and 160000 is the gitlink mode, which
    # is what tells a submodule from a file that happens to be named so
    return fields[1] if len(fields) == 4 and fields[0] == "160000" else None


def _checked_out(path: Path) -> bool:
    """Whether a submodule has a `.git` of its own under `path`.

    `-C path` does not stop git from discovering a repository above
    `path` when `path` has no `.git` -- a fresh `git worktree add` does
    not initialize submodules, so `path` can exist, empty, with the
    wrapper repository one directory up being the first `.git` upward
    discovery finds. Checking for `path/.git` directly, before any git
    command runs in it, is what keeps that discovery from having
    anywhere to walk to: a submodule's `.git` is a file pointing at its
    module elsewhere, a plain clone's is a directory, and `Path.exists`
    reads either without caring which.

    Args:
        path: the submodule's working directory.

    Returns:
        True where `path/.git` exists, False where the submodule was
        never initialized (or `path` itself does not exist).
    """
    return (path / ".git").exists()


def commit_of(tag: str) -> str | None:
    """Return the commit a tag names in the vendored clone.

    Args:
        tag: the release tag, as README.md names it.

    Returns:
        The 40-hex commit the tag resolves to, or None where the clone
        does not have that tag -- an uninitialized submodule, or a
        shallow checkout carrying no tags.
    """
    if not _checked_out(_ROOT / _SUBMODULE):
        return None
    return _git(
        "rev-parse",
        "--verify",
        "--quiet",
        f"{tag}^{{commit}}",
        cwd=_ROOT / _SUBMODULE,
        # a different repository, so the hook environment goes
        disown=True,
    )


def why_no_tag(tag: str) -> str:
    """Say which of the three states a clone without that tag is in.

    One message for all three used to be enough for a developer, who has
    one of them; it is not enough for a checkout somebody else makes,
    where which state it is *is* the finding. pre-commit.ci is that
    checkout: told to take the submodule it takes it, and the hook failed
    all the same, with a message that could not say whether the clone was
    missing or merely shallow.

    Args:
        tag: the release tag that could not be resolved.

    Returns:
        A sentence naming the state and what would change it.
    """
    if not _checked_out(_ROOT / _SUBMODULE):
        return (
            f"the {_SUBMODULE} submodule is not checked out, so nothing here"
            " can resolve a tag: git submodule update --init"
        )
    if (
        _git(
            "rev-parse", "--is-shallow-repository", cwd=_ROOT / _SUBMODULE, disown=True
        )
        == "true"
    ):
        return (
            f"the vendored clone is shallow and carries no {tag} tag:"
            " git -C secp256k1 fetch --unshallow --tags, or check the"
            " submodule out with fetch-depth 0"
        )
    return (
        f"the vendored clone has no {tag} tag, though it is neither absent"
        " nor shallow: git -C secp256k1 fetch --tags"
    )


def main() -> int:
    """Compare the pin with the release the prose names.

    Returns:
        0 where they agree, 1 where they do not or where the question
        could not be asked -- which is a failure too: a check that
        cannot read its inputs has not passed.
    """
    pinned = pinned_commit()
    if pinned is None:
        print(f"no {_SUBMODULE} submodule in this tree", file=sys.stderr)
        return 1

    named = named_release((_ROOT / "README.md").read_text(encoding="utf-8"))
    if named is None:
        print(
            "README.md links to no libsecp256k1 release: the version this"
            " package wraps is named there, and release.yml reads it from"
            " that same line",
            file=sys.stderr,
        )
        return 1

    tagged = commit_of(named)
    if tagged is None:
        print(why_no_tag(named), file=sys.stderr)
        return 1

    if tagged != pinned:
        print(
            f"README.md names {named} ({tagged[:7]}), and the submodule is"
            f" pinned to {pinned[:7]}. The submodule moves in a change of"
            " its own, with the version named in README.md and"
            " RELEASE_NOTES.md moved with it",
            file=sys.stderr,
        )
        return 1

    print(f"the submodule is pinned to {named} ({pinned[:7]}), as README.md says")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

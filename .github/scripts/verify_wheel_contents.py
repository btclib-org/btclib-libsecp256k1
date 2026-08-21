# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Check a built wheel against an allowlist of its members.

`twine check`, `check-wheel-contents` and `pyroma` read the *metadata* of
a wheel: whether it is syntactically valid, whether the long description
renders, whether the classifiers a package should declare are there.
None of them reads every member, and what is in the archive is what a
user installs.

`check-wheel-contents --package btclib_secp256k1`, configured in
`pyproject.toml` for `btclib`, is the closest built-in answer, and it
does not fit here: it diffs the wheel's whole library against the one
named package tree, and this package's wheel is not one package tree.
Every wheel this project ships also carries a compiled artifact at the
wheel's own root, beside `btclib_secp256k1/` rather than inside it -- the
extension module for a static wheel, that module's ABI-mode source and
the shared `libsecp256k1` for a dynamic one -- which `--package` reports
as "files not in package tree" whether or not they are the ones this
project intends. `[tool.check-wheel-contents]` keeps `ignore = ["W003",
"W009"]` for the same reason, on the dynamic wheel specifically: the
checks those codes name are about a *non-package* file at the top level,
which for this project's dynamic wheel is not a mistake but the shared
library.

Three questions, and what answers them:

**Which top-level artifact must be there.** A wheel's tag says whether it
is static (an `infer_tag`ed `cpNN-...`, one compiled extension) or
dynamic (`py3-none-<platform>`, an ABI-mode module and the shared library
beside it) -- `scripts/hatch_build.py`'s own distinction, and this reads
the same tag it writes. Which artifacts a wheel of that kind must carry,
and refusing an extra one -- a stray file that is not part of
`btclib_secp256k1/` and not one of them -- is what `--package` cannot
phrase without also refusing the artifact that belongs.

**Whether the artifact is really there**, and not a zero-byte member a
half-finished build step left behind: `scripts/cffi_build.py` raises when
it cannot find one to copy, not when it copies an empty one, so an empty
file is a shape that check has no report for. `toplevel_reason` below
checks the kind-appropriate artifact for size as well as presence, which
none of `check-wheel-contents`'s codes do for any member.

**Whether `btclib_secp256k1/` itself is complete.** Everything under
that directory in the wheel has to be everything the checkout has under
it -- source, `py.typed`, nothing more and nothing less -- which is
`--package`'s own question, asked here by hand rather than through a
flag that would also judge the sibling artifact.

The sdist is not this script's subject. `btclib`'s sibling script checks
it because `MANIFEST.in` there is an *include* list -- a file the tree
gains and MANIFEST.in does not name is a file the sdist silently drops,
which is the failure this whole class of check exists for.
`[tool.hatch.build.targets.sdist] exclude` here is the opposite shape: a
file the tree gains ships by default, and has to be named to be left
out, so the failure mode is an sdist too wide rather than one silently
narrow. What that leaves unchecked -- an exclude pattern that lists a
file this build still needs -- is a build failure, not a silent gap,
which is a different question with a different check to answer it.

Run it against one built wheel:

    uv run --no-project --python 3.14 \\
        .github/scripts/verify_wheel_contents.py dist/*.whl

`test.yml`'s `check-dist` job runs it on every wheel it downloads --
`build-cibuildwheel`, `build-dynamic` and `build-windows` between them --
which are the artifacts `release.yml`'s own `test` job produces and the
publish jobs upload: one build, checked and shipped, so this judges the
files this project actually publishes rather than a copy of them.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# the package this repository ships, read fresh from the checkout rather
# than hard-coded: a module added to it is a module the next wheel has to
# carry, and a copy of the file list here would drift the day one is
# added or removed without anybody editing this script to match
PACKAGE_DIR = Path(__file__).parents[2] / "btclib_secp256k1"

# no member of this wheel carries any of these, whichever top-level
# artifact the kind below admits: a `.pth` executes at interpreter
# startup, before the first import; a `.pyc` is a compiled module nobody
# reviewed; an archive inside an archive is a second package installing
# with the first. Checked against `btclib_secp256k1/` and the
# top-level artifact -- not against `.dist-info`, which is already
# validated member by member, against its own allowlist, above
FORBIDDEN_SUFFIXES = (".egg", ".pth", ".pyc", ".tar.gz", ".whl", ".zip")
FORBIDDEN_NAMES = ("sitecustomize.py", "usercustomize.py")

# what hatchling writes into `.dist-info`, and no more. No
# `top_level.txt`: that is a setuptools file, and this build backend is
# hatchling
WHEEL_METADATA_FILES = frozenset({"METADATA", "RECORD", "WHEEL"})
# `license-files` in pyproject.toml, copied into `licenses/` verbatim
WHEEL_LICENSE_FILES = frozenset({"AUTHORS.md", "COPYRIGHT", "LICENSE"})

# suffixes a compiled extension module carries, keyed by platform: cffi's
# static path compiles one of these, named `_btclib_secp256k1` with an
# ABI tag before the suffix on POSIX (cffi's own convention) and without
# one on Windows -- `scripts/cffi_build.py`'s MSVC path names the
# extension `_btclib_secp256k1.pyd` outright
EXTENSION_SUFFIXES = (".so", ".pyd")
# the shared library a dynamic wheel carries beside the ABI-mode module,
# by the platform suffix `shared_library_extension` in cffi_build.py
# names for it. No version suffix: the same function skips a candidate
# with more than one, which is the symlink chain's own name and not the
# file CMake just built
SHARED_LIBRARY_SUFFIXES = (".dll", ".dylib", ".so")


def wheel_kind(name: str) -> str:
    """Return "static" or "dynamic" for the wheel named `name`.

    The python tag is the second-to-last dash-separated field before the
    platform tag in a three-tag wheel name, and it is what
    scripts/hatch_build.py itself sets: `py3-none-<platform>` for a
    dynamic wheel, an inferred `cpNN-cpNN-<platform>` for a static one.
    Reading the filename rather than the `WHEEL` file's Root-Is-Purelib
    line: that line is `false` for both kinds here, since the build hook
    clears `pure_python` before either is tagged.
    """
    tags = name[: -len(".whl")].split("-")
    return "dynamic" if tags[-3] == "py3" else "static"


def toplevel_reason(members: set[str], kind: str) -> str | None:
    """Say why the wheel's top-level artifact does not match `kind`.

    Returns None if it does. `members` is every member outside
    `btclib_secp256k1/` and the `.dist-info` directory.
    """
    if kind == "static":
        matches = [
            m
            for m in members
            if m.startswith("_btclib_secp256k1") and m.endswith(EXTENSION_SUFFIXES)
        ]
        rest = members - set(matches)
        if len(matches) != 1 or rest:
            return (
                "a static wheel carries exactly one _btclib_secp256k1 extension "
                f"module and nothing else at its root; found {sorted(members)}"
            )
        return None
    py_module = "_btclib_secp256k1.py"
    libs = [
        m
        for m in members
        if m.startswith("libsecp256k1") and m.endswith(SHARED_LIBRARY_SUFFIXES)
    ]
    rest = members - {py_module, *libs}
    if py_module not in members or len(libs) != 1 or rest:
        return (
            "a dynamic wheel carries _btclib_secp256k1.py and one "
            f"libsecp256k1 shared library and nothing else at its root; "
            f"found {sorted(members)}"
        )
    return None


def forbidden_reason(path: str) -> str | None:
    """Say why this member may never be in the wheel, or None."""
    name = path.rsplit("/", 1)[-1]
    if name in FORBIDDEN_NAMES:
        return f"is {name}, which Python imports at startup"
    for suffix in FORBIDDEN_SUFFIXES:
        if path.endswith(suffix):
            return f"carries the forbidden suffix {suffix}"
    if "__pycache__" in path.split("/"):
        return "is under __pycache__"
    return None


def package_payload_complaints(members: set[str]) -> list[str]:
    """Diff the wheel's `btclib_secp256k1/` against this checkout's.

    What `check-wheel-contents --package btclib_secp256k1` would report,
    asked directly instead: every check against the checkout beside this
    tree, and so every complaint this function returns, applies equally
    to a wheel judged in the sdist-install jobs, which have no compiled
    artifact for `toplevel_reason` to be right or wrong about.
    """
    on_disk = {
        f"btclib_secp256k1/{path.relative_to(PACKAGE_DIR)}"
        for path in PACKAGE_DIR.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    missing = on_disk - members
    extra = members - on_disk
    complaints = [f"btclib_secp256k1/ is missing {name}" for name in sorted(missing)]
    complaints += [
        f"wheel carries {name}, not in the checkout" for name in sorted(extra)
    ]
    return complaints


def verify_wheel(wheel: Path) -> list[str]:
    """Return every complaint about the wheel at `wheel`."""
    kind = wheel_kind(wheel.name)
    distribution, version = wheel.name.split("-")[:2]
    dist_info = f"{distribution}-{version}.dist-info"

    with zipfile.ZipFile(wheel) as archive:
        infos = [info for info in archive.infolist() if not info.filename.endswith("/")]
        sizes = {info.filename: info.file_size for info in infos}
    members = set(sizes)

    complaints = []

    dist_info_members = {m for m in members if m.startswith(f"{dist_info}/")}
    package_members = {m for m in members if m.startswith("btclib_secp256k1/")}
    toplevel_members = members - dist_info_members - package_members

    for name in dist_info_members:
        relative = name[len(dist_info) + 1 :]
        if relative in WHEEL_METADATA_FILES:
            continue
        if relative.startswith("licenses/") and relative[len("licenses/") :] in (
            WHEEL_LICENSE_FILES
        ):
            continue
        complaints.append(f"{name} is under {dist_info}/ and is not one of its files")
    required_dist_info = WHEEL_METADATA_FILES | {
        f"licenses/{name}" for name in WHEEL_LICENSE_FILES
    }
    complaints += [
        f"{dist_info}/{name} is missing"
        for name in sorted(
            required_dist_info - {m[len(dist_info) + 1 :] for m in dist_info_members}
        )
    ]

    for name in package_members | toplevel_members:
        reason = forbidden_reason(name)
        if reason is not None:
            complaints.append(f"{name} {reason}")

    complaints += package_payload_complaints(package_members)

    toplevel_error = toplevel_reason(toplevel_members, kind)
    if toplevel_error is not None:
        complaints.append(toplevel_error)
    else:
        for name in toplevel_members:
            if sizes[name] == 0:
                complaints.append(f"{name} is present and empty")

    return [f"{wheel.name}: {c}" for c in complaints]


def main(argv: list[str]) -> int:
    """Verify every wheel named on the command line."""
    if len(argv) < 2:
        print(f"usage: {argv[0]} <wheel> [<wheel> ...]", file=sys.stderr)
        return 2

    complaints = [c for arg in argv[1:] for c in verify_wheel(Path(arg))]
    for complaint in complaints:
        # the workflow annotation, so a failure is readable from the run
        # summary rather than only from the log
        print(f"::error::{complaint}", file=sys.stderr)
    if not complaints:
        for arg in argv[1:]:
            print(f"{Path(arg).name}: carries what it may and no more")
    return 1 if complaints else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

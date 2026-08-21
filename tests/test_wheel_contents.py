# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the wheel-content check of `.github/scripts`.

What CI can show is that a real build passes: `test.yml`'s `check-dist`
job runs the script on every wheel it downloads. What CI cannot show is
that anything *fails* -- a wheel with a second compiled extension in it
is not something a workflow can produce on purpose -- so the archives
here are synthetic, one member planted per rule, and the assertion is
the complaint.

The last two tests ask a different question: whether
`docs/source/package-content-policy.md` states the same policy. A page
beside a script is a second copy of one list, and two copies are one
that can be wrong -- the page saying `.so` is a shared-library suffix
while the script's tuple does not carry it, with nothing to notice.
Those two compare the page against the script's own constants in both
directions, the same way `btclib`'s own
`tests/verify_dist_contents_test.py` does; the parsing helpers below are
copied from there rather than written twice, the two pages having the
same "list stated by the paragraph naming it" shape.

The script is loaded by path, `.github/scripts` being no package, as
`test_submodule_pin.py` loads its own subject.
"""

from __future__ import annotations

import importlib.util
import re
import runpy
import sys
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "verify_wheel_contents.py"
_PAGE = Path(__file__).parents[1] / "docs" / "source" / "package-content-policy.md"

_VERSION = "0.8.0.5"
_DIST_INFO = f"btclib_secp256k1-{_VERSION}.dist-info"

# the smallest static wheel that passes: the package, its typed marker,
# the compiled extension, and the metadata hatchling writes
_PACKAGE = ("btclib_secp256k1/__init__.py", "btclib_secp256k1/py.typed")
_DIST_INFO_MEMBERS = (
    f"{_DIST_INFO}/METADATA",
    f"{_DIST_INFO}/RECORD",
    f"{_DIST_INFO}/WHEEL",
    f"{_DIST_INFO}/licenses/AUTHORS.md",
    f"{_DIST_INFO}/licenses/COPYRIGHT",
    f"{_DIST_INFO}/licenses/LICENSE",
)


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    """Return the script, imported by path, reading a fake checkout.

    `PACKAGE_DIR` is a module-level constant computed from `__file__` at
    import time, so it is patched after the fact rather than by
    controlling where the script is loaded from -- the script itself
    stays at its real path, which is what the pairing tests below read
    the source of.
    """
    spec = importlib.util.spec_from_file_location("verify_wheel_contents", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    package_dir = tmp_path / "btclib_secp256k1"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "py.typed").write_text("", encoding="utf-8")
    monkeypatch.setattr(module, "PACKAGE_DIR", package_dir)
    return module


def write_wheel(
    path: Path,
    *,
    kind: str = "static",
    extra: tuple[str, ...] = (),
    omit: tuple[str, ...] = (),
    empty: tuple[str, ...] = (),
) -> Path:
    """Write a wheel at `path` and return it.

    `kind` selects the tag and the top-level artifact a clean wheel of
    that kind carries; `extra`, `omit` and `empty` perturb the member
    set from there, `empty` writing a zero-byte member instead of one
    with content.
    """
    toplevel = (
        ("_btclib_secp256k1.cpython-314-darwin.so",)
        if kind == "static"
        else ("_btclib_secp256k1.py", "libsecp256k1.dylib")
    )
    members = {*_PACKAGE, *_DIST_INFO_MEMBERS, *toplevel, *extra} - set(omit)

    with zipfile.ZipFile(path, "w") as archive:
        for member in sorted(members):
            archive.writestr(member, b"" if member in empty else b"x")
    return path


def test_a_clean_static_wheel_has_no_complaints(
    script: ModuleType, tmp_path: Path
) -> None:
    """The smallest passing static wheel is accepted."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl"
    )
    assert script.verify_wheel(wheel) == []


def test_a_clean_dynamic_wheel_has_no_complaints(
    script: ModuleType, tmp_path: Path
) -> None:
    """The smallest passing dynamic wheel is accepted."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-py3-none-any.whl", kind="dynamic"
    )
    assert script.verify_wheel(wheel) == []


@pytest.mark.parametrize("member", ["btclib_secp256k1/x.pth", "btclib_secp256k1/x.egg"])
def test_a_forbidden_suffix_under_the_package_is_refused(
    script: ModuleType, tmp_path: Path, member: str
) -> None:
    """Every suffix `FORBIDDEN_SUFFIXES` names is refused."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=(member,),
    )
    complaints = script.verify_wheel(wheel)
    assert any(member in c for c in complaints)


def test_a_forbidden_name_under_the_package_is_refused(
    script: ModuleType, tmp_path: Path
) -> None:
    """`sitecustomize.py` under the package is refused by name."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=("btclib_secp256k1/sitecustomize.py",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("sitecustomize.py" in c for c in complaints)


def test_pycache_is_refused_by_name(script: ModuleType, tmp_path: Path) -> None:
    """A `__pycache__` member fails, whether or not it carries a `.pyc`."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=("btclib_secp256k1/__pycache__/x",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("__pycache__" in c for c in complaints)


def test_a_dist_info_member_outside_the_allowlist_is_refused(
    script: ModuleType, tmp_path: Path
) -> None:
    """`entry_points.txt` under `.dist-info` is not one of its files."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=(f"{_DIST_INFO}/entry_points.txt",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("entry_points.txt" in c for c in complaints)


def test_a_missing_dist_info_file_is_reported(
    script: ModuleType, tmp_path: Path
) -> None:
    """A wheel with no `RECORD` says so."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        omit=(f"{_DIST_INFO}/RECORD",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("RECORD" in c and "missing" in c for c in complaints)


def test_a_missing_package_file_is_reported(script: ModuleType, tmp_path: Path) -> None:
    """`py.typed` dropped from the wheel is caught against the checkout."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        omit=("btclib_secp256k1/py.typed",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("py.typed" in c and "missing" in c for c in complaints)


def test_an_untracked_package_file_is_reported(
    script: ModuleType, tmp_path: Path
) -> None:
    """A package member the checkout does not have is caught too."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=("btclib_secp256k1/stray.py",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("stray.py" in c and "not in the checkout" in c for c in complaints)


def test_a_second_static_extension_is_refused(
    script: ModuleType, tmp_path: Path
) -> None:
    """A second top-level compiled extension fails a static wheel."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        extra=("_btclib_secp256k1_second.so",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("exactly one" in c for c in complaints)


def test_a_missing_shared_library_fails_a_dynamic_wheel(
    script: ModuleType, tmp_path: Path
) -> None:
    """The dynamic wheel's shared library is required, not just allowed."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-py3-none-any.whl",
        kind="dynamic",
        omit=("libsecp256k1.dylib",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("dynamic wheel carries" in c for c in complaints)


def test_a_versioned_shared_library_name_is_not_the_expected_one(
    script: ModuleType, tmp_path: Path
) -> None:
    """`libsecp256k1.so.2`, alone, does not satisfy the shared-library rule.

    `scripts/cffi_build.py` itself skips a candidate with more than one
    suffix when it copies the artifact into the wheel -- this is the
    versioned name that skip exists to leave behind, and if one reached
    the wheel regardless it would not read as the shared library the
    dynamic wheel is required to carry.
    """
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-py3-none-any.whl",
        kind="dynamic",
        omit=("libsecp256k1.dylib",),
        extra=("libsecp256k1.so.2",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("dynamic wheel carries" in c for c in complaints)


def test_an_empty_toplevel_artifact_is_reported(
    script: ModuleType, tmp_path: Path
) -> None:
    """A zero-byte extension is a member, and a broken one."""
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl",
        empty=("_btclib_secp256k1.cpython-314-darwin.so",),
    )
    complaints = script.verify_wheel(wheel)
    assert any("empty" in c for c in complaints)


@pytest.mark.parametrize(
    "name,kind",
    [
        ("btclib_secp256k1-0.8.0.5-cp314-cp314-macosx_11_0_arm64.whl", "static"),
        ("btclib_secp256k1-0.8.0.5-py3-none-macosx_11_0_arm64.whl", "dynamic"),
    ],
)
def test_wheel_kind_reads_the_python_tag(
    script: ModuleType, name: str, kind: str
) -> None:
    """`py3` in the python-tag position means dynamic, anything else static."""
    assert script.wheel_kind(name) == kind


def test_main_reports_every_argument(script: ModuleType, tmp_path: Path) -> None:
    """`main` checks every wheel named on the line, not just the first."""
    clean = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl"
    )
    broken = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-py3-none-any.whl",
        kind="dynamic",
        omit=("btclib_secp256k1/py.typed",),
    )
    assert script.main(["prog", str(clean), str(broken)]) == 1


def test_main_needs_at_least_one_wheel(script: ModuleType) -> None:
    """No argument is a usage error, not a silent pass."""
    assert script.main(["prog"]) == 2


def test_the_main_guard_runs_the_script_as___main__(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover `if __name__ == "__main__":` without a subprocess.

    This project collects no coverage from a child interpreter, so a
    real subprocess would leave the guard as uncovered as it is
    elsewhere in `.github/scripts`. `runpy.run_path` executes the file
    fresh with `__name__` set to `"__main__"` in this one, against the
    real `btclib_secp256k1/` of this checkout, which the fixture above
    does not patch here since nothing constructs this module through it.
    """
    wheel = write_wheel(
        tmp_path / f"btclib_secp256k1-{_VERSION}-cp314-cp314-macosx_11_0_arm64.whl"
    )
    monkeypatch.setattr(sys, "argv", ["prog", str(wheel)])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    # the real package tree, not the fixture's empty one: __init__.py
    # alone is missing every other module this checkout's package has,
    # so this run is expected to complain and only its exit status --
    # nonzero rather than a crash -- is what this test is about
    assert excinfo.value.code == 1


# --- the page states the script's constants, and no more ------------------

_CONSTANT = re.compile(r"`([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)`")
_CODE_SPAN = re.compile(r"`([^`]+)`")
_REASON = " \N{EM DASH} "


def _rules(text: str) -> list[tuple[set[str], set[str]]]:
    """Pair every rule list of the page with the constants above it.

    A list introduced by a paragraph naming no constant is not a rule
    list and is skipped. Each item contributes the code spans before its
    dash.
    """
    rules: list[tuple[set[str], set[str]]] = []
    paragraph: list[str] = []
    lead: list[str] = []
    items: list[str] = []
    for line in (*text.splitlines(), ""):
        if line.startswith("- "):
            items.append(line[2:])
        elif items and line.startswith("  "):
            items[-1] += " " + line.strip()
        elif items:
            named = set(_CONSTANT.findall(" ".join(lead)))
            if named:
                rules.append((named, _stated(items)))
            items, lead = [], []
        elif line.strip():
            paragraph.append(line)
        elif paragraph:
            lead, paragraph = paragraph, []
    return rules


def _stated(items: list[str]) -> set[str]:
    """Every code span a rule list states, before each item's reason."""
    spans: set[str] = set()
    for item in items:
        rule, dash, _ = item.partition(_REASON)
        assert dash, f"a rule with no reason after it: {item}"
        spans.update(_CODE_SPAN.findall(rule))
    return spans


def test_rules_skips_a_list_whose_paragraph_names_no_constant() -> None:
    """A list is a rule list only once its lead paragraph names one.

    `_rules` is exercised directly, on synthetic text, because
    `docs/source/package-content-policy.md` -- the only text the other
    two tests parse -- never carries a stray list of this shape, and
    planting one there to cover a helper would leave the page
    misstating its own policy.
    """
    text = "Prose that names nothing in backticks.\n\n- one \N{EM DASH} reason\n"
    assert _rules(text) == []


def test_rules_treats_consecutive_blank_lines_as_one_gap() -> None:
    """A blank line with no paragraph pending starts nothing.

    Two blank lines ahead of the first paragraph -- the page's own
    opening never has the second -- are what the first exercises.
    """
    text = "\n\nParagraph naming `A_CONSTANT`.\n\n- `one` \N{EM DASH} reason\n"
    assert _rules(text) == [({"A_CONSTANT"}, {"one"})]


def _policy_constants(
    script: ModuleType,
) -> dict[str, tuple[str, ...] | frozenset[str]]:
    """Every constant of the script that is a list of members."""
    return {
        name: value
        for name, value in vars(script).items()
        if name.isupper() and isinstance(value, (tuple, frozenset))
    }


def test_the_page_states_what_the_script_enforces(script: ModuleType) -> None:
    """Every rule list on the page is its constants, exactly."""
    constants = _policy_constants(script)

    for named, stated in _rules(_PAGE.read_text(encoding="utf-8")):
        expected = {value for name in named for value in constants.get(name, ())}
        assert stated == expected, sorted(named)


def test_the_page_states_every_rule_the_script_has(script: ModuleType) -> None:
    """And no constant is left off the page, or stated twice."""
    named = [
        name for names, _ in _rules(_PAGE.read_text(encoding="utf-8")) for name in names
    ]

    assert sorted(named) == sorted(_policy_constants(script))

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the test-citation check of `.github/scripts`.

Unlike `tests/test_submodule_pin.py`'s check, this one reads only
`tests/*.py` off disk -- no git, no network -- so there is no state in
which asking it about the real suite has to be skipped. Keeping that
case here, rather than leaving it to the hook alone, is what proves the
attribution heuristic covers this suite's one citation of another
project's test, rust-secp256k1's `test_low_r`, without a hand-maintained
list carrying its name.

The script is loaded by path, `.github/scripts` being no package. Every
fixture below is a plain string handed to `dangling_citations`, not a
docstring or comment of this module, so none of it is itself prose this
check would read -- see `check_test_citations`'s own module docstring
for why that distinction is what keeps this file from becoming a case
for the thing it tests.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest


def _load() -> ModuleType:
    """Import the check by path.

    Returns:
        The module.
    """
    path = Path(__file__).parents[1] / ".github" / "scripts" / "check_test_citations.py"
    spec = importlib.util.spec_from_file_location("check_test_citations", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check = _load()


def _write(tmp_path: Path, name: str, source: str) -> None:
    """Write one test module into `tmp_path`, dedented.

    Args:
        tmp_path: the directory standing in for `tests/`.
        name: the file's name, `.py` included.
        source: its text.
    """
    (tmp_path / name).write_text(textwrap.dedent(source), encoding="utf-8")


def test_the_real_suite_has_no_dangling_citation() -> None:
    """What the hook itself answers on every commit, made visible here.

    `Path(__file__).parent` is `tests/` itself -- the tree the hook
    reads on the commit that adds this file, no monkeypatch required.
    """
    assert check.dangling_citations(Path(__file__).parent) == []


def test_a_citation_of_a_test_defined_in_another_module_resolves(
    tmp_path: Path,
) -> None:
    """A citation is to the suite, not to the file it appears in."""
    _write(tmp_path, "a.py", '"""See `test_elsewhere`."""')
    _write(tmp_path, "b.py", "def test_elsewhere() -> None:\n    pass\n")

    assert check.dangling_citations(tmp_path) == []


def test_a_citation_naming_no_test_anywhere_is_dangling(tmp_path: Path) -> None:
    """A rename or a typo leaves exactly the citation behind, unresolved."""
    _write(tmp_path, "a.py", '"""See `test_renamed_away`."""\n')

    dangling = check.dangling_citations(tmp_path)

    assert len(dangling) == 1
    path, line, name = dangling[0]
    assert path == tmp_path / "a.py"
    assert line == 1
    assert name == "test_renamed_away"


def test_a_possessive_citation_is_read_as_another_projects_test(tmp_path: Path) -> None:
    """Possessive prose is attribution, not a claim that a test is undefined."""
    _write(tmp_path, "a.py", '"""Reproduces rust-secp256k1\'s `test_low_r`."""\n')

    assert check.dangling_citations(tmp_path) == []


def test_a_citation_beside_a_foreign_source_path_is_skipped(tmp_path: Path) -> None:
    """A `.rs`/`.c`/`.cpp` path named just before a citation is attribution too.

    This is the module-docstring shape `tests/test_vectors.py` actually
    uses: the path and the citation on two wrapped lines of one bullet,
    with no possessive anywhere in it.
    """
    _write(
        tmp_path,
        "a.py",
        '"""rust-bitcoin/rust-secp256k1 src/lib.rs\n`test_low_r`, whose vector..."""\n',
    )

    assert check.dangling_citations(tmp_path) == []


def test_attribution_does_not_reach_across_a_paragraph(tmp_path: Path) -> None:
    """A foreign path several sentences back excuses no unrelated citation.

    Otherwise one upstream citation in a module's docstring would quietly
    exempt every dangling one after it -- the false negative the
    look-back window exists to bound.
    """
    far = "x" * (check._LOOKBACK + 1)
    _write(tmp_path, "a.py", f'"""src/lib.rs {far} `test_renamed_away`."""\n')

    dangling = check.dangling_citations(tmp_path)

    assert [name for _, _, name in dangling] == ["test_renamed_away"]


def test_main_fails_and_names_the_dangling_citation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`main` is `dangling_citations` against `_TESTS`, reported to stderr."""
    _write(tmp_path, "a.py", '"""See `test_renamed_away`."""\n')
    monkeypatch.setattr(check, "_TESTS", tmp_path)
    monkeypatch.setattr(check, "_ROOT", tmp_path)

    assert check.main() == 1
    error = capsys.readouterr().err
    assert "a.py:1" in error
    assert "test_renamed_away" in error


def test_main_passes_when_every_citation_resolves(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The passing case, printed rather than only silent."""
    _write(
        tmp_path, "a.py", '"""See `test_here`."""\ndef test_here() -> None:\n    pass\n'
    )
    monkeypatch.setattr(check, "_TESTS", tmp_path)

    assert check.main() == 0
    assert "names a test that exists" in capsys.readouterr().out

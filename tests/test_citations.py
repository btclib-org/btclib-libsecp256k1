# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A test this package names in its prose is a test that exists.

The prose here points at tests by name -- the module docstring of
`tests/test_verified_signing.py` names four, and `btclib_secp256k1/dsa.py`
names two of the cases behind a claim it makes about itself -- and nothing
said whether the name still belonged to anything. #256 was two landmarks
that had come to point at the wrong test, and naming the test instead of
its position is better only until a rename: an append falsifies a
position, a rename falsifies a name, and neither turns anything red.

What is read is every backticked span in the sources, whitespace collapsed
out of it, that then spells a test name. Text rather than the syntax tree,
which inverts `tests/test_secret.py`'s reasoning for the opposite
population: there a mention had to be told from a call, so the names come
off the AST; here the mention *is* the subject, and half of them are in
comments the AST does not carry.

Two shapes make the reader what it is rather than a one-line pattern:

- **a citation wrapped by the reflow.** `tests/test_docs.py` cites
  `test_no_documented_module_has_gone_away` broken at an underscore across
  two lines. A pattern anchored to one line does not report it as dangling
  -- it never sees it, which is the failure a guard must not have -- so the
  span is collapsed before it is compared, of whitespace and of the `#` a
  wrap inside a comment block adds. What collapsing costs is stated in
  `_cited`.
- **a name that is not ours.** `tests/test_vectors.py` cites
  rust-secp256k1's own `test_low_r` to say which upstream vector it
  reproduces: correct prose that resolves to nothing here. Those are named
  in `_FOREIGN`, with where each comes from, and each is asserted to still
  be cited by something other than this file -- an exemption that stops
  applying fails rather than sitting there, which it could not do if the
  prose explaining it counted as a use.

`CHANGELOG.md` and `HISTORY.md` are out of scope, and not for the twenty
or so citations they would add. A released section is that release's
account of itself, so a test renamed afterwards does not make it wrong,
and a check over it would ask for the record to be edited whenever the
tree moves -- rewriting history rather than fixing a reference.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]

# the sources whose prose a reader navigates the code by: this suite, and
# the package's own docstrings, which cite the tests behind their claims.
# This file is not among them, and that is what makes the staleness check
# below mean anything: it names `test_low_r` in order to explain the
# exemption, so reading itself would let the guard keep its own exemptions
# alive. It also holds citations as data -- `_cited`'s own cases -- which
# are fixtures rather than prose, and one of them names a test that
# deliberately does not exist
_SOURCES = [
    path
    for path in sorted((_ROOT / "tests").glob("*.py"))
    + sorted((_ROOT / "btclib_secp256k1").glob("*.py"))
    if path.name != Path(__file__).name
]

# any backticked span, across lines: what is inside is decided after the
# whitespace comes out, a citation being wrappable at an underscore
_SPAN = re.compile(r"`([^`]+)`", re.DOTALL)

# what a test is called here, which the naming hook already enforces of
# every definition
_NAME = re.compile(r"test_[a-z0-9_]+")

_DEFINITION = re.compile(r"^def (test_[a-z0-9_]+)\(", re.MULTILINE)

# cited names that belong to somebody else's suite, and where each is
# from. `test_no_foreign_citation_has_gone_stale` holds every entry to
# still being cited, so this cannot become a list of names nobody removed
_FOREIGN = {
    "test_low_r": "rust-bitcoin/rust-secp256k1, src/lib.rs",
}


def _cited(text: str) -> set[str]:
    """Every test name a text cites, wrapped citations included.

    The span is collapsed rather than matched in place: `#` goes with the
    whitespace because a citation wrapped inside a comment block carries
    the next line's marker into the middle of the name.

    What that cannot tell apart is a span of several words that happens to
    begin with `test_`: `` `test_a and test_b` `` would collapse into one
    name that was never cited, and be reported as missing. Nothing here
    is written that way, and the direction of the error is the safe one --
    it fails, and the prose is what gets fixed.

    Args:
        text: the source of one file.

    Returns:
        The test names cited in it.
    """
    collapsed = (re.sub(r"[\s#]+", "", span) for span in _SPAN.findall(text))
    return {name for name in collapsed if _NAME.fullmatch(name)}


def _defined() -> set[str]:
    """Every test this suite defines.

    Returns:
        The names of every test function under `tests/`.
    """
    names: set[str] = set()
    for path in sorted((_ROOT / "tests").glob("*.py")):
        names.update(_DEFINITION.findall(path.read_text(encoding="utf-8")))
    return names


def _citations() -> dict[str, list[str]]:
    """Every cited name, and which files cite it.

    Returns:
        A mapping of test name to the file names citing it.
    """
    where: dict[str, list[str]] = {}
    for path in _SOURCES:
        for name in sorted(_cited(path.read_text(encoding="utf-8"))):
            where.setdefault(name, []).append(path.name)
    return where


def test_every_cited_test_exists() -> None:
    """A name in the prose resolves, or it is somebody else's test.

    The independent side is the file itself: the names come out of the
    prose and the definitions out of `def` lines, so a rename that misses
    a docstring leaves the two disagreeing.
    """
    defined = _defined()
    dangling = {
        name: files
        for name, files in _citations().items()
        if name not in defined and name not in _FOREIGN
    }
    assert not dangling, (
        f"prose names a test that does not exist: {dangling}."
        " Rename it in the prose too, or -- if it is another project's"
        " test, cited to say what is reproduced -- add it to _FOREIGN with"
        " where it comes from."
    )


def test_no_foreign_citation_has_gone_stale() -> None:
    """An exemption that stopped applying is a line nobody removed."""
    cited = set(_citations())
    unused = sorted(name for name in _FOREIGN if name not in cited)
    assert not unused, (
        f"_FOREIGN names what nothing cites any more: {unused}."
        " Remove the entry: it exempts a citation that is gone."
    )


def test_the_prose_was_read_at_all() -> None:
    """The two guards above pass for free over an empty population.

    Neither says anything if the reader finds no citation, which is what a
    pattern broken by a refactor would look like -- and the sources are
    globbed, so a wrong path is silent in the same way.
    """
    assert len(_SOURCES) > 1
    citations = _citations()
    assert citations
    assert set(citations) & _defined()


@pytest.mark.parametrize(
    "span, expected",
    [
        ("`test_the_sweep_is_whole`", {"test_the_sweep_is_whole"}),
        # the wrap in tests/test_docs.py, at an underscore in a docstring
        (
            "`test_no_documented_module\n    _has_gone_away`",
            {"test_no_documented_module_has_gone_away"},
        ),
        # the same wrap inside a comment block, which adds the marker
        ("# `test_a_long_name\n# _across_lines`", {"test_a_long_name_across_lines"}),
        # a backticked span that is code rather than a citation
        ("`dsa.sign(msg, key)`", set()),
        ("`_pubkey_from_prvkey_`", set()),
        # not backticked at all: trezor's names in tests/test_vectors.py
        ("test_ecdsa_sign_digest_deterministic and test_ecdsa_der", set()),
    ],
)
def test_the_reader_reads_a_citation(span: str, expected: set[str]) -> None:
    """`_cited` on the shapes this tree actually holds.

    A guard whose pattern matches nothing passes, so the reader is held to
    the wrapped citation it exists for -- and to leaving alone the
    backticked code and the unbackticked upstream names beside it.

    Args:
        span: prose to read.
        expected: the names it cites.
    """
    assert _cited(span) == expected

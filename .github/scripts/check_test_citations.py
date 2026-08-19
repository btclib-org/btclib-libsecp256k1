# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A test named in the suite's own prose is still a test.

Test names in `tests/*.py` are prose that other prose refers to --
`tests/test_verified_signing.py`'s own module docstring names four of
its file's tests, `tests/test_vectors.py` names two more elsewhere in the
package, and so on. An append cannot falsify such a citation, but a
rename does, silently: nothing before this went red for one, and #255's
rename of two test names is the reason that is not hypothetical -- only
a human grepping for citations kept the prose in step with it.

What this asks of every citation of the form `` `test_...` `` in a
docstring or comment of `tests/*.py` is that it still names a test that
exists. Not every such citation is of *this* suite, though:
`tests/test_vectors.py` names, in the same breath as its own
`src/lib.rs`, rust-secp256k1's `test_low_r` -- correct prose about a
test this suite does not define and never will. Telling that citation
from a stale one is the reason this does not simply flag every name
with no matching `def`: a citation is read as another project's, and
skipped, where the text just before it names whose test it is -- a
possessive ("rust-secp256k1's `test_low_r`") or a foreign source file
in the same breath (a `.c`, `.cpp` or `.rs` path, this package's own
tests being Python). Excluding a list of upstream test names by hand
was the alternative, and is a list nothing forces anyone to update when
a citation of a third project arrives; the attribution a human reader
already needs to make sense of the citation is not.

Only a docstring or a `#` comment is asked, and not every string literal
a module happens to contain: a test module's own fixtures are free to
build a string that looks like a citation without being read as one --
`tests/test_test_citations.py` does exactly that, to exercise this
check without becoming a case for it.

Run by the `test-citations` hook of .pre-commit-config.yaml, and so by
the lint workflow, on every commit: nothing else walks `tests/*.py` for
citations rather than for what they describe, `tests/test_secret.py`'s
own walk of the package being over a different population -- callers of
`_secret.take`, not the test suite's prose about itself.
"""

from __future__ import annotations

import ast
import io
import sys
import tokenize
from pathlib import Path
from re import compile as re_compile

_ROOT = Path(__file__).resolve().parents[2]
_TESTS = _ROOT / "tests"

_CITATION = re_compile(r"`(test_[A-Za-z0-9_]+)`")

# a citation attributed to a name other than this suite's own: a
# possessive naming whose test it is ("rust-secp256k1's `test_low_r`"),
# or a source file foreign to this package's own tests -- which are
# Python -- named in the same breath ("src/lib.rs\n`test_low_r`"). Both
# are anchored to sit right before the citation, with only whitespace
# between: unanchored, "the parser's `test_renamed_away`" would read an
# ordinary English possessive as attribution, and a `.c`/`.cpp`/`.rs`
# mention anywhere in the look-back window would excuse a citation a
# whole unrelated sentence later. The possessive's own noun is also
# required to look like a project slug -- a hyphen or a digit in it,
# "rust-secp256k1" having both -- which is what tells that from "the
# parser's" or "this suite's" without a hand-maintained list of names
_POSSESSIVE = re_compile(r"[\w][\w.-]*[-0-9][\w.-]*'s\s*$")
_FOREIGN_SOURCE = re_compile(r"\.(?:c|cc|cpp|h|hpp|rs)\b\s*$")

# far enough back to reach across one wrapped line -- a path ending one
# line and the citation opening the next -- and no further: a citation
# earns its own attribution, not one borrowed from a paragraph away.
# Both patterns above are anchored to the end of the window regardless,
# so this bounds how far a *wrapped* attribution can reach rather than
# doing the anchoring itself
_LOOKBACK = 200


def defined_tests(tests_dir: Path) -> set[str]:
    """Return the name of every test any module in `tests_dir` defines.

    Args:
        tests_dir: the directory to walk, non-recursively -- `tests/`
            has no test package below it.

    Returns:
        Every `def test_...` name, pooled across every module: a
        citation is to the suite, not to one file of it, so a test named
        in one module and cited from another still resolves.
    """
    names: set[str] = set()
    for path in sorted(tests_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                names.add(node.name)
    return names


def _prose_spans(text: str) -> list[tuple[int, int]]:
    """Return the character span of every docstring and comment in `text`.

    A citation is prose, documentation of the suite referring to itself,
    and confining the search to docstrings and comments is what keeps an
    ordinary string literal -- a test module's own fixture, built to
    look like a citation without being one -- from being read as one.

    Args:
        text: one module's source.

    Returns:
        A `(start, end)` character offset per module, class and function
        docstring, and per `#` comment -- in the same offsets
        `_CITATION.finditer(text)` reports its matches in.
    """
    line_starts = [0]
    for line in text.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))

    def offset(line: int, col: int) -> int:
        return line_starts[line - 1] + col

    spans: list[tuple[int, int]] = []

    tree = ast.parse(text)
    scopes: list[ast.Module | ast.FunctionDef | ast.ClassDef] = [tree]
    scopes.extend(
        n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.ClassDef)
    )
    for scope in scopes:
        first = scope.body[0] if scope.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
            and first.value.end_lineno is not None
            and first.value.end_col_offset is not None
        ):
            spans.append((
                offset(first.value.lineno, first.value.col_offset),
                offset(first.value.end_lineno, first.value.end_col_offset),
            ))

    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            spans.append((offset(*tok.start), offset(*tok.end)))

    return spans


def _attributed_elsewhere(text: str, start: int) -> bool:
    """Whether the citation at `start` in `text` is prose about another suite.

    Args:
        text: the whole file's source.
        start: the index of the citation's opening backtick.

    Returns:
        True where the text just before the citation names whose test it
        is, rather than only naming the test.
    """
    before = text[max(0, start - _LOOKBACK) : start]
    return bool(_POSSESSIVE.search(before)) or bool(_FOREIGN_SOURCE.search(before))


def dangling_citations(tests_dir: Path) -> list[tuple[Path, int, str]]:
    """Return every citation that names no test this suite defines.

    Args:
        tests_dir: the directory to walk; see `defined_tests`.

    Returns:
        A `(path, line, name)` triple per dangling citation, in the
        order `tests_dir.glob` and `re.finditer` produce them; empty
        where every citation resolves or is attributed elsewhere.
    """
    defined = defined_tests(tests_dir)
    dangling: list[tuple[Path, int, str]] = []
    for path in sorted(tests_dir.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        spans = _prose_spans(text)
        for match in _CITATION.finditer(text):
            if not any(start <= match.start() < end for start, end in spans):
                continue
            name = match[1]
            if name in defined or _attributed_elsewhere(text, match.start()):
                continue
            line = text.count("\n", 0, match.start()) + 1
            dangling.append((path, line, name))
    return dangling


def main() -> int:
    """Fail where a citation names no test that exists.

    Returns:
        0 where every `` `test_...` `` citation in `tests/*.py` resolves
        or is attributed to another project's test; 1 otherwise.
    """
    dangling = dangling_citations(_TESTS)
    for path, line, name in dangling:
        rel = path.relative_to(_ROOT)
        print(
            f"{rel}:{line}: `{name}` is cited but no test in tests/*.py is"
            " named that -- a rename or removal left the citation behind;"
            " a citation of another project's test needs an attribution"
            " next to it (a possessive, or the foreign source file) for"
            " this check to tell the two apart",
            file=sys.stderr,
        )
    if dangling:
        return 1
    print("every `test_...` citation in tests/*.py names a test that exists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

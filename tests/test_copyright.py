# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""LICENSE and pyproject.toml's author, checked together.

btclib's own LICENSE named "Ferdinando M. Ametrano and btclib
contributors" for years after the rest of that project had moved to "The
btclib developers", with nothing comparing the two (btclib#389). LICENSE
here named "Giacomo Caironi" the same way, against this project's own
COPYRIGHT and `authors` already saying "The btclib developers" -- caught
by hand, not by a check, which is what this one is.

Regex rather than `tomllib` for the one line wanted out of
pyproject.toml: the floor here is 3.10, and `tomllib` is 3.11. Once that
floor moves, this can read the file directly instead.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_HOLDER_RE = r"Copyright \([Cc]\) (\d{4})(?:-(\d{4}))? (.+)"
_AUTHOR_RE = r'authors\s*=\s*\[\{\s*name\s*=\s*"([^"]+)"'


def _license_holder() -> tuple[str, str, str]:
    text = (_ROOT / "LICENSE").read_text(encoding="utf-8")
    match = re.search(_HOLDER_RE, text)
    assert match, (
        f"LICENSE has no 'Copyright (c) YYYY[-YYYY] holder' line: {text[:80]!r}"
    )
    start, end, holder = match.group(1), match.group(2), match.group(3)
    return start, end or start, holder


def _pyproject_author() -> str:
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(_AUTHOR_RE, text)
    assert match, "pyproject.toml has no 'authors = [{ name = ... }]' line"
    return match.group(1)


def test_license_holder_matches_the_declared_author() -> None:
    """The wheel's `Author` metadata is the same holder LICENSE names."""
    _, _, license_holder = _license_holder()
    author = _pyproject_author()
    assert license_holder == author, (
        f"LICENSE names {license_holder!r}, pyproject.toml's author "
        f"{author!r}. A wheel built from one and read from the other "
        "would disagree about who holds the copyright"
    )

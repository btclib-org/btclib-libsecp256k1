# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `tests/README.md` must not say about itself.

The same claim btclib's own `vendored_data_test.py` forbids, for the
same reason: a stated count is a line every open branch has to edit, so
a pull request vendoring a fourth file is guaranteed to conflict on it,
and the Summary's own `git ls-files` command already answers the
question on demand. The lists stay; the number in front of them goes.
"""

import re
from pathlib import Path

_README = Path(__file__).parent / "README.md"

# "N files." as the Summary might open, in digits or spelled out; against
# the whole file, the shape being specific enough to occur nowhere else
_FORBIDDEN_ANYWHERE = r"(?im)^(?:\d+|[a-z-]+) files\."

# a Summary bullet that opens with a count of what it lists; against the
# Summary alone
_FORBIDDEN_IN_SUMMARY = r"(?m)^- \d+ [a-z]"


def _summary() -> str:
    """Return the Summary section, which ends at the end of the file."""
    text = _README.read_text(encoding="utf-8")
    return text[text.index("\n## Summary\n") :]


def test_the_readme_states_no_total() -> None:
    """No "N files.", written by hand or restored by a rebase."""
    match = re.search(_FORBIDDEN_ANYWHERE, _README.read_text(encoding="utf-8"))
    assert match is None, (
        f"tests/README.md states a total again: {match[0]!r}."
        " Remove it -- the git ls-files command in its Summary answers on"
        " demand, and every open branch would have to edit the number."
    )


def test_no_summary_bullet_counts_what_it_lists() -> None:
    """The names are the fact; a number in front of them is a second one."""
    match = re.search(_FORBIDDEN_IN_SUMMARY, _summary())
    assert match is None, (
        f"a Summary bullet states a count again: {match[0]!r}."
        " The list that follows it is the count, and the two drift apart."
    )


def test_the_patterns_still_match() -> None:
    """The guards above pass for free if their patterns match nothing."""
    assert re.search(_FORBIDDEN_ANYWHERE, "3 files. Against a pinned blob:")
    assert re.search(_FORBIDDEN_ANYWHERE, "Three files. Against a pinned blob:")
    assert re.search(_FORBIDDEN_IN_SUMMARY, "- 1 identical byte for byte: `en`")
    assert re.search(_FORBIDDEN_IN_SUMMARY, "- 2 reformatted: `ecdsa_sig.json`")


def test_the_patterns_spare_the_numbers_that_are_facts() -> None:
    """A number in an entry is upstream's, not a claim about this file."""
    spared = (
        "Verdict: **identical**, CRLF included. All 19 vectors, all eight",
        "199 vectors, JSON-equal to the upstream blob;",
        "Four of the 19 are messages of 0, 1, 17 and 100 bytes",
    )
    for text in spared:
        assert not re.search(_FORBIDDEN_ANYWHERE, text), text
        assert not re.search(_FORBIDDEN_IN_SUMMARY, text), text

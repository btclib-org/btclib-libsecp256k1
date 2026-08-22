# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The mypy hook's pins are the versions `uv.lock` resolves.

The type gate runs in an environment of its own: `.pre-commit-config.yaml`
gives the mirror a `rev` and a list of `additional_dependencies`, and
pre-commit builds that environment once and keeps it. The editor cannot
use it -- this package is a compiled extension and the import does not
resolve where nothing built one -- so what the editor reads is the
project environment instead, and the two are the same mypy only while the
two declarations say the same thing.

Nothing made them say it. `.pre-commit-config.yaml` records that they are
"moved by hand, with the lint and test groups of uv.lock", which is a
procedure rather than a check, and section 4 of the organization standard
names that second declaration as the price of this branch. This module is
what turns the procedure into a red test: a `uv lock` that moves one of
these and a hand that does not follow is the whole of what it catches,
and it is silent -- both environments still build, and mypy still passes
in each, against different versions.

Parsed rather than loaded. `uv.lock` is toml and the floor here is 3.10,
where `tomllib` is not yet in the standard library, which is the reason
`test_copyright.py` beside this one reads pyproject.toml the same way;
`.pre-commit-config.yaml` is yaml and no group here carries a parser for
it. Both shapes are narrow enough to match: a `[[package]]` table with a
name and a version, and a two-space-indented `- name==version` under the
key that lists them.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_CONFIG = _ROOT / ".pre-commit-config.yaml"
_LOCK = _ROOT / "uv.lock"

# the mypy hook's block, from its repo line to the next hook's: the pins
# read below are that hook's and not another's, `shellcheck-py` being
# pinned the same way one hook over and deliberately absent from the lock
_MYPY_BLOCK = re.compile(
    r"^  - repo: https://github\.com/pre-commit/mirrors-mypy\n(.*?)(?=^  - repo: )",
    re.MULTILINE | re.DOTALL,
)
_REV = re.compile(r"^    rev: v?(?P<version>[0-9][0-9a-z.]*)\s*$", re.MULTILINE)
_PIN = re.compile(
    r"^          - (?P<name>[a-z0-9_.-]+)==(?P<version>\S+)\s*$", re.MULTILINE
)


def _block() -> str:
    """Return the mypy hook's block of `.pre-commit-config.yaml`."""
    match = _MYPY_BLOCK.search(_CONFIG.read_text(encoding="utf-8"))
    assert match, "no mirrors-mypy hook in .pre-commit-config.yaml"
    return match[1]


def _locked(name: str) -> str | None:
    """Return the version `uv.lock` resolves for `name`, or None."""
    pattern = re.compile(
        rf'^name = "{re.escape(name)}"\nversion = "(?P<version>[^"]+)"$',
        re.MULTILINE,
    )
    match = pattern.search(_LOCK.read_text(encoding="utf-8"))
    return match["version"] if match else None


_BLOCK = _block()
_PINS = tuple((m["name"], m["version"]) for m in _PIN.finditer(_BLOCK))


def test_the_hook_block_was_read() -> None:
    """A block that parsed to nothing satisfies every check below.

    The two patterns are anchored on an indentation `.pre-commit-config
    .yaml` happens to use, so a reformat that changed it would leave the
    pins unread and the assertions quantifying over nothing.
    """
    assert _PINS, "the mirrors-mypy hook lists no pinned additional_dependencies"


def test_the_rev_is_the_locked_mypy() -> None:
    """The isolated environment's mypy and the project's are one version.

    They have to be: the editor reads the project's, the gate reads the
    hook's, and a developer told the two disagree learns it from a
    finding one reports and the other does not.
    """
    rev = _REV.search(_BLOCK)
    assert rev, "the mirrors-mypy hook declares no rev"
    assert rev["version"] == _locked("mypy"), (
        f"the hook pins mypy {rev['version']} where uv.lock resolves {_locked('mypy')}"
    )


@pytest.mark.parametrize("name, version", _PINS, ids=lambda v: v)
def test_every_pin_is_the_locked_version(name: str, version: str) -> None:
    """Each package the hook installs is the one the project installs."""
    locked = _locked(name)
    assert locked is not None, (
        f"the mypy hook pins {name}=={version} and uv.lock resolves no"
        f" {name}: it is not one of the packages the lock keeps level"
    )
    assert version == locked, (
        f"the mypy hook pins {name}=={version} where uv.lock resolves {locked}"
    )

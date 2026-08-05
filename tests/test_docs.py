# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every module this package ships is documented.

Matching btclib's own tests/docs_test.py: the page under `docs/source/`
is hand written, which invites drift, and telling contributors to re-run
`sphinx-apidoc -f` is no answer -- `-f` regenerates it from the template,
discarding the myst links to the markdown files. What drift costs is a
module absent from the automodule directives, and therefore from the
published documentation, with nothing anywhere to say so; this test is
the thing that says so.

Simpler than btclib's version in one way: this package has no
subpackages, so a single page holds every stanza and there is no
toctree-entry pattern to also check.
"""

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_PACKAGE_DIR = _ROOT / "btclib_libsecp256k1"
_DOCS_DIR = _ROOT / "docs" / "source"

# what a documented module looks like to sphinx: ".. automodule:: name",
# whatever indentation and options follow it
_AUTOMODULE = re.compile(r"^\s*\.\.\s+automodule::\s+(\S+)\s*$", re.MULTILINE)


def _documented() -> set[str]:
    """Every dotted name the documentation sources mention."""
    names: set[str] = set()
    for page in _DOCS_DIR.glob("*.rst"):
        text = page.read_text(encoding="utf-8")
        names.update(_AUTOMODULE.findall(text))
    return names


def _is_public(parts: tuple[str, ...]) -> bool:
    """Whether a module path names something a user is meant to import.

    `__init__` is the package itself and not a private name, which is
    the only reason this is not a one-line `startswith("_")`. One module
    under `btclib_libsecp256k1/` is private, `_scalar`: the shared
    private-key normalization every signing module calls, not API of its
    own, and the underscore is what says so.
    """
    return not any(part.startswith("_") for part in parts if part != "__init__")


def _shipped() -> set[str]:
    """Every dotted name a user can import from an installed package.

    Read off the source tree rather than by walking the imported package
    with pkgutil: a module missing from the documentation is usually a
    module just added, and this way noticing it does not depend on it
    being importable -- which, for a cffi extension, means built.
    """
    names = {"btclib_libsecp256k1"}
    for path in sorted(_PACKAGE_DIR.rglob("*.py")):
        parts = path.relative_to(_PACKAGE_DIR).with_suffix("").parts
        if not _is_public(parts):
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            continue
        names.add(".".join(("btclib_libsecp256k1", *parts)))
    return names


# the two directions are separate tests because they fail for opposite
# reasons and are fixed in opposite files: something undocumented is a
# missing stanza in docs/source, something documented that no longer
# exists is a stanza left behind by a rename
def test_every_module_is_documented() -> None:
    """Verify every shipped module has a stanza in docs/source."""
    undocumented = _shipped() - _documented()
    assert not undocumented, (
        "not documented in docs/source: "
        + ", ".join(sorted(undocumented))
        + " -- add an automodule stanza (do not run sphinx-apidoc -f,"
        " which discards the hand-tuned pages)"
    )


def test_no_documented_module_has_gone_away() -> None:
    """Verify no automodule stanza names a module the tree lost."""
    stale = _documented() - _shipped()
    assert not stale, "documented in docs/source but not shipped: " + ", ".join(
        sorted(stale)
    )


def test_the_docs_sources_were_found_at_all() -> None:
    """Guard the two tests above against passing vacuously.

    Both compare against a set built by globbing, and a wrong `_DOCS_DIR`
    would make `_documented()` empty, which `test_no_documented_module
    _has_gone_away` reports as success.
    """
    assert _DOCS_DIR.is_dir()
    assert (_DOCS_DIR / "btclib_libsecp256k1.rst").is_file()
    assert len(_documented()) > 5


@pytest.mark.parametrize("name", sorted(_shipped()))
def test_shipped_module_is_a_dotted_package_name(name: str) -> None:
    """The set the assertions above are built on holds what it claims."""
    assert name == "btclib_libsecp256k1" or name.startswith("btclib_libsecp256k1.")
    assert not any(part.startswith("_") for part in name.split("."))


@pytest.mark.parametrize(
    "parts, public",
    [
        (("dsa",), True),
        (("__init__",), True),
        (("_scalar",), False),
    ],
)
def test_is_public(parts: tuple[str, ...], public: bool) -> None:
    """Both answers, on the two shapes this tree actually has."""
    assert _is_public(parts) is public

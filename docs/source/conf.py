# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the
documentation: https://www.sphinx-
doc.org/en/master/usage/configuration.html
"""

import posixpath
import re
from pathlib import Path
from typing import Any

import tomllib
from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.transforms.post_transforms import SphinxPostTransform

# the repository root, two levels up from this file, and the one place
# below that is allowed to name it
ROOT = Path(__file__).parents[2].resolve()
# read once and read twice from: the version below and the github url the
# transform at the bottom builds its links on
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "btclib_libsecp256k1"
# no __copyright__ in this package to read back, unlike btclib's own
# conf.py: LICENSE is the only place the holder and years are declared,
# so this reads that file instead, minus the "Copyright (c) " sphinx
# prepends itself
project_copyright = re.search(
    r"^Copyright \(c\) (.+)$",
    (ROOT / "LICENSE").read_text(encoding="utf-8"),
    re.MULTILINE,
).group(1)
author = "The btclib developers"
# read from pyproject.toml, the one place the version is declared, and not
# from importlib.metadata: that would need this package installed in the
# environment building the documentation, which read the docs does not do
release = PYPROJECT["project"]["version"]

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.coverage",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
]

# no sphinx.ext.todo, for the reason btclib's own conf.py gives: a
# ``.. todo::`` left at the default renders as nothing at all, and without
# the extension it is an unknown directive that -W turns into a failed
# build instead

source_suffix = [".rst", ".md"]

# unlike btclib's own conf.py, which needs none of this: CONTRIBUTING.md
# links to "README.md#build", an anchor into a markdown heading rather
# than a whole file, and myst generates no heading ids at all unless
# told to. 2 is the depth of "## Build", the one heading a root file
# links to by anchor today
myst_heading_anchors = 2

# no suppress_warnings, matching btclib: the transform at the bottom
# resolves every link the included root files carry, so a myst target
# still missing is a link with nowhere to go and -W is what says so

templates_path = ["_templates"]

exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"

# no html_static_path, matching btclib's own conf.py and for the same
# reason: neither an overridden stylesheet nor a shipped image exists
# here, and sphinx warns about a declared "_static" directory that has
# never existed

# -- Links out of the included root markdown files ----------------------------

# Four pages of the toctree are this repository's README, CONTRIBUTING,
# SECURITY and HISTORY, each pulled into a *_link.md shim by a myst
# {include} -- three fewer than btclib, which also has CODE_OF_CONDUCT,
# REPOSITORY and RELEASING among its root files but not among its shims,
# and no CHANGELOG at all, HISTORY being the only release notes file here.
# Those root files are written for the three places that read them
# unrendered -- the GitHub file view, the PyPI long description, and (for
# this repository) nothing else, there being no website served from it --
# so a bare "SECURITY.md" is the correct spelling there, and myst resolves
# not one of those links once the file is lifted into this tree.
#
# What it emits instead is the reason this needs code rather than a
# warning filter, exactly as btclib's own conf.py explains: a target myst
# cannot resolve becomes an anchor on the page it is already on,
# href="#SECURITY.md", an id nothing has. The transform below answers
# each link from the repository rather than from a table that would have
# to be kept in step with this directory: a path a *_link.md shim
# includes becomes a reference to that page, any other path that exists
# in the tree becomes a link to the file on GitHub, and a path that
# exists nowhere is left to myst -- which reports it, and -W then fails.

INCLUDE = re.compile(r"^```\{include\}\s+(.+?)\s*$", re.MULTILINE)


def included(shim: Path) -> tuple[str, str]:
    """Map the file a *_link.md shim renders to the shim's own docname."""
    paths = INCLUDE.findall(shim.read_text(encoding="utf-8"))
    if len(paths) != 1:
        err_msg = f"{shim.name}: {len(paths)} include fences, expected one"
        raise ValueError(err_msg)
    return str((shim.parent / paths[0]).resolve().relative_to(ROOT)), shim.stem


# repository-relative path -> the docname whose page renders it
INCLUDED = dict(map(included, sorted(Path(__file__).parent.glob("*_link.md"))))
# the branch, not a permalink pinned to a commit: these are navigation
# links to files that keep changing, and a reader following one wants the
# file as it stands
BLOB = f"{PYPROJECT['project']['urls']['repository']}/blob/main/"


class RootFileLinks(SphinxPostTransform):
    """Resolve the repository-relative links of the included root files."""

    default_priority = 5

    def run(self, **kwargs: Any) -> None:
        """Rewrite every myst xref naming a file of this repository."""
        for node in list(self.document.findall(pending_xref)):
            if node.get("reftype") != "myst" or node.get("refdomain") is not None:
                continue
            if node.get("refdoc", self.env.docname) not in INCLUDED.values():
                continue
            target, _, anchor = node["reftarget"].partition("#")
            target = posixpath.normpath(target)
            if target.startswith(".."):
                continue
            if target in INCLUDED:
                node["refdomain"] = "doc"
                node["reftarget"] = INCLUDED[target]
                node["reftargetid"] = anchor or None
            elif (ROOT / target).is_file():
                fragment = f"#{anchor}" if anchor else ""
                reference = nodes.reference(
                    "", "", refuri=f"{BLOB}{target}{fragment}", internal=False
                )
                reference.extend(node.children)
                node.replace_self(reference)


def setup(app: Sphinx) -> None:
    """Register the transform above; sphinx calls this."""
    app.add_post_transform(RootFileLinks)

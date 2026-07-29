# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests of what installing the package provides, rather than its source.

That is the extension module and the distribution metadata.

One package works with both extensions: the static one, which has
libsecp256k1 linked in, and the dynamic one (cffi ABI mode), which has
to find at run time the shared library shipped beside it. Whichever
build these tests run on, the branch of _load_lib taken by the import
itself is the only one that exists, so the search is driven here with a
stand-in module: what is checked is not that a library can be loaded,
but that a directory not holding one is reported instead of being
mistaken for one.
"""

import pathlib
import re
import types

import pytest

from btclib_libsecp256k1 import __version__, _load_lib


def test_version() -> None:
    # that the distribution is installed under the name __init__.py asks
    # for is not what this checks: were it not, importlib.metadata would
    # raise at import time and every test would fail. What is checked is
    # that the package keeps exposing the attribute, and with a value
    assert isinstance(__version__, str)
    assert __version__


def test_load_lib_no_candidate(tmp_path: pathlib.Path) -> None:
    module = types.SimpleNamespace(__file__=str(tmp_path / "_extension.py"))
    with pytest.raises(ImportError, match=re.escape(str(tmp_path))):
        _load_lib(module)


def test_load_lib_unloadable_candidate(tmp_path: pathlib.Path) -> None:
    # a file matching the glob that the loader rejects is skipped, and
    # the directory as a whole is reported as holding no library
    (tmp_path / "libsecp256k1.so").write_bytes(b"not a shared object")
    module = types.SimpleNamespace(__file__=str(tmp_path / "_extension.py"))
    with pytest.raises(ImportError, match="no loadable shared libsecp256k1"):
        _load_lib(module)

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Pure python cffi bindings to libsecp256k1: https://github.com/bitcoin-core/secp256k1."""

import pathlib
from importlib.metadata import version
from typing import Any

import _btclib_libsecp256k1

# read from the installed distribution metadata, so that the version in
# pyproject.toml stays the only place to bump at release time
__version__ = version("btclib_libsecp256k1")

# an opaque handle to a libsecp256k1 object, as returned by ffi.new: the
# cffi cdata type is not expressible in the type system, but a named
# alias still says what the value is
CData = Any

ffi = _btclib_libsecp256k1.ffi


def _load_lib(module: Any) -> Any:
    """Return the libsecp256k1 handle of the extension module.

    The extension is taken as an argument, rather than read from the
    enclosing scope, because only one of the two branches below exists
    in any given build: the other one is only reachable, and therefore
    only testable, with a stand-in.
    """
    # a static extension has the library linked in
    if hasattr(module, "lib"):
        return module.lib

    # a dynamic one (cffi ABI mode) has to find, at run time, the shared
    # object shipped beside it
    path = pathlib.Path(module.__file__).parent
    for suffix in (".dll", ".so", ".dylib"):
        for file in path.glob(f"libsecp256k1*{suffix}*"):
            try:
                return ffi.dlopen(str(file))
            except OSError:
                # a file the loader rejects does not end the search: a
                # wheel repaired by auditwheel or delocate can ship more
                # than one match, only one of which is the library
                pass
    msg = f"no loadable shared libsecp256k1 found in {path}"
    raise ImportError(msg)


lib = _load_lib(_btclib_libsecp256k1)

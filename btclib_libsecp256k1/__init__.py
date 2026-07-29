# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Pure python cffi bindings to libsecp256k1: https://github.com/bitcoin-core/secp256k1."""

import pathlib
from typing import Any

import _btclib_libsecp256k1

# an opaque handle to a libsecp256k1 object, as returned by ffi.new: the
# cffi cdata type is not expressible in the type system, but a named
# alias still says what the value is
CData = Any

ffi = _btclib_libsecp256k1.ffi


def _load_lib() -> Any:
    """Return the libsecp256k1 handle of the extension module."""

    # a static extension has the library linked in
    if hasattr(_btclib_libsecp256k1, "lib"):
        return _btclib_libsecp256k1.lib

    # a dynamic one (cffi ABI mode) has to find, at run time, the shared
    # object shipped beside it
    path = pathlib.Path(_btclib_libsecp256k1.__file__).parent
    for suffix in (".dll", ".so", ".dylib"):
        for file in path.glob(f"libsecp256k1*{suffix}*"):
            try:
                return ffi.dlopen(str(file))
            except OSError:
                pass
    msg = f"no loadable shared libsecp256k1 found in {path}"
    raise ImportError(msg)


lib = _load_lib()

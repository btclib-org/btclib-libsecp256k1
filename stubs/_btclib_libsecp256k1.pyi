# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Type stub for the cffi generated extension module.

The extension is built at install time and has no source to inspect, so
without this stub mypy sees `ffi` and `lib` as `Any` and every wrapper in
the package type-checks vacuously: the whole codebase is a thin layer
over these two objects.

Only the surface the package actually uses is declared. `lib` stays `Any`
on purpose: its members are the ~100 libsecp256k1 entry points, declared
in C and generated at build time, so a hand-written stub for them would
be a second source of truth that nothing keeps honest.

`unpack` is narrowed to bytes. In general it returns bytes, str or a
list, depending on the cdata type; the package only ever unpacks
`char[]`, which is the bytes case.
"""

from typing import Any

class _FFI:
    NULL: Any
    def new(self, cdecl: str, init: Any = ...) -> Any: ...
    def unpack(self, cdata: Any, length: int) -> bytes: ...
    def dlopen(self, name: str) -> Any: ...

ffi: _FFI
lib: Any

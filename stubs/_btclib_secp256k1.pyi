# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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

`buffer` answers a writable view of what a cdata owns, and its length is
that of the memory rather than of a pointer to it: `_secret` reads both
from it. `memoryview` is what it is used as -- sliced, assigned to, and
measured -- so that is what it is declared to return.

`addressof` is how a field of a struct is passed where libsecp256k1 wants
a pointer to it: the found outputs of `silentpayments` carry an x-only
public key and a label by value, and each has to reach its own serializer.
"""

from typing import Any

class _FFI:
    NULL: Any
    def new(self, cdecl: str, init: Any = ...) -> Any: ...
    def addressof(self, cdata: Any, field: str) -> Any: ...
    def sizeof(self, cdecl_or_cdata: Any) -> int: ...
    def buffer(self, cdata: Any, size: int = ...) -> memoryview: ...
    def unpack(self, cdata: Any, length: int) -> bytes: ...
    def string(self, cdata: Any) -> bytes: ...
    def callback(self, cdecl: str, python_callable: Any) -> Any: ...
    def dlopen(self, name: str) -> Any: ...

ffi: _FFI
lib: Any

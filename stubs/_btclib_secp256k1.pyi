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

`from_buffer` and `memmove` are the two halves of what a caller's own 32
octets can become. The first re-views them as the item type the boundary
takes, without copying and while keeping the memory alive, which is
`_scalar._owned_octets`; the second fills a buffer this package allocated
from either a `bytes` or a cdata, which is `_secret.scalar_buffer`, where
a copy is owed because libsecp256k1 writes through the pointer or because
this package wipes it afterwards.

`addressof` is how a field of a struct is passed where libsecp256k1 wants
a pointer to it: the found outputs of `silentpayments` carry an x-only
public key and a label by value, and each has to reach its own serializer.

`typeof` resolves a cdecl once, at import, for the buffers whose
declaration is built by an f-string, and `new` takes what it answers as
well as a string. `_CType` is what says so: with `Any` there instead,
`new` accepts anything at all -- `ffi.new(_XONLY_SIZE)`, an int where a
cdecl belongs, and the size and the type it was built from now sit a
dozen lines apart in the same module -- which is the vacuous
type-checking this file exists to prevent.

`typeof` also answers *about* a cdata, which is how `_scalar.scalar`
asks whether the 32 octets it was handed are an array of them: the
parameter is therefore `Any`, as `sizeof`'s already is for taking either
a cdecl or a cdata, cdata being what this file cannot name. The three
fields of `_CType` are the ones that question reads -- the kind, the
element type, and the name to put in the exception -- and they are here
rather than opaque because something now reads them.
"""

from typing import Any

class _CType:
    kind: str
    cname: str
    item: _CType

class _FFI:
    NULL: Any
    def new(self, cdecl: str | _CType, init: Any = ...) -> Any: ...
    def typeof(self, cdecl_or_cdata: Any) -> _CType: ...
    def addressof(self, cdata: Any, field: str) -> Any: ...
    def sizeof(self, cdecl_or_cdata: Any) -> int: ...
    def buffer(self, cdata: Any, size: int = ...) -> memoryview: ...
    def from_buffer(self, cdecl: str | _CType, python_buffer: Any) -> Any: ...
    def memmove(self, dest: Any, src: Any, n: int) -> None: ...
    def unpack(self, cdata: Any, length: int) -> bytes: ...
    def string(self, cdata: Any) -> bytes: ...
    def callback(self, cdecl: str, python_callable: Any) -> Any: ...
    def dlopen(self, name: str) -> Any: ...

ffi: _FFI
lib: Any

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Pure python cffi bindings to libsecp256k1: https://github.com/bitcoin-core/secp256k1.

Every entry point of these bindings takes octets and answers octets. A
libsecp256k1 object crosses the boundary only where a caller already
holds one, and there are two ways it can. The first is a `parse`:
`keys.parse` and `keys.serialize`, and the pairs beside them in `xonly`,
`dsa`, `recovery` and `silentpayments`, are that bridge, and a MuSig2
session driven through the raw `lib` is who is on the other side of it.

The second is a keypair, which has no bridge because it has no
serialization to be one: `secp256k1_keypair` holds a private key in
libsecp256k1's own layout, and the C API creates one and never writes it
out. A caller that built one -- through `lib`, as a MuSig2 signer does --
holds an object nothing here could have handed it as octets, and
`xonly.from_keypair` is what reads the public key off it.
`ssa.Signer.pubkey` is that same call for a caller that let this package
build the keypair instead.

Under each of those entry points is the half of it that speaks in those
objects, spelled `_foo_`. The leading underscore says private, because
an object is a promise no argument check can hold a caller to: what can
be proved of a bare pointer's contents is nothing, and what answers for
it is libsecp256k1 itself, through the illegal callback `context.guarded`
turns back into an exception. The trailing one says which kind of
private, `_verify_` taking a parsed key where `_parse_der` is an
ordinary helper. `foo` is `_foo_` with a parse in front of it, a
serialize behind it, or both, which is the equality
`tests/test_parsed_keys.py` holds every pair to; what the private half
saves is what composing two public ones pays between them, a
serialization of a point that was already in hand and a parse of what
was just serialized -- and for a compressed key that parse is a field
square root.
"""

import pathlib
from importlib.metadata import version
from typing import Any

import _btclib_secp256k1

# read from the installed distribution metadata, so that the version in
# pyproject.toml stays the only place to bump at release time
__version__ = version("btclib_secp256k1")

# an opaque handle to a libsecp256k1 object, as returned by ffi.new: the
# cffi cdata type is not expressible in the type system, but a named
# alias still says what the value is
CData = Any

# what may be handed to an argument these bindings pass on as a bare
# pointer. Three named types rather than the buffer protocol at large:
# `bytes(x)` of anything else is a guess -- of an `int` it is that many
# zero octets, which would turn `octets(32, "message hash", 32)` into a
# valid argument -- while these three state a value and a width and are
# copied, never passed through. `collections.abc.Buffer` is the same
# idea and arrives with python 3.12, which is not yet the floor here
BytesLike = bytes | bytearray | memoryview

ffi = _btclib_secp256k1.ffi


def _load_lib(module: Any) -> Any:
    """Return the libsecp256k1 handle of the extension module.

    The extension is taken as an argument, rather than read from the
    enclosing scope, because only one of the two branches below exists
    in any given build: the other one is only reachable, and therefore
    only testable, with a stand-in.

    Args:
        module: the compiled extension module, or a stand-in for it.

    Returns:
        The object every wrapper calls libsecp256k1 through: the `lib`
        of a static extension, or what `ffi.dlopen` returns for the
        shared object shipped beside a dynamic one.

    Raises:
        ImportError: if the extension carries no linked-in library and
            no shared object beside it can be loaded. Chains the last
            loader error, if any candidate was rejected rather than
            merely absent.
    """
    # a static extension has the library linked in
    if hasattr(module, "lib"):
        return module.lib

    # a dynamic one (cffi ABI mode) has to find, at run time, the shared
    # object shipped beside it
    path = pathlib.Path(module.__file__).parent
    rejected: list[tuple[str, OSError]] = []
    for suffix in (".dll", ".so", ".dylib"):
        for file in path.glob(f"libsecp256k1*{suffix}*"):
            try:
                return ffi.dlopen(str(file))
            except OSError as exc:
                # a file the loader rejects does not end the search: a
                # wheel repaired by auditwheel or delocate can ship more
                # than one match, only one of which is the library --
                # but its error is worth keeping, in case none is
                rejected.append((file.name, exc))
    if rejected:
        tried = ", ".join(f"{name} ({exc})" for name, exc in rejected)
        msg = f"no loadable shared libsecp256k1 found in {path}, tried: {tried}"
        raise ImportError(msg) from rejected[-1][1]
    msg = f"no loadable shared libsecp256k1 found in {path}"
    raise ImportError(msg)


lib = _load_lib(_btclib_secp256k1)

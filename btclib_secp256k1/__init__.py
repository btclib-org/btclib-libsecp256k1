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
it is libsecp256k1 itself, through the illegal callback -- which these
wrappers do not read, so a private half handed an object libsecp256k1
cannot use answers whatever that call answers: its own exception where a
return code allowed one, and otherwise a `False`, an ordering or a
shared secret that mean nothing. `context.check` immediately after the
call is what says so, and the public entry point above is the one with
no such case, having parsed the octets itself. The trailing one says
which kind of
private, `_verify_` taking a parsed key where `_parse_der` is an
ordinary helper. `foo` is `_foo_` with a parse in front of it, a
serialize behind it, or both, which is the equality
`tests/test_parsed_keys.py` holds every pair to; what the private half
saves is what composing two public ones pays between them, a
serialization of a point that was already in hand and a parse of what
was just serialized -- and for a compressed key that parse is a field
square root.
"""

from typing import TYPE_CHECKING, Any

import _btclib_secp256k1


def _read_version() -> str:
    """Read the version out of the installed distribution metadata.

    That is where it comes from so that the version in pyproject.toml
    stays the only place to bump at release time. Where it is read is
    the `__getattr__` below; this is only the reading of it, and it is
    out here rather than inside that function because mypy does not
    check the body of the `else` a `TYPE_CHECKING` guard takes -- a
    `return len(...)` from a function annotated `-> str` passes
    `--strict` in there, and is caught as `[return-value]` out here.

    `importlib.metadata` is not a small module to reach for -- `email`,
    `json` and `inspect` are three of the ones it pulls behind it -- so
    the import is deferred to the one call that needs it.

    Returns:
        The version of the installed distribution.
    """
    from importlib.metadata import version  # noqa: PLC0415

    return version("btclib_secp256k1")


if TYPE_CHECKING:
    # what a type checker is told, and it is told this instead of the
    # function below rather than as well: a module with a `__getattr__`
    # is one mypy stops checking attribute names on altogether, so
    # `from btclib_secp256k1 import nosuchmodule` and
    # `btclib_secp256k1.typo` both start passing --strict. That is the
    # front door of this package, the line every caller writes, and the
    # two checks are worth the six lines it takes to keep them
    __version__: str
else:

    def __getattr__(name: str) -> str:
        """Build the one attribute this module makes only when asked.

        `__version__` is that attribute, and reading it at import is
        what made that import 15.85 milliseconds where it is now 1.69 --
        an Apple M5, macOS 26.6, arm64, CPython 3.14.6, minimum of 12
        fresh interpreters. CHANGELOG.md carries the command, the rest
        of the table and what the 14 milliseconds are made of, so that
        the decomposition is written down once. So the caller that wants
        the version pays for it and the one that never asks pays
        nothing; btclib, which depends on this package, is one of
        those.

        The value is stored into the module's own namespace on the way
        out, which is the usual shape of PEP 562 and is what keeps the
        second read a dict lookup rather than another walk of the
        metadata: `importlib.metadata.version` is 290 microseconds every
        time it is called, `sys.modules` caching the module and not the
        answer. So `dir()` does not list `__version__` until something
        reads it, and does afterwards.

        Args:
            name: the attribute being looked up.

        Returns:
            The version of the installed distribution, for
            `__version__`.

        Raises:
            AttributeError: for any other name, this being the fallback
                python calls only once the module itself has none.
        """
        if name == "__version__":
            globals()["__version__"] = value = _read_version()
            return value
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)


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

# what a caller may hand a producer of secrets to be written into,
# instead of taking the `bytes` it would otherwise return. `bytes` is
# absent for the reason the whole facility exists: it cannot be
# overwritten, so writing a secret there would buy nothing.
#
# The runtime is wider than this: `_secret.into_buffer` takes whatever
# the buffer protocol offers and is writable, an `mmap` and an
# `array.array("B")` included. These two are what a typed caller passes
# bare -- `collections.abc.Buffer` is the alias that would say the rest
# and arrives with python 3.12, which is not yet the floor here -- and
# anything else is `memoryview(x)`, which copies nothing
MutableBytesLike = bytearray | memoryview

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
    # object shipped beside it. pathlib is imported here rather than at
    # module level because the line above is where a static build
    # returns, and a static build is what every platform of the matrix
    # ships by default: 2.27 milliseconds of an import that is 1.69
    # milliseconds without it, measured as `__getattr__` says. It is
    # worth that only alongside the deferral there -- `importlib.metadata`
    # imports pathlib itself, so this line on its own would save nothing
    import pathlib  # noqa: PLC0415

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

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Overwriting the libsecp256k1 buffers a secret passes through.

What SECURITY.md records as inherent is the python side: a `bytes` is
immutable, so the secret a caller hands in and the one handed back stay
in the process until the garbage collector gets to them, and may have
been copied on the way. The buffers here are not that. They are memory
cffi allocated and this package owns, they are writable, and nothing
outside these wrappers ever sees them -- so the copy they hold is the
one copy that can be taken back, and leaving it was an omission rather
than a limit.

It buys one copy, not safety: the `bytes` returned to the caller holds
the same secret and cannot be overwritten. Scalar work that must not
leave a trace belongs where that can be promised.

`into` is where that last copy stops being a `bytes`. A caller who
hands a producer of secrets a writable buffer gets the secret written
there and nothing returned, so the un-zeroizable object is never made
-- and the wiping of what is left is theirs, which is the whole of the
difference. #87 declined an opaque *handle* for a reason this does not
disturb: a handle is a lifetime someone has to own and invalidate, and
belongs where the signing state lives. This is one argument and one
call, and owns nothing.

The one such buffer this package builds rather than fills is the
keypair, and `keypair` below is where it is built, so that the module
holding the obligation to wipe one is the module that hands one out.
"""

from __future__ import annotations

from typing import overload

from . import BytesLike, CData, MutableBytesLike, ffi, lib
from ._scalar import scalar
from .context import ctx


def _zero(memory: memoryview) -> None:
    """Overwrite what a cffi buffer views.

    The statement that writes the zeros, written once: `wipe` builds the
    view over a cdata, and `take` is already holding one it read the
    secret through, so calling `wipe` from there would build a second
    over the same memory.

    That it is a function and not the statement inlined in both places
    is a trade made deliberately and against the faster spelling.
    Measured over the same session as every other figure of this change,
    which CHANGELOG.md names: calling `wipe` a second time is 0.1826
    microseconds, this is 0.1439, and the inlined statement is 0.1314.
    So the frame gives up about a quarter of what is on the table, and
    what it buys is that the line which overwrites a secret exists once:
    two copies are two things to keep true, in the one facility whose
    whole claim is about what is left in memory.

    Args:
        memory: the `ffi.buffer` to overwrite, and a view of the whole
            cdata rather than a slice of one -- `wipe` builds it from
            the cdata for the reason its own docstring gives, and
            `_zero(ffi.buffer(buffer, 8))` would zero a quarter of the
            private key inside a keypair and report success, which is
            the failure that docstring records. Typed as the stub
            declares `ffi.buffer` to answer, this being the module that
            reads both a slice and a length off one.
    """
    memory[:] = bytes(len(memory))


def wipe(buffer: CData) -> None:
    """Overwrite a buffer that held a secret.

    The length is the buffer's own, and is asked of it rather than
    written here: `ffi.buffer` answers the size of what a cdata owns,
    which for the `secp256k1_keypair *` below is the 96 octets of the
    struct and not the 8 of the pointer -- `ffi.sizeof` would have said
    8, and wiped the first quarter of the private key while reporting
    success.

    Args:
        buffer: the cffi buffer to overwrite, as `ffi.new` returned it.
    """
    _zero(ffi.buffer(buffer))


def into_buffer(into: object, size: int) -> memoryview:
    """Hold a caller's buffer to what a secret is about to be written to.

    What is required is a buffer of exactly `size` writable, contiguous
    octets, and anything else is refused rather than adapted. The length
    is the one that matters: `into[:] = ...` of a short buffer raises
    anyway, but a caller who sized it by hand should be told what it
    should have been, and a *longer* one would take the secret in its
    first octets and leave whatever was in the rest -- which reads as a
    secret with a tail. A read-only view cannot be written and cannot be
    wiped either, so it would defeat the facility silently. Items wider
    than an octet are refused for the reason `_scalar.octets` refuses
    them: the view states a width this would not be honouring.

    Contiguity is two refusals rather than one, and neither is
    fastidious. A view of more than one dimension passes every other
    check -- `memoryview(bytearray(32)).cast("B", (4, 8))` is writable,
    octet-wide and 32 octets long -- and then fails the copy itself with
    `NotImplementedError`, which is neither of the two exceptions a
    caller was told to expect. A strided one *works*, and is refused all
    the same: `memoryview(bytearray(64))[::2]` would leave the secret
    scattered through 64 octets of an owner whose other 32 the caller
    has no reason to think are involved, and a wipe through the view
    would be right while a wipe of the owner would look right and not
    be.

    Anything the buffer protocol offers is otherwise accepted, an
    `mmap` and an `array.array("B")` included -- the first of those
    being a plausible destination, `mlock`ed, for exactly the caller
    this exists for. What refuses a non-buffer is `memoryview` itself.

    Typed `object` rather than `MutableBytesLike`, that being the
    annotation this exists to not trust: a caller is not obliged to run
    a type checker, and the whole job here is to answer what happens
    when they did not.

    Args:
        into: the buffer, as the caller passed it.
        size: the number of octets the secret is.

    Returns:
        A `memoryview` of the buffer, one octet per item, which is what
        the copy is made through.

    Raises:
        TypeError: if it is not a writable buffer of contiguous
            one-dimensional octets.
        ValueError: if it is not exactly `size` octets long.
    """
    try:
        # the annotation is `object` on purpose, and mypy is right that
        # `memoryview` wants a Buffer: asking whether this one is a
        # buffer is what the call is for, and the answer is the
        # TypeError below
        view = memoryview(into)  # type: ignore[arg-type]
    except TypeError:
        msg = (
            "the buffer to write into must be a writable buffer, "
            f"not {type(into).__name__}"
        )
        raise TypeError(msg) from None
    if view.readonly:
        raise TypeError("the buffer to write into must be writable")
    if view.itemsize != 1:
        msg = (
            "the buffer to write into must be a buffer of bytes, "
            f"not of {view.itemsize}-byte items"
        )
        raise TypeError(msg)
    if view.ndim != 1 or not view.c_contiguous:
        raise TypeError("the buffer to write into must be contiguous octets")
    if view.nbytes != size:
        raise ValueError(f"the buffer to write into must be {size} bytes")
    return view


@overload
def take(buffer: CData) -> bytes: ...
@overload
def take(buffer: CData, *, into: MutableBytesLike) -> None: ...
@overload
def take(buffer: CData, *, into: MutableBytesLike | None) -> bytes | None: ...
def take(buffer: CData, *, into: MutableBytesLike | None = None) -> bytes | None:
    """Read a secret out of the buffer holding it, and overwrite that.

    The pair of operations every wrapper producing a secret ends with,
    so that neither is done without the other.

    With `into`, the secret is copied there instead of into a `bytes`,
    and nothing is returned. That is the whole of what the argument
    buys, and it is worth being exact about: this package's own buffer
    is wiped either way, and what changes is only whether the copy the
    caller ends up holding is one they can overwrite. It does not
    overwrite it for them, and the argument that produced the secret is
    still whatever they made it out of. See SECURITY.md.

    Either way this package's buffer is left zeroed, a refused `into`
    included: the pair is the point, and a failure is no reason to keep
    a secret the caller cannot reach.

    Args:
        buffer: the cffi buffer holding the secret.
        into: a writable buffer of exactly the secret's length, to
            receive it instead of a `bytes`.

    Returns:
        Its contents as bytes, the buffer itself left zeroed -- or None
        where `into` was given and has been written to.

    Raises:
        TypeError: if `into` is not a writable buffer of contiguous
            one-dimensional octets.
        ValueError: if `into` is not the secret's length.
    """
    # the zeroing goes through this view rather than through `wipe`,
    # which would build a second one over the same cdata: what `wipe`
    # writes is `_zero`, and it is that statement both paths reach
    memory = ffi.buffer(buffer)
    if into is None:
        secret = bytes(memory)
        _zero(memory)
        return secret
    # the zeroing is in a `finally` because `into_buffer` can refuse, and
    # this is the one call here with a failure path: without it a
    # rejected buffer returns through the entry point leaving a live
    # private key in cffi memory that is freed without being
    # overwritten, in the one facility whose whole claim is about where
    # copies of secrets live. Nothing is lost by wiping on the way out:
    # the value never reached the caller, and the operation they retry
    # recomputes it
    try:
        view = into_buffer(into, len(memory))
        view[:] = memory
    finally:
        _zero(memory)
    return None


def scalar_buffer(prvkey: BytesLike | int | CData, name: str) -> CData:
    """Copy a scalar into 32 octets of this package's own memory.

    The copy `_scalar.scalar` does not take, taken where it is owed --
    which is two situations rather than one, and neither is about
    distrusting the caller:

    - libsecp256k1 *writes through* the pointer.
      `secp256k1_ec_seckey_negate`, `_tweak_add` and `_tweak_mul` all
      answer in place, and the caller's own key must not be overwritten
      by a function that returns a new one;
    - this package *wipes* the buffer afterwards, which
      `silentpayments._create_outputs_` does in a `finally` for every
      private key it built. Wiping memory the caller handed in would zero
      their key on the way out of a call that only read it.

    So a `bytes` or a cdata arrives here and 32 octets of ours leave, and
    `take` or an explicit `wipe` is what the caller of this owes in turn.
    `ffi.memmove` is what fills it, rather than `ffi.new(cdecl, ...)`:
    that takes an initializer, which is `bytes` or a list and never a
    cdata of another item type -- the four call sites used to spell it
    that way and refused a caller's buffer with cffi's own message about
    an internal `char[32]`. It also means no `bytes` of the secret is made
    in between, which is the whole of what a caller holding a buffer came
    for.

    Args:
        prvkey: the scalar, as the caller passed it, in any form
            `_scalar.scalar` accepts.
        name: what the scalar is, as the exception should call it.

    Returns:
        A `char[32]` holding those octets, for the caller of this to hand
        libsecp256k1 and then to wipe.

    Raises:
        TypeError: propagated from `_scalar.scalar`.
        ValueError: propagated from it too, a length among the reasons.
    """
    buffer = ffi.new("char[32]")
    # the length is the buffer's own, as it is in `wipe`, rather than a
    # literal written a second time beside the cdecl
    ffi.memmove(buffer, scalar(prvkey, name), ffi.sizeof(buffer))
    return buffer


def keypair(prvkey: BytesLike | int) -> CData:
    """Build the libsecp256k1 keypair of a private key.

    Three modules need one -- `ssa` to sign, `xonly` to tweak a taproot
    private key, `silentpayments` to spend a taproot input -- and each
    wipes it on the way out, `wipe` above being how. That is why the
    building of it lives here beside the wiping rather than in `keys`:
    what a keypair holds is the private key in libsecp256k1's own
    layout, so a caller of this owes the buffer a `wipe`, and the two
    halves of that obligation are better read together than looked up in
    two places.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The libsecp256k1 keypair object, which the caller wipes.

    Raises:
        TypeError: if the key is neither an int nor bytes.
        ValueError: if it is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
    """
    buffer = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, buffer, scalar(prvkey, "private key")):
        raise ValueError("invalid private key: not in [1, n-1]")
    return buffer

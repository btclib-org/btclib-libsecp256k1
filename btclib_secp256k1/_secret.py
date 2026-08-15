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

The one such buffer this package builds rather than fills is the
keypair, and `keypair` below is where it is built, so that the module
holding the obligation to wipe one is the module that hands one out.
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, lib
from ._scalar import scalar
from .context import ctx


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
    memory = ffi.buffer(buffer)
    memory[:] = bytes(len(memory))


def take(buffer: CData) -> bytes:
    """Read a secret out of the buffer holding it, and overwrite that.

    The pair of operations every wrapper producing a secret ends with,
    so that neither is done without the other.

    Args:
        buffer: the cffi buffer holding the secret.

    Returns:
        Its contents, as bytes, the buffer itself left zeroed.
    """
    secret = bytes(ffi.buffer(buffer))
    wipe(buffer)
    return secret


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

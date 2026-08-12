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
"""

from __future__ import annotations

from . import CData, ffi


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

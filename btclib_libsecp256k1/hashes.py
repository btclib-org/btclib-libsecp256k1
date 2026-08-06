# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tagged hashing, according to BIP340.

https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
"""

from __future__ import annotations

from . import ffi, lib
from .context import ctx


def tagged_sha256(tag: bytes, msg: bytes) -> bytes:
    """Return the BIP340 tagged hash of a message.

    That is SHA256(SHA256(tag) || SHA256(tag) || msg): the tag separates
    the domains of the protocols using it, so that what one of them signs
    cannot be read as a message of another. The BIP340 challenge and the
    BIP341 taproot tags (TapLeaf, TapBranch, TapTweak) are built with it.

    Args:
        tag: the domain separation tag, of any length.
        msg: the message to hash, of any length.

    Returns:
        The 32-byte tagged hash.

    Raises:
        RuntimeError: if libsecp256k1 fails, which no input can make it
            do.

    Example:
        >>> from btclib_libsecp256k1 import hashes
        >>> hashes.tagged_sha256(b"TapLeaf", b"").hex()
        '5212c288a377d1f8164962a5a13429f9ba6a7b84e59776a52c6637df2106facb'
    """
    output = ffi.new("char[32]")
    if not lib.secp256k1_tagged_sha256(ctx, output, tag, len(tag), msg, len(msg)):
        raise RuntimeError("tagged hashing failed")
    return ffi.unpack(output, 32)

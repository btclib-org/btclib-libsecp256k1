# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

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
    """

    output = ffi.new("char[32]")
    if not lib.secp256k1_tagged_sha256(ctx, output, tag, len(tag), msg, len(msg)):
        raise RuntimeError("tagged hashing failed")
    return ffi.unpack(output, 32)

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Diffie-Hellman (ECDH)."""

from __future__ import annotations

from . import ffi, lib
from .context import ctx


def shared_secret(pubkey_bytes: bytes, prvkey: bytes | int) -> bytes:
    """Compute the ECDH shared secret.

    The result is the SHA256 of the compressed shared point, i.e. the
    libsecp256k1 default hash function; it is computed in constant time.
    """

    prvkey_bytes = prvkey.to_bytes(32, "big") if isinstance(prvkey, int) else prvkey
    if len(prvkey_bytes) != 32:
        raise ValueError("the private key must be 32 bytes")

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    output = ffi.new("char[32]")
    # a NULL hash function selects secp256k1_ecdh_hash_function_sha256,
    # which writes 32 bytes to output
    if not lib.secp256k1_ecdh(ctx, output, pubkey, prvkey_bytes, ffi.NULL, ffi.NULL):
        raise ValueError("invalid private key")
    return ffi.unpack(output, 32)

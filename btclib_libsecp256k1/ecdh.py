# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Diffie-Hellman (ECDH)."""

from __future__ import annotations

from . import ffi, lib
from ._scalar import scalar
from .context import ctx


def shared_secret(pubkey_bytes: bytes, prvkey: bytes | int) -> bytes:
    """Compute the ECDH shared secret.

    The result is the SHA256 of the compressed shared point, i.e. the
    libsecp256k1 default hash function; it is computed in constant time.

    The hash function is not configurable, by decision. libsecp256k1
    takes it as a C callback, so exposing it would mean calling back into
    python from the middle of the computation, with the shared point
    passing through python objects; and it would buy nothing, the point
    being available as keys.pubkey_tweak_mul(pubkey_bytes, prvkey),
    itself constant time. A protocol needing another derivation applies
    it to that: SHA256 of it is what this function returns.

    Args:
        pubkey_bytes: the other party's public key, 33 or 65 bytes.
        prvkey: this party's private key, 32 bytes or an int below
            2**256.

    Returns:
        The 32-byte shared secret.

    Raises:
        ValueError: if the public key is not a valid point, if the
            private key is not 32 bytes or does not fit in them, or if
            it is not a valid scalar.
    """
    prvkey_bytes = scalar(prvkey, "private key")

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    output = ffi.new("char[32]")
    # a NULL hash function selects secp256k1_ecdh_hash_function_sha256,
    # which writes 32 bytes to output
    if not lib.secp256k1_ecdh(ctx, output, pubkey, prvkey_bytes, ffi.NULL, ffi.NULL):
        raise ValueError("invalid private key")
    return ffi.unpack(output, 32)

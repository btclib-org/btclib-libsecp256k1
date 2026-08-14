# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Diffie-Hellman (ECDH)."""

from __future__ import annotations

from . import BytesLike, CData, ffi, keys, lib
from ._scalar import scalar
from ._secret import take
from .context import ctx


def shared_secret_(pubkey: CData, prvkey: BytesLike | int) -> bytes:
    """Compute the ECDH shared secret from an already-parsed public key.

    The inner half of `shared_secret`, for a caller who already holds the
    other party's parsed key -- one exchanging with the same counterparty
    more than once, or one that validated the key on receipt: see
    `keys.parse` for what the underscore means throughout.

    Args:
        pubkey: the other party's already-parsed public key, as
            `keys.parse` returns.
        prvkey: this party's private key, 32 bytes or an int below
            2**256.

    Returns:
        The 32-byte shared secret, the SHA256 of the compressed shared
        point as `shared_secret` documents it.

    Raises:
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not a valid scalar.
    """
    prvkey_bytes = scalar(prvkey, "private key")

    output = ffi.new("char[32]")
    # a NULL hash function selects secp256k1_ecdh_hash_function_sha256,
    # which writes 32 bytes to output
    if not lib.secp256k1_ecdh(ctx, output, pubkey, prvkey_bytes, ffi.NULL, ffi.NULL):
        raise ValueError("invalid private key")
    return take(output)


def shared_secret(pubkey_bytes: BytesLike, prvkey: BytesLike | int) -> bytes:
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
    return shared_secret_(keys.parse(pubkey_bytes), prvkey)

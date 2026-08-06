# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ElligatorSwift encoding and x-only ECDH, according to BIP324.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
"""

from __future__ import annotations

import secrets

from . import ffi, lib
from ._scalar import scalar
from .context import ctx

# SECP256K1_EC_COMPRESSED: the libsecp256k1 flag macros do not survive
# the preprocessing of the headers into cffi definitions
COMPRESSED = 258


def create(prvkey: bytes | int, aux_rand32: bytes | None = None) -> bytes:
    """Create the 64-byte ElligatorSwift encoding of a private key's public key.

    This is safer than encode(mult_(prvkey)), as the private key itself
    is used as entropy for the encoding.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of auxiliary randomness, or None for fresh
            randomness.

    Returns:
        The 64-byte ElligatorSwift encoding of the public key.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes, or if
            the private key is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
    """
    prvkey_bytes = scalar(prvkey, "private key")

    # entropy is not a serialization: a shorter value is a caller mistake
    # rather than a small number, and is not padded into a valid argument
    if aux_rand32 is None:
        aux_rand32 = secrets.token_bytes(32)
    elif len(aux_rand32) != 32:
        raise ValueError("aux_rand32 must be 32 bytes")

    ell_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ellswift_create(ctx, ell_bytes, prvkey_bytes, aux_rand32):
        raise ValueError("invalid private key")
    return ffi.unpack(ell_bytes, 64)


def encode(pubkey_bytes: bytes, rnd32: bytes | None = None) -> bytes:
    """Encode a public key as 64 ElligatorSwift bytes.

    The randomness must not be a deterministic function of the public
    key; when it is not provided, it is freshly generated.

    Args:
        pubkey_bytes: the public key to encode, 33 or 65 bytes.
        rnd32: the 32 bytes deciding which of the encodings of that key
            is produced, or None for fresh randomness.

    Returns:
        The 64-byte ElligatorSwift encoding, indistinguishable from
        uniform bytes.

    Raises:
        ValueError: if the public key is not a valid point, or if rnd32
            is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to encode, which no valid
            input can make it do.
    """
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    # 32 bytes of entropy, or nothing: see the comment in create
    if rnd32 is None:
        rnd32 = secrets.token_bytes(32)
    elif len(rnd32) != 32:
        raise ValueError("rnd32 must be 32 bytes")

    ell_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ellswift_encode(ctx, ell_bytes, pubkey, rnd32):
        raise RuntimeError("ElligatorSwift encoding failed")
    return ffi.unpack(ell_bytes, 64)


def decode(ell_bytes: bytes) -> bytes:
    """Decode a 64-byte ElligatorSwift public key into its compressed form.

    Args:
        ell_bytes: the 64-byte encoding.

    Returns:
        The 33-byte compressed public key. Every 64 bytes decode to a
        point, which is what makes the encoding indistinguishable from
        random: there is nothing to reject.

    Raises:
        ValueError: if the input is not 64 bytes.
        RuntimeError: if libsecp256k1 fails to decode or serialize,
            which no 64 bytes can make it do.
    """
    if len(ell_bytes) != 64:
        raise ValueError("the ElligatorSwift public key must be 64 bytes")

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ellswift_decode(ctx, pubkey, ell_bytes):
        raise RuntimeError("ElligatorSwift decoding failed")

    output = ffi.new("char[33]")
    length = ffi.new("size_t *", 33)
    if not lib.secp256k1_ec_pubkey_serialize(ctx, output, length, pubkey, COMPRESSED):
        raise RuntimeError("point serialization failed")
    return ffi.unpack(output, 33)


def xdh(
    ell_a_bytes: bytes, ell_b_bytes: bytes, prvkey: bytes | int, party: int
) -> bytes:
    """Compute the x-only ECDH shared secret of two ElligatorSwift keys.

    The private key must be the one of the given party: 0 for party A,
    1 for party B; the correspondence is not checked. The 32-byte secret
    is derived with the BIP324 hash function.

    Args:
        ell_a_bytes: the 64-byte encoding of party A's key.
        ell_b_bytes: the 64-byte encoding of party B's key.
        prvkey: the private key of the party below, 32 bytes or an int
            below 2**256.
        party: 0 if the private key is A's, 1 if it is B's.

    Returns:
        The 32-byte shared secret, which both parties compute alike. The
        two encodings enter the hash in the order they are given here,
        so BIP324's initiator goes first.

    Raises:
        ValueError: if either encoding is not 64 bytes, if party is not
            0 or 1, or if the private key is not 32 bytes, does not fit
            in them, or is not a valid scalar.
    """
    if len(ell_a_bytes) != 64 or len(ell_b_bytes) != 64:
        raise ValueError("the ElligatorSwift public keys must be 64 bytes")
    if party not in (0, 1):
        raise ValueError("the party must be 0 (A) or 1 (B)")

    prvkey_bytes = scalar(prvkey, "private key")

    output = ffi.new("char[32]")
    if not lib.secp256k1_ellswift_xdh(
        ctx,
        output,
        ell_a_bytes,
        ell_b_bytes,
        prvkey_bytes,
        party,
        lib.secp256k1_ellswift_xdh_hash_function_bip324,
        ffi.NULL,
    ):
        raise ValueError("invalid private key")
    return ffi.unpack(output, 32)

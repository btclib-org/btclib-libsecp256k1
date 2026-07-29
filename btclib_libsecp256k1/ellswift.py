# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

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
    """

    prvkey_bytes = scalar(prvkey, "private key")

    if not aux_rand32:
        aux_rand32 = secrets.token_bytes(32)
    if len(aux_rand32) > 32:
        raise ValueError("aux_rand32 must be at most 32 bytes")
    aux_rand32 = b"\x00" * (32 - len(aux_rand32)) + aux_rand32

    ell_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ellswift_create(ctx, ell_bytes, prvkey_bytes, aux_rand32):
        raise ValueError("invalid private key")
    return ffi.unpack(ell_bytes, 64)


def encode(pubkey_bytes: bytes, rnd32: bytes | None = None) -> bytes:
    """Encode a public key as 64 ElligatorSwift bytes.

    The randomness must not be a deterministic function of the public
    key; when it is not provided, it is freshly generated.
    """

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    if not rnd32:
        rnd32 = secrets.token_bytes(32)
    if len(rnd32) > 32:
        raise ValueError("rnd32 must be at most 32 bytes")
    rnd32 = b"\x00" * (32 - len(rnd32)) + rnd32

    ell_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ellswift_encode(ctx, ell_bytes, pubkey, rnd32):
        raise RuntimeError("ElligatorSwift encoding failed")
    return ffi.unpack(ell_bytes, 64)


def decode(ell_bytes: bytes) -> bytes:
    """Decode a 64-byte ElligatorSwift public key into its compressed form."""

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

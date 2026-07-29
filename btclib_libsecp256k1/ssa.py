# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Variant of Elliptic Curve Schnorr Signature Algorithm (ECSSA), according.

to BIP340-Schnorr: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
"""
from __future__ import annotations

import secrets

from . import ffi, lib
from .context import ctx


def sign(
    msg_bytes: bytes, prvkey: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature."""

    if isinstance(prvkey, int):
        prvkey_bytes = prvkey.to_bytes(32, "big")
    else:
        prvkey_bytes = prvkey
    if len(prvkey_bytes) != 32:
        raise ValueError("the private key must be 32 bytes")
    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")

    keypair = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair, prvkey_bytes):
        raise ValueError("invalid private key")

    sig = ffi.new("char[64]")

    if not aux_rand32:
        aux_rand32 = secrets.token_bytes(32)
    if len(aux_rand32) > 32:
        raise ValueError("aux_rand32 must be at most 32 bytes")
    aux_rand32 = b"\x00" * (32 - len(aux_rand32)) + aux_rand32
    if lib.secp256k1_schnorrsig_sign32(ctx, sig, msg_bytes, keypair, aux_rand32):
        return ffi.unpack(sig, 64)
    raise RuntimeError("schnorr signing failed")


def verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify a Schhnorr signature."""

    if len(signature_bytes) != 64:
        raise ValueError("the signature must be 64 bytes")

    if len(pubkey_bytes) == 32:
        pubkey_bytes = b"\x02" + pubkey_bytes

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(
        ctx, xonly_pubkey, ffi.new("int *"), pubkey
    ):
        raise RuntimeError("x-only public key conversion failed")

    return bool(
        lib.secp256k1_schnorrsig_verify(
            ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
        )
    )

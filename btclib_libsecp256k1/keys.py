# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Secp256k1 key and point algebra.

These are the libsecp256k1 secret and public key operations, i.e. the
scalar and point arithmetic underlying key derivation (BIP32) and key
aggregation; libsecp256k1 calls a private key a secret key, hence its
seckey function names.

Public keys are returned in compressed form, unless otherwise required.
"""
from __future__ import annotations

from collections.abc import Sequence

from . import ffi, lib
from .context import ctx

# SECP256K1_EC_COMPRESSED and SECP256K1_EC_UNCOMPRESSED: the
# libsecp256k1 flag macros do not survive the preprocessing of the
# headers into cffi definitions
COMPRESSED = 258
UNCOMPRESSED = 2


def prvkey_verify(prvkey: bytes | int) -> bool:
    """Return True if the private key is a valid scalar, i.e. in [1, n-1]."""

    prvkey_bytes = _scalar(prvkey, "private key")
    return bool(lib.secp256k1_ec_seckey_verify(ctx, prvkey_bytes))


def prvkey_negate(prvkey: bytes | int) -> bytes:
    """Negate a private key."""

    prvkey_buffer = ffi.new("char[32]", _scalar(prvkey, "private key"))
    if not lib.secp256k1_ec_seckey_negate(ctx, prvkey_buffer):
        raise ValueError("invalid private key")
    return ffi.unpack(prvkey_buffer, 32)


def prvkey_tweak_add(prvkey: bytes | int, tweak: bytes | int) -> bytes:
    """Add a tweak to a private key."""

    prvkey_buffer = ffi.new("char[32]", _scalar(prvkey, "private key"))
    tweak_bytes = _scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_add(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return ffi.unpack(prvkey_buffer, 32)


def prvkey_tweak_mul(prvkey: bytes | int, tweak: bytes | int) -> bytes:
    """Multiply a private key by a tweak."""

    prvkey_buffer = ffi.new("char[32]", _scalar(prvkey, "private key"))
    tweak_bytes = _scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_mul(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return ffi.unpack(prvkey_buffer, 32)


def pubkey_negate(pubkey_bytes: bytes, compressed: bool = True) -> bytes:
    """Negate a public key."""

    pubkey = parse(pubkey_bytes)
    if not lib.secp256k1_ec_pubkey_negate(ctx, pubkey):
        raise RuntimeError("public key negation failed")
    return serialize(pubkey, compressed)


def pubkey_tweak_add(
    pubkey_bytes: bytes, tweak: bytes | int, compressed: bool = True
) -> bytes:
    """Add the generator multiplied by the tweak to a public key."""

    pubkey = parse(pubkey_bytes)
    tweak_bytes = _scalar(tweak, "tweak")
    if not lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak_bytes):
        raise ValueError("invalid tweak or resulting public key")
    return serialize(pubkey, compressed)


def pubkey_tweak_mul(
    pubkey_bytes: bytes, tweak: bytes | int, compressed: bool = True
) -> bytes:
    """Multiply a public key by a tweak.

    This is the multiplication of an arbitrary point, as opposed to the
    multiplication of the generator provided by the mult module.
    """

    pubkey = parse(pubkey_bytes)
    tweak_bytes = _scalar(tweak, "tweak")
    if not lib.secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak_bytes):
        raise ValueError("invalid tweak")
    return serialize(pubkey, compressed)


def pubkey_combine(pubkeys_bytes: Sequence[bytes], compressed: bool = True) -> bytes:
    """Add public keys together."""

    if not pubkeys_bytes:
        raise ValueError("at least one public key is required")

    pubkeys = [parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes]
    combined = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_combine(
        ctx, combined, ffi.new("secp256k1_pubkey *[]", pubkeys), len(pubkeys)
    ):
        raise ValueError("invalid public key sum")
    return serialize(combined, compressed)


def parse(pubkey_bytes: bytes):
    """Parse a public key into its internal libsecp256k1 representation."""

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")
    return pubkey


def serialize(pubkey, compressed: bool = True) -> bytes:
    """Serialize an internal public key, in compressed form by default."""

    size = 33 if compressed else 65
    output = ffi.new(f"char[{size}]")
    length = ffi.new("size_t *", size)
    flags = COMPRESSED if compressed else UNCOMPRESSED
    if not lib.secp256k1_ec_pubkey_serialize(ctx, output, length, pubkey, flags):
        raise RuntimeError("point serialization failed")
    return ffi.unpack(output, size)


def _scalar(num: bytes | int, name: str) -> bytes:
    """Normalize a scalar argument to 32 bytes."""

    num_bytes = num.to_bytes(32, "big") if isinstance(num, int) else num
    if len(num_bytes) != 32:
        raise ValueError(f"the {name} must be 32 bytes")
    return num_bytes

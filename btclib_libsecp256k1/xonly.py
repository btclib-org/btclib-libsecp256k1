# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""X-only public keys and their tweaking.

According to BIP340-Schnorr and to the BIP341 taproot key path:
https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

An x-only public key is the 32-byte x coordinate of the point with even
y; the parity returned along a tweaked key is the one of the tweaked
point, to be committed to by the taproot output.
"""

from __future__ import annotations

from . import CData, ffi, lib
from ._scalar import scalar
from .context import ctx


def from_pubkey(pubkey_bytes: bytes) -> tuple[bytes, int]:
    """Convert a public key into its x-only form and y parity."""

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")
    return _to_xonly(pubkey)


def tweak_add(pubkey_bytes: bytes, tweak: bytes | int) -> tuple[bytes, int]:
    """Add the generator multiplied by the tweak to an x-only public key.

    Return the tweaked x-only public key and its y parity. The input is
    either an x-only public key or a public key, whose even y point is
    then the tweaked one.
    """

    internal_pubkey = _parse(pubkey_bytes)
    tweak_bytes = scalar(tweak, "tweak")

    tweaked_pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_xonly_pubkey_tweak_add(
        ctx, tweaked_pubkey, internal_pubkey, tweak_bytes
    ):
        raise ValueError("invalid tweak or resulting public key")
    return _to_xonly(tweaked_pubkey)


def tweak_add_check(
    tweaked_pubkey_bytes: bytes,
    tweaked_parity: int,
    pubkey_bytes: bytes,
    tweak: bytes | int,
) -> bool:
    """Check that a tweaked x-only public key is the tweak of another one.

    This is the verification of a taproot commitment: it is cheaper than
    recomputing the tweak, as it compares the serialized keys.
    """

    if len(tweaked_pubkey_bytes) != 32:
        raise ValueError("the tweaked x-only public key must be 32 bytes")
    if tweaked_parity not in (0, 1):
        raise ValueError("the parity must be 0 or 1")

    internal_pubkey = _parse(pubkey_bytes)
    tweak_bytes = scalar(tweak, "tweak")

    return bool(
        lib.secp256k1_xonly_pubkey_tweak_add_check(
            ctx, tweaked_pubkey_bytes, tweaked_parity, internal_pubkey, tweak_bytes
        )
    )


def prvkey_tweak_add(prvkey: bytes | int, tweak: bytes | int) -> bytes:
    """Add a tweak to the private key of an x-only public key.

    The private key is first negated, if needed, to be the one of the
    even y point, so that the x-only public key of the result is the
    tweak_add of the x-only public key of the input: this is the private
    key to sign a taproot key path spending with.
    """

    keypair = _keypair(prvkey)
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_keypair_xonly_tweak_add(ctx, keypair, tweak_bytes):
        raise ValueError("invalid tweak or resulting private key")

    prvkey_buffer = ffi.new("char[32]")
    if not lib.secp256k1_keypair_sec(ctx, prvkey_buffer, keypair):
        raise RuntimeError("private key extraction failed")
    return ffi.unpack(prvkey_buffer, 32)


def _parse(pubkey_bytes: bytes) -> CData:
    """Parse an x-only public key, or the even y point of a public key."""

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if len(pubkey_bytes) == 32:
        if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pubkey, pubkey_bytes):
            raise ValueError("invalid x-only public key")
        return xonly_pubkey

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(
        ctx, xonly_pubkey, ffi.new("int *"), pubkey
    ):
        raise RuntimeError("x-only public key conversion failed")
    return xonly_pubkey


def _to_xonly(pubkey: CData) -> tuple[bytes, int]:
    """Serialize a public key as its x-only form and y parity."""

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    parity = ffi.new("int *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(ctx, xonly_pubkey, parity, pubkey):
        raise RuntimeError("x-only public key conversion failed")

    output = ffi.new("char[32]")
    if not lib.secp256k1_xonly_pubkey_serialize(ctx, output, xonly_pubkey):
        raise RuntimeError("x-only public key serialization failed")
    return ffi.unpack(output, 32), parity[0]


def _keypair(prvkey: bytes | int) -> CData:
    """Create a keypair from a private key."""

    keypair = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair, scalar(prvkey, "private key")):
        raise ValueError("invalid private key")
    return keypair

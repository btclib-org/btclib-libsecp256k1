# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""X-only public keys and their tweaking.

According to BIP340-Schnorr and to the BIP341 taproot key path:
https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

An x-only public key is the 32-byte x coordinate of the point with even
y; the parity returned along a tweaked key is the one of the tweaked
point, to be committed to by the taproot output.

`from_pubkey` is the conversion from a full public key, and the only
function here taking one: everything else takes the 32-byte form, so
that discarding a y coordinate happens where the caller can see it and
not inside an argument check.
"""

from __future__ import annotations

from . import CData, ffi, lib
from ._scalar import octets, scalar
from .context import ctx


def from_pubkey(pubkey_bytes: bytes) -> tuple[bytes, int]:
    """Convert a public key into its x-only form and y parity.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.

    Returns:
        The 32-byte x coordinate, and the parity of y: 0 for even, 1 for
        odd. The parity is returned rather than dropped because the
        x-only key of an odd-y point is the key of its negation, which
        the caller may need to know.

    Raises:
        ValueError: if the public key is not a valid point.
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no valid key can make it do.
    """
    octets(pubkey_bytes, "public key")
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")
    return _to_xonly(pubkey)


def tweak_add(pubkey_bytes: bytes, tweak: bytes | int) -> tuple[bytes, int]:
    """Add the generator multiplied by the tweak to an x-only public key.

    This is the BIP341 taproot output key, given the internal key and
    the TapTweak hash.

    Args:
        pubkey_bytes: the 32-byte x-only internal key.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte tweaked x-only key, and the parity of its y: that
        parity is what a taproot output commits to, and what
        `tweak_add_check` is given back.

    Raises:
        ValueError: if the key is not 32 bytes or not a valid x
            coordinate, if the tweak is not 32 bytes or does not fit in
            them, or if the tweak or the resulting key is invalid.
        RuntimeError: if libsecp256k1 fails to convert or serialize the
            result, which no valid input can make it do.
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

    Args:
        tweaked_pubkey_bytes: the 32-byte x-only key to check.
        tweaked_parity: the parity of its y, 0 or 1, as `tweak_add`
            returned it.
        pubkey_bytes: the 32-byte x-only internal key.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        True if tweaking the internal key by that tweak gives that key
        and that parity.

    Raises:
        ValueError: if either key is not 32 bytes or not a valid x
            coordinate, if the parity is not 0 or 1, or if the tweak is
            not 32 bytes or does not fit in them.
    """
    octets(tweaked_pubkey_bytes, "tweaked x-only public key", 32)
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

    Args:
        prvkey: the internal private key, 32 bytes or an int below
            2**256.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte tweaked private key.

    Raises:
        ValueError: if either value is not 32 bytes or does not fit in
            them, if the private key is not in [1, n-1], or if the tweak
            or the resulting key is invalid.
        RuntimeError: if libsecp256k1 fails to extract the key, which no
            valid input can make it do.
    """
    keypair = _keypair(prvkey)
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_keypair_xonly_tweak_add(ctx, keypair, tweak_bytes):
        raise ValueError("invalid tweak or resulting private key")

    prvkey_buffer = ffi.new("char[32]")
    if not lib.secp256k1_keypair_sec(ctx, prvkey_buffer, keypair):
        raise RuntimeError("private key extraction failed")
    return ffi.unpack(prvkey_buffer, ffi.sizeof(prvkey_buffer))


def _parse(pubkey_bytes: bytes) -> CData:
    """Parse a 32-byte x-only public key.

    Args:
        pubkey_bytes: the 32-byte x coordinate.

    Returns:
        The libsecp256k1 x-only public key object.

    Raises:
        ValueError: if it is not 32 bytes, or not a valid x coordinate.
    """
    # secp256k1_xonly_pubkey_parse takes a bare pointer to 32 bytes
    octets(pubkey_bytes, "x-only public key", 32)

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pubkey, pubkey_bytes):
        raise ValueError("invalid x-only public key")
    return xonly_pubkey


def _to_xonly(pubkey: CData) -> tuple[bytes, int]:
    """Serialize a public key as its x-only form and y parity.

    Args:
        pubkey: the libsecp256k1 public key object.

    Returns:
        Its 32-byte x coordinate, and the parity of y.

    Raises:
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no valid key can make it do.
    """
    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    parity = ffi.new("int *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(ctx, xonly_pubkey, parity, pubkey):
        raise RuntimeError("x-only public key conversion failed")

    output = ffi.new("char[32]")
    if not lib.secp256k1_xonly_pubkey_serialize(ctx, output, xonly_pubkey):
        raise RuntimeError("x-only public key serialization failed")
    return ffi.unpack(output, ffi.sizeof(output)), parity[0]


def _keypair(prvkey: bytes | int) -> CData:
    """Create a keypair from a private key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The libsecp256k1 keypair object.

    Raises:
        ValueError: if the key is not 32 bytes, does not fit in them, or
            is not in [1, n-1].
    """
    keypair = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair, scalar(prvkey, "private key")):
        raise ValueError("invalid private key")
    return keypair

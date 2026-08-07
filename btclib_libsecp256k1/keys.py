# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Secp256k1 key and point algebra.

These are the libsecp256k1 secret and public key operations, i.e. the
scalar and point arithmetic underlying key derivation (BIP32) and key
aggregation; libsecp256k1 calls a private key a secret key, hence its
seckey function names.

Public keys are returned in compressed form, unless otherwise required.
"""

from __future__ import annotations

from collections.abc import Sequence

from . import CData, ffi, lib
from ._scalar import scalar
from .context import check, ctx

# SECP256K1_EC_COMPRESSED and SECP256K1_EC_UNCOMPRESSED: the
# libsecp256k1 flag macros do not survive the preprocessing of the
# headers into cffi definitions
COMPRESSED = 258
UNCOMPRESSED = 2


def prvkey_verify(prvkey: bytes | int) -> bool:
    """Return True if the private key is a valid scalar, i.e. in [1, n-1].

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        True if it is in [1, n-1]; False for zero and for anything at or
        above the group order, which is a verdict and not an error.

    Raises:
        ValueError: if it is not 32 bytes, or does not fit in them: that
            is a malformed argument rather than an invalid key.
    """
    prvkey_bytes = scalar(prvkey, "private key")
    return bool(lib.secp256k1_ec_seckey_verify(ctx, prvkey_bytes))


def prvkey_negate(prvkey: bytes | int) -> bytes:
    """Negate a private key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The 32 bytes of n - k, the key of the negated public key.

    Raises:
        ValueError: if it is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    if not lib.secp256k1_ec_seckey_negate(ctx, prvkey_buffer):
        raise ValueError("invalid private key")
    return ffi.unpack(prvkey_buffer, ffi.sizeof(prvkey_buffer))


def prvkey_tweak_add(prvkey: bytes | int, tweak: bytes | int) -> bytes:
    """Add a tweak to a private key.

    This is the private-key side of BIP32 derivation, and of any other
    scheme adding a scalar to a key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32 bytes of (k + t) mod n.

    Raises:
        ValueError: if either value is not 32 bytes or does not fit in
            them, if the private key is not in [1, n-1], or if the sum
            is zero, which is the one tweak with no valid result.
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_add(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return ffi.unpack(prvkey_buffer, ffi.sizeof(prvkey_buffer))


def prvkey_tweak_mul(prvkey: bytes | int, tweak: bytes | int) -> bytes:
    """Multiply a private key by a tweak.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32 bytes of (k * t) mod n.

    Raises:
        ValueError: if either value is not 32 bytes or does not fit in
            them, if the private key is not in [1, n-1], or if the tweak
            is zero or at or above the group order.
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_mul(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return ffi.unpack(prvkey_buffer, ffi.sizeof(prvkey_buffer))


def pubkey_from_prvkey(prvkey: bytes | int, compressed: bool = True) -> bytes:
    """Return the public key of a private key, i.e. the point kG.

    This is the generator multiplication of `mult.mult_`, with the
    serialization flag this module's other producers all take: `mult_`
    is its `compressed=False` case, and every private-to-public
    conversion that wants the compressed form -- BIP32 neutering, a
    fingerprint, an address -- is this call and nothing after it.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized point kG: 33 bytes whose first octet carries the
        parity of y, or the 65 bytes of 0x04 || x || y.

    Raises:
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the point,
            which no valid key can make it do.

    Example:
        >>> from btclib_libsecp256k1 import keys
        >>> keys.pubkey_from_prvkey(1).hex()[:10]
        '0279be667e'
    """
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(ctx, pubkey, scalar(prvkey, "private key")):
        raise ValueError("invalid private key: not in [1, n-1]")
    return serialize(pubkey, compressed)


def pubkey_negate(pubkey_bytes: bytes, compressed: bool = True) -> bytes:
    """Negate a public key.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The point with the same x and the other y, serialized.

    Raises:
        ValueError: if the public key is not a valid point.
        RuntimeError: if libsecp256k1 fails to negate or serialize it,
            which no valid key can make it do.
    """
    pubkey = parse(pubkey_bytes)
    if not lib.secp256k1_ec_pubkey_negate(ctx, pubkey):
        raise RuntimeError("public key negation failed")
    return serialize(pubkey, compressed)


def pubkey_tweak_add(
    pubkey_bytes: bytes, tweak: bytes | int, compressed: bool = True
) -> bytes:
    """Add the generator multiplied by the tweak to a public key.

    This is the public-key side of BIP32 derivation: the key of
    `prvkey_tweak_add(k, t)` is `pubkey_tweak_add(pubkey(k), t)`.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        tweak: the tweak, 32 bytes or an int below 2**256.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized point P + tG.

    Raises:
        ValueError: if the public key is not a valid point, if the tweak
            is not 32 bytes or does not fit in them, or if the tweak or
            the resulting key is invalid.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.
    """
    pubkey = parse(pubkey_bytes)
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak_bytes):
        raise ValueError("invalid tweak or resulting public key")
    return serialize(pubkey, compressed)


def pubkey_tweak_mul(
    pubkey_bytes: bytes, tweak: bytes | int, compressed: bool = True
) -> bytes:
    """Multiply a public key by a tweak.

    This is the multiplication of an arbitrary point, as opposed to the
    multiplication of the generator provided by the mult module. It is
    constant time, and is the shared point of an ECDH exchange: see
    `ecdh.shared_secret`, which hashes it.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        tweak: the scalar to multiply by, 32 bytes or an int below
            2**256.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized point tP.

    Raises:
        ValueError: if the public key is not a valid point, if the tweak
            is not 32 bytes or does not fit in them, or if it is zero or
            at or above the group order.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.
    """
    pubkey = parse(pubkey_bytes)
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak_bytes):
        raise ValueError("invalid tweak")
    return serialize(pubkey, compressed)


def pubkey_combine(pubkeys_bytes: Sequence[bytes], compressed: bool = True) -> bytes:
    """Add public keys together.

    Args:
        pubkeys_bytes: the public keys, each 33 or 65 bytes. At least
            one is required.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized sum of the points.

    Raises:
        ValueError: if the sequence is empty, if any key is not a valid
            point, or if the sum is the point at infinity, which has no
            serialization.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.
    """
    if not pubkeys_bytes:
        raise ValueError("at least one public key is required")

    pubkeys = [parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes]
    combined = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_combine(
        ctx, combined, ffi.new("secp256k1_pubkey *[]", pubkeys), len(pubkeys)
    ):
        raise ValueError("invalid public key sum")
    return serialize(combined, compressed)


def pubkey_cmp(pubkey1_bytes: bytes, pubkey2_bytes: bytes) -> int:
    """Compare two public keys, in lexicographic order of compressed form.

    The order is the one of the compressed serialization, whichever form
    the arguments are given in.

    Args:
        pubkey1_bytes: the first public key, 33 or 65 bytes.
        pubkey2_bytes: the second public key, 33 or 65 bytes.

    Returns:
        A negative number, zero, or a positive number, according to
        whether the first key sorts before, equal to, or after the
        second.

    Raises:
        ValueError: if either key is not a valid point.
    """
    return int(
        lib.secp256k1_ec_pubkey_cmp(ctx, parse(pubkey1_bytes), parse(pubkey2_bytes))
    )


def pubkey_sort(pubkeys_bytes: Sequence[bytes], compressed: bool = True) -> list[bytes]:
    """Sort public keys, in lexicographic order of compressed form.

    This is the ordering of a BIP67 multisig script, and the one MuSig2
    key aggregation applies when the participants have not agreed on a
    different one.

    Args:
        pubkeys_bytes: the public keys, each 33 or 65 bytes. An empty
            sequence sorts to an empty list.
        compressed: whether to return 33 bytes each rather than 65.

    Returns:
        The same keys, serialized, in ascending order.

    Raises:
        ValueError: if any key is not a valid point.
        RuntimeError: if libsecp256k1 fails to sort or serialize, which
            no valid input can make it do.
    """
    pubkeys = [parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes]
    # the array holds borrowed pointers, and is what gets reordered: the
    # list above is what keeps the keys it points to alive
    array = ffi.new("secp256k1_pubkey *[]", pubkeys)
    if not lib.secp256k1_ec_pubkey_sort(ctx, array, len(pubkeys)):
        raise RuntimeError("public key sorting failed")
    return [serialize(pubkey, compressed) for pubkey in array]


def parse(pubkey_bytes: bytes) -> CData:
    """Parse a public key into its internal libsecp256k1 representation.

    The internal form is what the raw `lib` calls take, and what
    `serialize` turns back into bytes: `serialize(parse(key))` is the
    compressed form of a key given in either form.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.

    Returns:
        The libsecp256k1 public key object.

    Raises:
        ValueError: if the bytes are not a valid point in either
            serialization.
    """
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")
    return pubkey


def serialize(pubkey: CData, compressed: bool = True) -> bytes:
    """Serialize an internal public key, in compressed form by default.

    Args:
        pubkey: the libsecp256k1 public key object, as `parse` returns.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The 33-byte compressed serialization, or the 65-byte
        uncompressed one.

    Raises:
        ValueError: if the object is not a public key libsecp256k1 will
            read -- a NULL pointer, or a `secp256k1_pubkey` nothing has
            written to. This is the one argument of these bindings that
            is a libsecp256k1 object rather than bytes, and so the one
            that cannot be checked before the call.
        RuntimeError: if libsecp256k1 fails for any other reason, which
            a key it produced cannot make it do.

    Example:
        >>> from btclib_libsecp256k1 import keys, mult
        >>> keys.serialize(keys.parse(mult.mult_(1))).hex()[:10]
        '0279be667e'
    """
    # the size is written once and the capacity derived from it. What is
    # unpacked is the buffer, not the length libsecp256k1 reports back:
    # this serialization has one length per flag, so a buffer of the
    # wrong size has to reach the caller to be caught -- reading the
    # reported length instead would quietly accept an oversized one,
    # which a mutation session measured directly (`size = 34` survived
    # that spelling, and dies in this one). The DER serialization is the
    # other case, and reads `length[0]` for the reason given there
    size = 33 if compressed else 65
    output = ffi.new(f"char[{size}]")
    length = ffi.new("size_t *", ffi.sizeof(output))
    flags = COMPRESSED if compressed else UNCOMPRESSED
    if not lib.secp256k1_ec_pubkey_serialize(ctx, output, length, pubkey, flags):
        # every other argument of these bindings is bytes, checked before
        # the call; this one is a libsecp256k1 object the caller holds, so
        # a violated precondition is reachable here and nowhere else.
        # check() is what turns it back into the message libsecp256k1
        # wrote -- and, raising it, takes it off the thread. Left there it
        # would be found by the next check(), which is the one a MuSig2
        # caller makes through `lib`, and blamed on a call that did not
        # produce it
        check()
        raise RuntimeError("point serialization failed")
    return ffi.unpack(output, ffi.sizeof(output))

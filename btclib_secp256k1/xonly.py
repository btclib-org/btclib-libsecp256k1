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

`from_pubkey` is the conversion from a full public key, and the only one
taking its bytes: every other entry point taking bytes takes the 32-byte
form, so that discarding a y coordinate happens where the caller can see
it and not inside an argument check. `from_pubkey_` and `tweak_add_` take
a full public key too, and are that same rule rather than an exception to
it -- a caller holding what `keys.parse` returns is holding the point,
and a call that takes it and answers 32 bytes drops the y in plain sight.
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, keys, lib
from ._scalar import octets, scalar
from ._secret import take, wipe
from .context import ctx


def _from_pubkey(pubkey: CData) -> tuple[CData, int]:
    """Convert a parsed public key into a parsed x-only key and the parity.

    The conversion itself, which is where the y is dropped, without the
    serialization that follows it in `from_pubkey_`: `tweak_add_` wants
    the object and not the 32 bytes, having a tweak to add to it.

    Args:
        pubkey: the already-parsed public key, as `keys.parse` returns.

    Returns:
        The libsecp256k1 x-only public key object, and the parity of the
        y that was dropped: 0 for even, 1 for odd.

    Raises:
        RuntimeError: if libsecp256k1 fails to convert it, which no valid
            key can make it do.
    """
    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    parity = ffi.new("int *")
    if not lib.secp256k1_xonly_pubkey_from_pubkey(ctx, xonly_pubkey, parity, pubkey):
        raise RuntimeError("x-only public key conversion failed")
    return xonly_pubkey, parity[0]


def _serialize(xonly_pubkey: CData) -> bytes:
    """Return the 32 bytes of a parsed x-only public key.

    Args:
        xonly_pubkey: the x-only public key object, as `parse` returns.

    Returns:
        The 32-byte x coordinate.

    Raises:
        RuntimeError: if libsecp256k1 fails to serialize it, which no
            valid key can make it do.
    """
    output = ffi.new("char[32]")
    if not lib.secp256k1_xonly_pubkey_serialize(ctx, output, xonly_pubkey):
        raise RuntimeError("x-only public key serialization failed")
    return ffi.unpack(output, ffi.sizeof(output))


def from_pubkey_(pubkey: CData) -> tuple[bytes, int]:
    """Convert an already-parsed public key into its x-only form and parity.

    The inner half of `from_pubkey`, for a caller who already holds the
    parsed point: see `keys.parse` for what the underscore means
    throughout.

    Args:
        pubkey: the already-parsed public key, as `keys.parse` returns.

    Returns:
        The 32-byte x coordinate, and the parity of y: 0 for even, 1 for
        odd.

    Raises:
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no valid key can make it do.
    """
    xonly_pubkey, parity = _from_pubkey(pubkey)
    return _serialize(xonly_pubkey), parity


def from_pubkey(pubkey_bytes: BytesLike) -> tuple[bytes, int]:
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
    return from_pubkey_(keys.parse(pubkey_bytes))


def tweak_add(pubkey_bytes: BytesLike, tweak: BytesLike | int) -> tuple[bytes, int]:
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
    return _tweak_add(parse(pubkey_bytes), tweak)


def tweak_add_(pubkey: CData, tweak: BytesLike | int) -> tuple[bytes, int]:
    """Add the generator multiplied by the tweak, to an already-parsed key.

    The inner half of `tweak_add`, for a caller who already holds the
    parsed point: see `keys.parse` for what the underscore means
    throughout. The parsed point is a full public key, and the x-only
    form of it is `secp256k1_xonly_pubkey_from_pubkey`, which lifts
    nothing; reaching `tweak_add` from there instead means serializing the
    x and parsing it back, and that parse is a field square root -- of an
    x whose y the caller is holding.

    The point is taken as BIP341 takes an internal key, x-only: an odd-y
    key is tweaked as its negation, and answers the output key
    `tweak_add` answers for the same 32 bytes. `from_pubkey_` is where
    that parity is read, and takes the same object.

    Args:
        pubkey: the already-parsed public key, as `keys.parse` returns.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte tweaked x-only key, and the parity of its y.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            or if the tweak or the resulting key is invalid.
        RuntimeError: if libsecp256k1 fails to convert or serialize the
            result, which no valid input can make it do.
    """
    return _tweak_add(_from_pubkey(pubkey)[0], tweak)


def _tweak_add(internal_pubkey: CData, tweak: BytesLike | int) -> tuple[bytes, int]:
    """Add the generator multiplied by the tweak to a parsed x-only key.

    What the two halves above share, once each has reached the x-only key
    its own way: `parse` from the 32 bytes, or `_from_pubkey` from the
    point.

    Args:
        internal_pubkey: the x-only public key object.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte tweaked x-only key, and the parity of its y.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            or if the tweak or the resulting key is invalid.
        RuntimeError: if libsecp256k1 fails to convert or serialize the
            result, which no valid input can make it do.
    """
    tweak_bytes = scalar(tweak, "tweak")

    tweaked_pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_xonly_pubkey_tweak_add(
        ctx, tweaked_pubkey, internal_pubkey, tweak_bytes
    ):
        raise ValueError("invalid tweak or resulting public key")
    return from_pubkey_(tweaked_pubkey)


def tweak_add_check(
    tweaked_pubkey_bytes: BytesLike,
    tweaked_parity: int,
    pubkey_bytes: BytesLike,
    tweak: BytesLike | int,
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
        and that parity. 32 bytes which are the x coordinate of no point
        at all are one of the ways of being False: this compares the
        serialization rather than parsing it, which is where the saving
        over recomputing the tweak comes from.

    Raises:
        ValueError: if either key is not 32 bytes, if the internal key
            is not a valid x coordinate, if the parity is not 0 or 1, or
            if the tweak is not 32 bytes or does not fit in them. The
            tweaked key is not parsed, and so is never invalid: see
            Returns.
    """
    tweaked_pubkey_bytes = octets(tweaked_pubkey_bytes, "tweaked x-only public key", 32)
    if tweaked_parity not in (0, 1):
        raise ValueError("the parity must be 0 or 1")

    internal_pubkey = parse(pubkey_bytes)
    tweak_bytes = scalar(tweak, "tweak")

    return bool(
        lib.secp256k1_xonly_pubkey_tweak_add_check(
            ctx, tweaked_pubkey_bytes, tweaked_parity, internal_pubkey, tweak_bytes
        )
    )


def prvkey_tweak_add(prvkey: BytesLike | int, tweak: BytesLike | int) -> bytes:
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
    prvkey_buffer = ffi.new("char[32]")
    try:
        tweak_bytes = scalar(tweak, "tweak")
        if not lib.secp256k1_keypair_xonly_tweak_add(ctx, keypair, tweak_bytes):
            raise ValueError("invalid tweak or resulting private key")

        if not lib.secp256k1_keypair_sec(ctx, prvkey_buffer, keypair):
            raise RuntimeError("private key extraction failed")
        return take(prvkey_buffer)
    finally:
        # a keypair carries the private key -- the tweaked one here,
        # which is the one that signs -- so it is overwritten on the way
        # out whether that was reached or refused
        wipe(keypair)


def parse(pubkey_bytes: BytesLike) -> CData:
    """Parse a 32-byte x-only public key.

    The x-only counterpart of `keys.parse`, and the argument of
    `ssa.verify_`: a caller that has proved 32 bytes to be the x
    coordinate of a point has made the call BIP340 verification makes
    anyway, and can hand the result on rather than make it twice.

    There is no `serialize` beside it, and that is not an omission:
    nothing here hands back a parsed x-only key except this, `from_pubkey`
    and `tweak_add` answering with the 32 bytes and the parity instead.

    Args:
        pubkey_bytes: the 32-byte x coordinate.

    Returns:
        The libsecp256k1 x-only public key object.

    Raises:
        ValueError: if it is not 32 bytes, or not a valid x coordinate.
    """
    # secp256k1_xonly_pubkey_parse takes a bare pointer to 32 bytes
    pubkey_bytes = octets(pubkey_bytes, "x-only public key", 32)

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pubkey, pubkey_bytes):
        raise ValueError("invalid x-only public key")
    return xonly_pubkey


def _keypair(prvkey: BytesLike | int) -> CData:
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

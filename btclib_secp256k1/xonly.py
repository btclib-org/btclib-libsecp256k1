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

**A public key here is an x coordinate, and `02 || x`, `03 || x` and
`04 || x || y` all name it.** Every entry point taking a key takes any of
the three, and none of them consults the y: `lift_x` is the even-y point
whatever serialization the x arrived in, and a signer whose key is the
odd-y one signs with `n - d` for exactly that reason. So the parity is a
property of the serialization and not of the key, and there is no
discarding for an argument check to make visible -- `from_pubkey` returns
it because a caller converting a key it holds may want to know which of
the two forms it was handed, not because the two are different keys.

Which serialization to hand in is a question of cost and not of meaning:
`keys.parse` reads the uncompressed form for 0.256 us, both coordinates
being there, where the compressed form and the 32-byte one are a field
square root at 2.343.
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, keys, lib
from ._scalar import octets, scalar
from ._secret import take, wipe
from .context import check, ctx

# the x-only serialization, which is the whole of the key: the other
# two lengths this module takes are a full public key, whose x it is
_XONLY_SIZE = 32


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
        pubkey_bytes: the public key, 32, 33 or 65 bytes.

    Returns:
        The 32-byte x coordinate, and the parity of the y it was handed:
        0 for even, 1 for odd, and 0 for a key that arrived x-only, an
        x naming the even-y point. The parity is answered rather than
        dropped because a caller may want to know which serialization it
        held, not because the two are different keys.

    Raises:
        ValueError: if the public key is not a valid point, or is not 32,
            33 or 65 bytes.
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no valid key can make it do.
    """
    pubkey_bytes = octets(pubkey_bytes, "public key")
    if len(pubkey_bytes) == _XONLY_SIZE:
        # already the x, and the conversion is the proof that it is one
        return _serialize(parse(pubkey_bytes)), 0
    return from_pubkey_(keys.parse(pubkey_bytes))


def from_prvkey(prvkey: BytesLike | int) -> tuple[bytes, int]:
    """Return the x-only public key of a private key, and the y parity.

    The BIP340 and BIP341 form of `keys.pubkey_from_prvkey`, and the one
    to reach for when the 32 bytes are what is wanted: it is that call
    and `from_pubkey` with neither the serialization nor the parse
    between them, the point going straight from the multiplication into
    the conversion that drops its y.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte x coordinate of kG, and the parity of its y: 0 for
        even, 1 for odd. That parity is what BIP340 signing negates the
        key for, so a signer wanting only the key it signs under can
        ignore it.

    Raises:
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to convert or serialize the
            point, which no valid key can make it do.

    Example:
        >>> from btclib_secp256k1 import keys, xonly
        >>> pubkey = keys.pubkey_from_prvkey(1)
        >>> xonly.from_prvkey(1) == xonly.from_pubkey(pubkey)
        True
    """
    return from_pubkey_(keys.pubkey_from_prvkey_(prvkey))


def from_keypair(keypair: CData) -> tuple[bytes, int]:
    """Return the x-only public key of a keypair, and the y parity.

    The keypair already holds the point, so this is a read of it rather
    than a multiplication: `ssa.Signer.pubkey` is this call on the
    keypair a signer holds, and a MuSig2 session driven through `lib`
    holds another. `from_prvkey` is the same answer for a caller holding
    the private key and no keypair.

    Args:
        keypair: the libsecp256k1 keypair object, as `ssa.Signer` holds
            and as `secp256k1_keypair_create` writes.

    Returns:
        The 32-byte x coordinate, and the parity of y: 0 for even, 1 for
        odd. The parity is of the point the private key gives, the
        keypair being the negated key where that y is odd.

    Raises:
        ValueError: if the object is not a keypair libsecp256k1 will read
            -- a NULL pointer, or one that has been wiped. This and
            `keys.serialize` are the two arguments of these bindings that
            are libsecp256k1 objects rather than bytes, and so the two
            that cannot be checked before the call.
        RuntimeError: if libsecp256k1 fails for any other reason, or
            fails to serialize the result, which a keypair it built
            cannot make it do.
    """
    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    parity = ffi.new("int *")
    if not lib.secp256k1_keypair_xonly_pub(ctx, xonly_pubkey, parity, keypair):
        # the keypair is the caller's object, so a violated precondition
        # is reachable here as it is in `keys.serialize`, which says why
        # raising it is also what takes it off the thread. A wiped
        # keypair is the reachable way in, and what it is reported as is
        # the zero it holds where the x of a point should be
        check()
        raise RuntimeError("x-only public key conversion failed")
    return _serialize(xonly_pubkey), parity[0]


def tweak_add(pubkey_bytes: BytesLike, tweak: BytesLike | int) -> tuple[bytes, int]:
    """Add the generator multiplied by the tweak to an x-only public key.

    This is the BIP341 taproot output key, given the internal key and
    the TapTweak hash.

    Args:
        pubkey_bytes: the internal key, 32, 33 or 65 bytes. The
            uncompressed form is the cheap one to hand in: see `parse`.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The 32-byte tweaked x-only key, and the parity of its y: that
        parity is what a taproot output commits to, and what
        `tweak_add_check` is given back.

    Raises:
        ValueError: if the key is not a valid point, or is not 32, 33 or
            65 bytes, if the tweak is not 32 bytes or does not fit in
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
        pubkey_bytes: the internal key, 32, 33 or 65 bytes.
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
    """Parse a public key, in any of its serializations, into its x.

    The x-only counterpart of `keys.parse`, and the argument of
    `ssa.verify_`: a caller that has proved octets a public key has made
    the call BIP340 verification makes anyway, and can hand the result on
    rather than make it twice.

    Every entry point of this module that takes a public key reaches it,
    which is what makes them all take any of the three serializations.
    Which one costs what: the 32-byte form is `secp256k1_xonly_pubkey_parse`,
    a field square root at 2.343 us, and so is the compressed form; the
    uncompressed form is 0.256, both coordinates being there to read, and
    the x-only conversion that follows it reads the y rather than lifting
    one.

    There is no `serialize` beside it, and that is not an omission:
    nothing here hands back a parsed x-only key except this, `from_pubkey`
    and `tweak_add` answering with the 32 bytes and the parity instead.

    Args:
        pubkey_bytes: the public key, 32, 33 or 65 bytes.

    Returns:
        The libsecp256k1 x-only public key object.

    Raises:
        ValueError: if it is not a valid point, or is not 32, 33 or 65
            bytes.
    """
    # secp256k1_xonly_pubkey_parse takes a bare pointer to 32 bytes
    pubkey_bytes = octets(pubkey_bytes, "public key")
    if len(pubkey_bytes) != _XONLY_SIZE:
        return _from_pubkey(keys.parse(pubkey_bytes))[0]

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

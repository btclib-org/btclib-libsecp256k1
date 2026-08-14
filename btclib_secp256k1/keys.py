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

from . import BytesLike, CData, ffi, lib
from ._scalar import octets, scalar
from ._secret import take
from .context import check, ctx

# SECP256K1_EC_COMPRESSED and SECP256K1_EC_UNCOMPRESSED: the
# libsecp256k1 flag macros do not survive the preprocessing of the
# headers into cffi definitions
COMPRESSED = 258
UNCOMPRESSED = 2


def prvkey_verify(prvkey: BytesLike | int) -> bool:
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


def prvkey_negate(prvkey: BytesLike | int) -> bytes:
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
    return take(prvkey_buffer)


def prvkey_tweak_add(prvkey: BytesLike | int, tweak: BytesLike | int) -> bytes:
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
    return take(prvkey_buffer)


def prvkey_tweak_mul(prvkey: BytesLike | int, tweak: BytesLike | int) -> bytes:
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
    return take(prvkey_buffer)


def pubkey_from_prvkey(prvkey: BytesLike | int, compressed: bool = True) -> bytes:
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
        >>> from btclib_secp256k1 import keys
        >>> keys.pubkey_from_prvkey(1).hex()[:10]
        '0279be667e'
    """
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(ctx, pubkey, scalar(prvkey, "private key")):
        raise ValueError("invalid private key: not in [1, n-1]")
    return serialize(pubkey, compressed)


def pubkey_negate_(pubkey: CData) -> CData:
    """Negate an already-parsed public key.

    The inner half of `pubkey_negate`, for a caller who already holds the
    parsed point: see `parse` for what the underscore means throughout.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.

    Returns:
        The same object passed in, negated.

    Raises:
        RuntimeError: if libsecp256k1 fails to negate it, which no valid
            key can make it do.
    """
    if not lib.secp256k1_ec_pubkey_negate(ctx, pubkey):
        raise RuntimeError("public key negation failed")
    return pubkey


def pubkey_negate(pubkey_bytes: BytesLike, compressed: bool = True) -> bytes:
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
    return serialize(pubkey_negate_(parse(pubkey_bytes)), compressed)


def pubkey_tweak_add_(pubkey: CData, tweak: BytesLike | int) -> CData:
    """Add the generator multiplied by the tweak, to an already-parsed key.

    The inner half of `pubkey_tweak_add`, for a caller who already holds
    the parsed point and so has no parse left to redo: `PubkeyTweakChain`
    is the one, walking a BIP32 path one tweak at a time without parsing
    the point back out of its own serialization at every step. See
    `parse` for what the underscore means throughout.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The same object passed in, tweaked.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            or if the tweak or the resulting public key is invalid.
    """
    if not lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, scalar(tweak, "tweak")):
        raise ValueError("invalid tweak or resulting public key")
    return pubkey


def pubkey_tweak_add(
    pubkey_bytes: BytesLike, tweak: BytesLike | int, compressed: bool = True
) -> bytes:
    """Add the generator multiplied by the tweak to a public key.

    This is the public-key side of BIP32 derivation: the key of
    `prvkey_tweak_add(k, t)` is `pubkey_tweak_add(pubkey(k), t)`. Adding
    more than one tweak to the same key is `PubkeyTweakChain`, which
    parses the key once rather than once per tweak.

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
    return serialize(pubkey_tweak_add_(parse(pubkey_bytes), tweak), compressed)


class PubkeyTweakChain:
    """Add a sequence of tweaks to a public key, parsing it only once.

    `pubkey_tweak_add` parses its argument and serializes its result, so
    a caller adding tweak after tweak to its own output -- a BIP32 path
    walked one index at a time, each needing the previous step's
    serialized key to hash into the next tweak -- re-parses at every step
    the very point the step before had already built, and only
    serialized because *that* step's caller needed the bytes. This holds
    the parsed point across the calls instead: the first tweak is the
    only one that pays for a parse, and every step still returns the
    bytes its caller needs.

    Args:
        pubkey_bytes: the public key the chain starts from, 33 or 65
            bytes.

    Raises:
        ValueError: if the public key is not a valid point.

    Example:
        >>> from btclib_secp256k1 import keys, mult
        >>> generator = mult.mult_(1)
        >>> chain = keys.PubkeyTweakChain(generator)
        >>> step1 = chain.tweak_add(2)
        >>> step2 = chain.tweak_add(3)
        >>> step1 == keys.pubkey_tweak_add(generator, 2)
        True
        >>> step2 == keys.pubkey_tweak_add(step1, 3)
        True
    """

    # pydoclint (DOC301) asks that this carry no docstring of its own,
    # the class docstring above being where the constructor is documented
    def __init__(self, pubkey_bytes: BytesLike) -> None:  # noqa: D107
        self._pubkey = parse(pubkey_bytes)

    def tweak_add(self, tweak: BytesLike | int, compressed: bool = True) -> bytes:
        """Add the generator multiplied by the tweak, to the held key.

        Args:
            tweak: the tweak, 32 bytes or an int below 2**256.
            compressed: whether to return 33 bytes rather than 65.

        Returns:
            The serialized point, with this tweak and every earlier one
            already added.

        Raises:
            ValueError: if the tweak is not 32 bytes or does not fit in
                them, or if the tweak or the resulting key is invalid.
            RuntimeError: if libsecp256k1 fails to serialize the result,
                which no valid input can make it do.
        """
        return serialize(pubkey_tweak_add_(self._pubkey, tweak), compressed)


def pubkey_tweak_mul_(pubkey: CData, tweak: BytesLike | int) -> CData:
    """Multiply an already-parsed public key by a tweak.

    The inner half of `pubkey_tweak_mul`, for a caller who already holds
    the parsed point: see `parse` for what the underscore means
    throughout. This is the shared point of an ECDH exchange, and
    `ecdh.shared_secret_` is the hash of it from the same parsed key.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.
        tweak: the scalar to multiply by, 32 bytes or an int below
            2**256.

    Returns:
        The same object passed in, multiplied.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            or if it is zero or at or above the group order.
    """
    if not lib.secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, scalar(tweak, "tweak")):
        raise ValueError("invalid tweak")
    return pubkey


def pubkey_tweak_mul(
    pubkey_bytes: BytesLike, tweak: BytesLike | int, compressed: bool = True
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
    return serialize(pubkey_tweak_mul_(parse(pubkey_bytes), tweak), compressed)


def pubkey_combine(
    pubkeys_bytes: Sequence[BytesLike], compressed: bool = True
) -> bytes:
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


def pubkey_cmp_(pubkey1: CData, pubkey2: CData) -> int:
    """Compare two already-parsed public keys, in compressed-form order.

    The inner half of `pubkey_cmp`, for a caller who already holds both
    parsed points -- sorting keys it has parsed for another reason, where
    every comparison of a sort would otherwise parse both of its
    arguments again. See `parse` for what the underscore means
    throughout.

    Args:
        pubkey1: the first already-parsed public key, as `parse` returns.
        pubkey2: the second one.

    Returns:
        A negative number, zero, or a positive number, according to
        whether the first key sorts before, equal to, or after the
        second.
    """
    return int(lib.secp256k1_ec_pubkey_cmp(ctx, pubkey1, pubkey2))


def pubkey_cmp(pubkey1_bytes: BytesLike, pubkey2_bytes: BytesLike) -> int:
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
    return pubkey_cmp_(parse(pubkey1_bytes), parse(pubkey2_bytes))


def pubkey_sort(
    pubkeys_bytes: Sequence[BytesLike], compressed: bool = True
) -> list[bytes]:
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


def parse(pubkey_bytes: BytesLike) -> CData:
    """Parse a public key into its internal libsecp256k1 representation.

    The internal form is what the raw `lib` calls take, and what
    `serialize` turns back into bytes: `serialize(parse(key))` is the
    compressed form of a key given in either form.

    It is also what a trailing underscore means across these bindings.
    Every wrapper whose first act is to parse a public key has an inner
    half spelled with one -- `pubkey_tweak_add_` here, `dsa.verify_`
    elsewhere -- taking the object this returns in place of the bytes,
    and the outer half is that inner half with a `parse` in front of it,
    which is the equality `tests/test_parsed_keys.py` holds every pair
    to. For a compressed key that parse is a field square root, so a
    caller who has already paid for one -- having validated the key, or
    being about to use the same key again -- can hand it on rather than
    buy it twice. Nothing else about the two halves differs: the
    remaining arguments are checked exactly as the outer half checks
    them, a bare pointer's length being what no C return code can report.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.

    Returns:
        The libsecp256k1 public key object.

    Raises:
        ValueError: if the bytes are not a valid point in either
            serialization.
    """
    pubkey_bytes = octets(pubkey_bytes, "public key")
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
        >>> from btclib_secp256k1 import keys, mult
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

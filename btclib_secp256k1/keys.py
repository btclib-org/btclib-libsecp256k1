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
from typing import overload

from . import BytesLike, CData, MutableBytesLike, ffi, lib
from ._cdata import array
from ._scalar import octets, scalar
from ._secret import take
from .context import ctx

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


def pubkey_verify(pubkey_bytes: BytesLike) -> bool:
    """Return True if the octets are a public key libsecp256k1 accepts.

    The public-key twin of `prvkey_verify`, and the call for a library
    validating a key at its own boundary: `secp256k1_ec_pubkey_parse` is
    the proof, and this is that proof with nothing kept. `parse` hands
    back an object whose lifetime becomes the caller's, and `reserialize`
    hands back octets it already had -- 0.37 us of serialization for an
    answer that was in the argument.

    A verdict and not an exception, as `prvkey_verify` is: what the octets
    are wrong about is the caller's to phrase, and a library validating an
    input has its own word for it.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.

    Returns:
        True if it is a point of the curve in either serialization; False
        for octets of any other length too, which is a verdict here where
        every other entry point taking a key raises: there is nothing to
        do with such a key either way, and a caller asking whether it has
        one has asked about the length as well.

    Raises:
        TypeError: if the value is not bytes at all, which is a malformed
            argument and not a key to have a verdict on.
    """
    return _parsed(pubkey_bytes, "public key") is not None


@overload
def prvkey_negate(prvkey: BytesLike | int) -> bytes: ...
@overload
def prvkey_negate(prvkey: BytesLike | int, *, into: MutableBytesLike) -> None: ...
@overload
def prvkey_negate(
    prvkey: BytesLike | int, *, into: MutableBytesLike | None
) -> bytes | None: ...
def prvkey_negate(
    prvkey: BytesLike | int, *, into: MutableBytesLike | None = None
) -> bytes | None:
    """Negate a private key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32 bytes of n - k, the key of the negated public key -- or
        None where `into` was given and holds them.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if it is not 32 bytes, does not fit in them, or is
            not in [1, n-1]; or if `into` is not 32 bytes.
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    if not lib.secp256k1_ec_seckey_negate(ctx, prvkey_buffer):
        raise ValueError("invalid private key: not in [1, n-1]")
    return take(prvkey_buffer, into=into)


@overload
def prvkey_tweak_add(prvkey: BytesLike | int, tweak: BytesLike | int) -> bytes: ...
@overload
def prvkey_tweak_add(
    prvkey: BytesLike | int, tweak: BytesLike | int, *, into: MutableBytesLike
) -> None: ...
@overload
def prvkey_tweak_add(
    prvkey: BytesLike | int, tweak: BytesLike | int, *, into: MutableBytesLike | None
) -> bytes | None: ...
def prvkey_tweak_add(
    prvkey: BytesLike | int,
    tweak: BytesLike | int,
    *,
    into: MutableBytesLike | None = None,
) -> bytes | None:
    """Add a tweak to a private key.

    This is the private-key side of BIP32 derivation, and of any other
    scheme adding a scalar to a key. `xonly.prvkey_tweak_add` is the
    BIP341 one, which negates the key first where its point has odd y.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        tweak: the tweak, 32 bytes or an int below 2**256.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32 bytes of (k + t) mod n -- or None where `into` was given
        and holds them.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if either value is not 32 bytes or does not fit in
            them, if the private key is not in [1, n-1], if the sum
            is zero, which is the one tweak with no valid result, or if
            `into` is not 32 bytes.
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_add(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return take(prvkey_buffer, into=into)


@overload
def prvkey_tweak_mul(prvkey: BytesLike | int, tweak: BytesLike | int) -> bytes: ...
@overload
def prvkey_tweak_mul(
    prvkey: BytesLike | int, tweak: BytesLike | int, *, into: MutableBytesLike
) -> None: ...
@overload
def prvkey_tweak_mul(
    prvkey: BytesLike | int, tweak: BytesLike | int, *, into: MutableBytesLike | None
) -> bytes | None: ...
def prvkey_tweak_mul(
    prvkey: BytesLike | int,
    tweak: BytesLike | int,
    *,
    into: MutableBytesLike | None = None,
) -> bytes | None:
    """Multiply a private key by a tweak.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        tweak: the tweak, 32 bytes or an int below 2**256.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32 bytes of (k * t) mod n -- or None where `into` was given
        and holds them.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if either value is not 32 bytes or does not fit in
            them, if the private key is not in [1, n-1], if the tweak
            is zero or at or above the group order, or if `into` is not
            32 bytes.
    """
    prvkey_buffer = ffi.new("char[32]", scalar(prvkey, "private key"))
    tweak_bytes = scalar(tweak, "tweak")
    if not lib.secp256k1_ec_seckey_tweak_mul(ctx, prvkey_buffer, tweak_bytes):
        raise ValueError("invalid private key or tweak")
    return take(prvkey_buffer, into=into)


def _pubkey_from_prvkey_(prvkey: BytesLike | int) -> CData:
    """Return the public key of a private key, as the parsed point.

    The private half of `pubkey_from_prvkey`, for a caller who is about
    to hand the point to another wrapper rather than to hold its bytes:
    `xonly.from_prvkey` is the one this package makes. See the package
    docstring for what the two underscores mean throughout.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The libsecp256k1 public key object of the point kG.

    Raises:
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1].
    """
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(ctx, pubkey, scalar(prvkey, "private key")):
        raise ValueError("invalid private key: not in [1, n-1]")
    return pubkey


def pubkey_from_prvkey(prvkey: BytesLike | int, compressed: bool = True) -> bytes:
    """Return the public key of a private key, i.e. the point kG.

    This is the generator multiplication, with the serialization flag
    this module's other producers all take: `compressed=False` answers
    the 65 octets of `0x04 || x || y`, which is the form a caller reading
    coordinates wants and the cheap one to parse back. Every
    private-to-public conversion that wants the compressed form -- BIP32
    neutering, a fingerprint, an address -- is this call and nothing
    after it.

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
    return serialize(_pubkey_from_prvkey_(prvkey), compressed)


def _pubkey_negate_(pubkey: CData) -> CData:
    """Negate an already-parsed public key.

    The private half of `pubkey_negate`, for a caller who already holds
    the parsed point: see the package docstring for what the two
    underscores mean throughout.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.

    Returns:
        The same object passed in, negated.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- a NULL
            pointer, or a `secp256k1_pubkey` nothing has written to --
            or fails for any other reason, which a key it produced
            cannot make it do. Which of the two it was is on the thread
            rather than in the message, and `context.check` is what
            reads it.
    """
    negated = lib.secp256k1_ec_pubkey_negate(ctx, pubkey)
    if not negated:
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
    return serialize(_pubkey_negate_(parse(pubkey_bytes)), compressed)


def _pubkey_tweak_add_(pubkey: CData, tweak: BytesLike | int) -> CData:
    """Add the generator multiplied by the tweak, to an already-parsed key.

    The private half of `pubkey_tweak_add`, for a caller who already
    holds the parsed point and so has no parse left to redo:
    `PubkeyTweakChain` is the one, walking a BIP32 path one tweak at a
    time without parsing the point back out of its own serialization at
    every step. See the package docstring for what the two underscores
    mean throughout.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.
        tweak: the tweak, 32 bytes or an int below 2**256.

    Returns:
        The same object passed in, tweaked.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            if the tweak or the resulting public key is invalid, or if
            the object is not a public key libsecp256k1 will read, those
            last two being one message here -- `context.check` is what
            tells them apart.
    """
    tweak_bytes = scalar(tweak, "tweak")
    tweaked = lib.secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak_bytes)
    if not tweaked:
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
    return serialize(_pubkey_tweak_add_(parse(pubkey_bytes), tweak), compressed)


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

    `pubkey` is that point without a tweak added, for a caller that has
    reached the end of the path and wants the key it arrived at, or that
    wants the key it started from in the other serialization.

    Args:
        pubkey_bytes: the public key the chain starts from, 33 or 65
            bytes.

    Raises:
        ValueError: if the public key is not a valid point.

    Example:
        >>> from btclib_secp256k1 import keys
        >>> generator = keys.pubkey_from_prvkey(1, compressed=False)
        >>> chain = keys.PubkeyTweakChain(generator)
        >>> step1 = chain.tweak_add(2)
        >>> step2 = chain.tweak_add(3)
        >>> step1 == keys.pubkey_tweak_add(generator, 2)
        True
        >>> step2 == keys.pubkey_tweak_add(step1, 3)
        True
        >>> chain.pubkey() == step2
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
                them, or if the tweak or the resulting key is invalid --
                which ends the chain. libsecp256k1 says of
                `secp256k1_ec_pubkey_tweak_add` that "pubkey will be set
                to an invalid value if this function returns 0", and the
                point this holds is that pubkey: there is nothing left
                to step from, so a caller catching this builds a chain
                afresh rather than asking again.
            RuntimeError: if libsecp256k1 fails to serialize the result,
                which no valid input can make it do.
        """
        return serialize(_pubkey_tweak_add_(self._pubkey, tweak), compressed)

    def pubkey(self, compressed: bool = True) -> bytes:
        """Return the key the chain holds, with no tweak added.

        Returns:
            The serialized point, with every tweak added so far. Before
            the first `tweak_add` that is the key the chain was built
            from, which is how this doubles as the `reserialize` of it.

        Args:
            compressed: whether to return 33 bytes rather than 65.

        Raises:
            RuntimeError: if libsecp256k1 fails to serialize it, which
                no valid input can make it do.
        """
        return serialize(self._pubkey, compressed)

    def _pubkey_(self) -> CData:
        """Return the parsed point the chain holds.

        What `pubkey` answers in octets, for a caller handing the point
        to a private half rather than holding its bytes -- the end of a
        BIP32 path that is about to be tweaked into a taproot output
        key, `xonly._tweak_add_` being where that goes.

        Returns:
            The libsecp256k1 public key object, which is the chain's own
            and which the next `tweak_add` mutates.
        """
        return self._pubkey


def _pubkey_tweak_mul_(pubkey: CData, tweak: BytesLike | int) -> CData:
    """Multiply an already-parsed public key by a tweak.

    The private half of `pubkey_tweak_mul`, for a caller who already
    holds the parsed point: see the package docstring for what the two
    underscores mean throughout. This is the shared point of an ECDH
    exchange, and `ecdh._shared_secret_` is the hash of it from the same
    parsed key.

    Args:
        pubkey: the already-parsed public key, as `parse` returns.
            Mutated in place.
        tweak: the scalar to multiply by, 32 bytes or an int below
            2**256.

    Returns:
        The same object passed in, multiplied.

    Raises:
        ValueError: if the tweak is not 32 bytes or does not fit in them,
            if it is zero or at or above the group order, or if the
            object is not a public key libsecp256k1 will read, those
            last two being one message here -- `context.check` is what
            tells them apart.
    """
    tweak_bytes = scalar(tweak, "tweak")
    multiplied = lib.secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak_bytes)
    if not multiplied:
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
    return serialize(_pubkey_tweak_mul_(parse(pubkey_bytes), tweak), compressed)


def _pubkey_combine_(pubkeys: Sequence[CData]) -> CData:
    """Add already-parsed public keys together.

    The private half of `pubkey_combine`, and the one that answers with
    the sum rather than with its serialization: see the package
    docstring for what the two underscores mean throughout.
    `_pubkey_sort_` is what hands the keys over in the order BIP67 and
    MuSig2 ask for, and the two together are an aggregation that parses
    each key once and serializes once, where the public halves serialize
    every sorted key only to parse it back.

    Args:
        pubkeys: the already-parsed public keys, as `parse` returns. At
            least one is required.

    Returns:
        The libsecp256k1 public key object of the sum.

    Raises:
        ValueError: if the sequence is empty, if the sum is the point at
            infinity, which is no public key, or if any object is not a
            public key libsecp256k1 will read. The last two are one
            message, for the reason `_pubkey_sum_` gives.
    """
    combined = _pubkey_sum_(pubkeys)
    if combined is None:
        raise ValueError("invalid public key sum")
    return combined


def _pubkey_sum_(pubkeys: Sequence[CData]) -> CData | None:
    """Add already-parsed public keys together, infinity included.

    The private half of `pubkey_sum`, and what `_pubkey_combine_` is
    built on: see the package docstring for what the two underscores
    mean throughout.

    Args:
        pubkeys: the already-parsed public keys, as `parse` returns. At
            least one is required.

    Returns:
        The libsecp256k1 public key object of the sum, or None where that
        sum is the point at infinity -- and None, too, where libsecp256k1
        could not read one of the objects, the two being one answer here.
        `context.check` immediately after the call is what separates
        them: a key it refused is on the thread, and an infinity is not.
        No caller reaching this through `pubkey_sum` or `pubkey_combine`
        has the question, those parsing the octets they are given, so
        what the conflation costs is paid only by a caller passing
        objects of its own.

    Raises:
        ValueError: if the sequence is empty.
    """
    pubkeys = list(pubkeys)
    if not pubkeys:
        raise ValueError("at least one public key is required")

    combined = ffi.new("secp256k1_pubkey *")
    # libsecp256k1 answers 0 both for a key it cannot read and for a sum
    # that is the point at infinity, and reports the first through the
    # illegal callback rather than in the return value: what tells the
    # two apart is on the thread, which is what the Returns section
    # above sends a caller to `context.check` for
    summed = lib.secp256k1_ec_pubkey_combine(
        ctx, combined, array("secp256k1_pubkey *[]", pubkeys), len(pubkeys)
    )
    return combined if summed else None


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
    return serialize(
        _pubkey_combine_([parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes]),
        compressed,
    )


def pubkey_sum(
    pubkeys_bytes: Sequence[BytesLike], compressed: bool = True
) -> bytes | None:
    """Add public keys together, answering None for the point at infinity.

    `pubkey_combine` with the one sum that is no public key answered
    rather than refused. A caller doing arithmetic has that sum as a
    value -- `P + (-P)` is the identity and not a malformed argument --
    and the two spellings are the same call. There is no key here that
    libsecp256k1 could fail to read, `parse` below having proved every
    one of them, so the None this answers is the infinity and nothing
    else; `_pubkey_sum_` is where that is not true and says so.

    The infinity has no serialization, which is why it is None and not
    octets: a `secp256k1_pubkey` is a point of the curve and never the
    identity, so there is nothing for this to hand back.

    Args:
        pubkeys_bytes: the public keys, each 33 or 65 bytes. At least
            one is required.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized sum of the points, or None where they sum to the
        point at infinity.

    Raises:
        ValueError: if the sequence is empty, or if any key is not a
            valid point.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.

    Example:
        >>> from btclib_secp256k1 import keys
        >>> pubkey = keys.pubkey_from_prvkey(7)
        >>> keys.pubkey_sum([pubkey, keys.pubkey_negate(pubkey)]) is None
        True
        >>> keys.pubkey_sum([pubkey]) == pubkey
        True
    """
    summed = _pubkey_sum_([parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes])
    return None if summed is None else serialize(summed, compressed)


def pubkey_tweak_mul_sum(
    pubkeys_bytes: Sequence[BytesLike],
    tweaks: Sequence[BytesLike | int],
    compressed: bool = True,
) -> bytes | None:
    """Multiply each public key by its tweak and add the products.

    The two names it is spelled with, in that order: a
    `pubkey_tweak_mul` per pair and one `pubkey_sum` over the products.
    That is the multi-scalar multiplication a caller writes as a
    verification equation -- u*H + v*Q of ECDSA and BIP340, MuSig2's
    aggregate of a key per signer, BIP352's tweak data -- and the whole
    of what it adds is that no product is serialized: written with the
    public halves, each `pubkey_tweak_mul` serializes 65 octets that the
    sum then parses again, and the terms are the only place a caller has
    to put them.

    The naive form of it, deliberately: a term at a time and one sum,
    with none of the shared precomputation of Strauss or Pippenger.
    libsecp256k1 has `secp256k1_ecmult_multi_var`, which is internal and
    not declared in `include/secp256k1.h`, so this is the only
    multi-scalar multiplication the public API can be composed of -- and
    the saving here is the crossing rather than the arithmetic, flat in
    the number of terms where a batched algorithm would grow with it.

    **This is the second function here that is more than one
    libsecp256k1 decision**, `xonly.from_prvkey` being the first, and
    the README's Design section says why the rule is what it is: the
    boundary computes nothing of its own. Neither does this -- the terms
    are `secp256k1_ec_pubkey_tweak_mul` and the sum is
    `secp256k1_ec_pubkey_combine`, in the one order that spells the
    equation -- and what is saved is a serialization and a parse per
    term, about a seventh of the call from three terms up and a little
    less at two.
    `PubkeyTweakChain` is an exception of the other kind and not of
    this one: its `tweak_add` is one decision and a serialization like
    every other, and what it holds is a parsed key across calls the
    caller makes one at a time.

    The infinity is `pubkey_sum`'s None, for the reason it is there and
    is more likely here: a verification equation is written to land on
    it, u*H + v*Q with v*Q the negation of u*H being the accepting case
    of a check spelled as a difference.

    Args:
        pubkeys_bytes: the public keys, each 33 or 65 bytes. At least
            one is required, as the sum requires it.
        tweaks: the scalar each key is multiplied by, one per key, 32
            bytes or an int below 2**256.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized sum of the products, or None where they sum to
        the point at infinity.

    Raises:
        ValueError: if the two sequences are of different lengths, if
            the sequence of keys is empty, if any key is not a valid
            point, or if any tweak is not 32 bytes, does not fit in
            them, or multiplies its key to something invalid -- zero and
            the group order being the two scalars there is no product
            for.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no valid input can make it do.

    Example:
        >>> from btclib_secp256k1 import keys
        >>> generator = keys.pubkey_from_prvkey(1)
        >>> pubkey = keys.pubkey_from_prvkey(7)
        >>> # 2*G + 3*(7*G) is 23*G
        >>> total = keys.pubkey_tweak_mul_sum([generator, pubkey], [2, 3])
        >>> total == keys.pubkey_from_prvkey(23)
        True
        >>> # and a sum landing on the identity is None, not a refusal
        >>> negated = keys.pubkey_negate(pubkey)
        >>> keys.pubkey_tweak_mul_sum([pubkey, negated], [3, 3]) is None
        True
    """
    if len(pubkeys_bytes) != len(tweaks):
        msg = (
            f"as many tweaks as public keys are required: "
            f"{len(tweaks)} tweaks, {len(pubkeys_bytes)} public keys"
        )
        raise ValueError(msg)

    # `strict=False` and the check above rather than `strict=True` and
    # no check: a sequence has a length, so the two are the same guard,
    # and the one that raises here says which sequence was short and by
    # how much where zip says only that they differed. A guard no input
    # can reach is one no test can drive, which this package does not
    # leave behind
    products = [
        _pubkey_tweak_mul_(parse(pubkey_bytes), tweak)
        for pubkey_bytes, tweak in zip(pubkeys_bytes, tweaks, strict=False)
    ]
    summed = _pubkey_sum_(products)
    return None if summed is None else serialize(summed, compressed)


def _pubkey_cmp_(pubkey1: CData, pubkey2: CData) -> int:
    """Compare two already-parsed public keys, in compressed-form order.

    The private half of `pubkey_cmp`, for a caller who already holds
    both parsed points -- sorting keys it has parsed for another reason,
    where every comparison of a sort would otherwise parse both of its
    arguments again. See the package docstring for what the two
    underscores mean throughout.

    Args:
        pubkey1: the first already-parsed public key, as `parse` returns.
        pubkey2: the second one.

    Returns:
        A negative number, zero, or a positive number, according to
        whether the first key sorts before, equal to, or after the
        second. Where libsecp256k1 cannot read an object it compares a
        key of zeros in its place, so the answer is an ordering like any
        other and means nothing: this raises nothing, and
        `context.check` immediately after the call is what says the
        answer is not to be believed. `pubkey_cmp` parses what it is
        given and so has no such case.
    """
    order = lib.secp256k1_ec_pubkey_cmp(ctx, pubkey1, pubkey2)
    return int(order)


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
    return _pubkey_cmp_(parse(pubkey1_bytes), parse(pubkey2_bytes))


def _pubkey_sort_(pubkeys: Sequence[CData]) -> list[CData]:
    """Sort already-parsed public keys, in compressed-form order.

    The private half of `pubkey_sort`, and the one that answers with the
    keys rather than with their serializations: see the package
    docstring for what the two underscores mean throughout. Sorting in
    order to aggregate is this and `_pubkey_combine_`, which takes what
    this returns.

    Args:
        pubkeys: the already-parsed public keys, as `parse` returns. An
            empty sequence sorts to an empty list.

    Returns:
        The same objects that were passed in, in ascending order.

    Raises:
        RuntimeError: if libsecp256k1 refuses an object -- one it cannot
            read -- or fails to sort for any other reason, which no
            valid key can make it do. `context.check` is what tells the
            two apart.
    """
    pubkeys = list(pubkeys)
    # nothing to sort is not a call to make: the array of an empty
    # sequence is the NULL `_cdata.array` answers, which is what
    # libsecp256k1 wants beside a count of zero, and there is no
    # ordering to read back out of it
    if not pubkeys:
        return []

    # the array holds borrowed pointers, and is what gets reordered: the
    # list above is what keeps the keys it points to alive
    pointers = array("secp256k1_pubkey *[]", pubkeys)
    sorted_ = lib.secp256k1_ec_pubkey_sort(ctx, pointers, len(pubkeys))
    if not sorted_:
        raise RuntimeError("public key sorting failed")
    # what comes back are the caller's own objects, found by the address
    # each reordered pointer holds -- a cffi pointer hashes and compares
    # as that address. Handing back the array's own elements instead
    # would hand back pointers that own nothing, and that dangle the
    # moment the caller drops the sequence they point into
    owners = {pubkey: pubkey for pubkey in pubkeys}
    return [owners[pointer] for pointer in pointers]


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
    return [
        serialize(pubkey, compressed)
        for pubkey in _pubkey_sort_([
            parse(pubkey_bytes) for pubkey_bytes in pubkeys_bytes
        ])
    ]


def parse(pubkey_bytes: BytesLike, name: str = "public key") -> CData:
    """Parse a public key into its internal libsecp256k1 representation.

    The internal form is what the raw `lib` calls take, and what
    `serialize` turns back into bytes: `serialize(parse(key))` is the
    compressed form of a key given in either form, which is
    `reserialize` and the reason it exists. It is also what every
    private half of this package takes, for which see the package
    docstring.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        name: what the key is, as the exception should call it, for a
            caller passing more than one kind of public key --
            `silentpayments` passes four, and which one was refused is
            the whole of what its caller needs.

    Returns:
        The libsecp256k1 public key object.

    Raises:
        ValueError: if the bytes are not a valid point in either
            serialization.
    """
    pubkey = _parsed(pubkey_bytes, name)
    if pubkey is None:
        raise ValueError(f"invalid {name}")
    return pubkey


def _parsed(pubkey_bytes: BytesLike, name: str) -> CData | None:
    """Parse a public key, answering None where it is not one.

    `secp256k1_ec_pubkey_parse` is the proof that octets are a public key,
    and there are two things to do with the same proof: `parse` keeps what
    it built and raises when there is nothing to keep, `pubkey_verify`
    keeps nothing and answers the verdict. Written twice, the two would be
    one call each until an argument check moved in one of them.

    It costs `parse` a python call, and that is the whole of what the
    single statement is bought with: 0.269 microseconds against 0.256 on
    the uncompressed serialization, and 2.326 against 2.310 on the
    compressed one, where the field square root is what is being paid for
    -- an Apple M5, macOS 26.6, arm64, CPython 3.14.6, minimum of 7 rounds
    of 300 000 calls.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        name: what the key is, as an exception should call it.

    Returns:
        The libsecp256k1 public key object, or None if libsecp256k1
        refuses the octets -- a length no serialization has among them,
        which is why neither caller checks one.

    Raises:
        TypeError: if the value is not bytes, which is a malformed
            argument rather than a key that fails to parse: a caller with
            no octets at all asked no question about a key.
    """
    pubkey_bytes = octets(pubkey_bytes, name)
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        return None
    return pubkey


def reserialize(pubkey_bytes: BytesLike, compressed: bool = True) -> bytes:
    """Prove octets a public key, and answer them in the form asked for.

    `serialize(parse(key))` as one call, which is two things a caller
    wants separately and always together.

    It is the **validation**: a library proving a key at its own boundary
    has `parse` and nothing to do with what `parse` returns, and this
    answers octets instead of an object whose lifetime is the caller's.

    And it is the **conversion**, which nothing else here offers: a caller
    holding an uncompressed key and needing the compressed one to hash has
    no other call to make, and one holding a compressed key and about to
    make several more calls with it has a reason to ask for the other
    form. The uncompressed serialization is the cheap one to open --
    `parse` is 0.269 us on 65 bytes against 2.326 on 33, both coordinates
    being there to read where a compressed key is a field square root --
    so `reserialize(key, compressed=False)` pays that root once and leaves
    every later call at the price of reading it.

    Args:
        pubkey_bytes: the public key, 33 or 65 bytes.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The same point, serialized as asked.

    Raises:
        ValueError: if the bytes are not a valid point in either
            serialization.
        RuntimeError: if libsecp256k1 fails to serialize it, which no
            valid key can make it do.

    Example:
        >>> from btclib_secp256k1 import keys
        >>> compressed = keys.pubkey_from_prvkey(1)
        >>> uncompressed = keys.reserialize(compressed, compressed=False)
        >>> uncompressed == keys.pubkey_from_prvkey(1, compressed=False)
        True
        >>> keys.reserialize(uncompressed) == compressed
        True
    """
    return serialize(parse(pubkey_bytes), compressed)


def serialize(pubkey: CData, compressed: bool = True) -> bytes:
    """Serialize an internal public key, in compressed form by default.

    Args:
        pubkey: the libsecp256k1 public key object, as `parse` returns.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The 33-byte compressed serialization, or the 65-byte
        uncompressed one.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- a NULL
            pointer, or a `secp256k1_pubkey` nothing has written to --
            or fails for any other reason, which a key it produced
            cannot make it do. Which of the two it was is on the thread
            rather than in the message, and `context.check` is what
            reads it.

    Example:
        >>> from btclib_secp256k1 import keys
        >>> uncompressed = keys.pubkey_from_prvkey(1, compressed=False)
        >>> keys.serialize(keys.parse(uncompressed)).hex()[:10]
        '0279be667e'
    """
    # the buffer is declared by a literal and the size read back off it,
    # so the two cannot say different numbers: `ffi.new` of an
    # interpolated cdecl parses that string on every call, which is 0.043
    # microseconds of the 0.313 this costs -- an Apple M5, macOS 26.6,
    # arm64, CPython 3.13.14, minimum of 9 rounds of 500 000 calls.
    #
    # What is unpacked is the buffer, not the length libsecp256k1 reports
    # back: this serialization has one length per flag, so a buffer of
    # the wrong size has to reach the caller to be caught -- reading the
    # reported length instead would quietly accept an oversized one,
    # which a mutation session measured directly (`char[34]` survives
    # that spelling, and dies in this one). The DER serialization is the
    # other case, and reads `length[0]` for the reason given there.
    #
    # The length is built per call and not hoisted, though it is the same
    # number every time: libsecp256k1 writes 0 into it before it does
    # anything (`*outputlen = 0` in secp256k1.c) and restores it only on
    # success, and it holds the value it finds there against 33 or 65 on
    # the way in. One failed call would leave a shared buffer at
    # zero, and every later serialization -- on any thread, of a
    # perfectly good key -- would be refused
    output = ffi.new("char[33]" if compressed else "char[65]")
    size = ffi.sizeof(output)
    length = ffi.new("size_t *", size)
    flags = COMPRESSED if compressed else UNCOMPRESSED
    serialized = lib.secp256k1_ec_pubkey_serialize(ctx, output, length, pubkey, flags)
    if not serialized:
        raise RuntimeError("point serialization failed")
    return ffi.unpack(output, size)

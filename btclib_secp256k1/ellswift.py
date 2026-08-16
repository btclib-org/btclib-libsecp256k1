# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ElligatorSwift encoding and x-only ECDH, according to BIP324.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, lib
from ._scalar import entropy, in_range, octets, scalar
from ._secret import take
from .context import ctx, guarded
from .keys import parse, serialize


def create(prvkey: BytesLike | int, aux_rand32: BytesLike | None = None) -> bytes:
    """Create the 64-byte ElligatorSwift encoding of a private key's public key.

    This is safer than encoding the public key of that private key, as
    the key itself is used as entropy for the encoding.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of auxiliary randomness, or None for fresh
            randomness.

    Returns:
        The 64-byte ElligatorSwift encoding of the public key.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes, or if
            the private key is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
    """
    prvkey_bytes = scalar(prvkey, "private key")

    ell_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ellswift_create(
        ctx, ell_bytes, prvkey_bytes, entropy(aux_rand32)
    ):
        raise ValueError("invalid private key: not in [1, n-1]")
    return ffi.unpack(ell_bytes, ffi.sizeof(ell_bytes))


def _encode_(pubkey: CData, aux_rand32: BytesLike | None = None) -> bytes:
    """Encode an already-parsed public key as 64 ElligatorSwift bytes.

    The private half of `encode`, for a caller who already holds the
    parsed point -- one encoding a key it has just decoded, or one
    encoding the same key more than once, which BIP324 does with fresh
    randomness at every connection: see the package docstring for what
    the two underscores mean throughout.

    Args:
        pubkey: the already-parsed public key, as `keys.parse` returns.
        aux_rand32: the 32 bytes deciding which of the encodings of that
            key is produced, or None for fresh randomness.

    Returns:
        The 64-byte ElligatorSwift encoding.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes, or if the
            object is not a public key libsecp256k1 will read; see
            `context.guarded`.
        RuntimeError: if libsecp256k1 fails to encode, which no valid
            input can make it do.
    """
    ell_bytes = ffi.new("char[64]")
    aux_rand32_bytes = entropy(aux_rand32)
    with guarded():
        encoded = lib.secp256k1_ellswift_encode(
            ctx, ell_bytes, pubkey, aux_rand32_bytes
        )
    if not encoded:
        raise RuntimeError("ElligatorSwift encoding failed")
    return ffi.unpack(ell_bytes, ffi.sizeof(ell_bytes))


def encode(pubkey_bytes: BytesLike, aux_rand32: BytesLike | None = None) -> bytes:
    """Encode a public key as 64 ElligatorSwift bytes.

    The randomness must not be a deterministic function of the public
    key; when it is not provided, it is freshly generated.

    Args:
        pubkey_bytes: the public key to encode, 33 or 65 bytes.
        aux_rand32: the 32 bytes deciding which of the encodings of that
            key is produced, or None for fresh randomness.

    Returns:
        The 64-byte ElligatorSwift encoding, indistinguishable from
        uniform bytes.

    Raises:
        ValueError: if the public key is not a valid point, or if
            aux_rand32 is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to encode, which no valid
            input can make it do.
    """
    return _encode_(parse(pubkey_bytes), aux_rand32)


def _decode_(ell_bytes: BytesLike) -> CData:
    """Decode a 64-byte ElligatorSwift public key into a parsed key.

    The private half of `decode`, and the one that answers with the point
    rather than with its serialization: see the package docstring for
    what the two underscores mean throughout. A decoded key that is about
    to be tweaked, verified against or encoded again is what this is for --
    libsecp256k1 hands the point over already lifted, and serializing it
    only to lift it back is a field square root nothing asked for.

    Args:
        ell_bytes: the 64-byte encoding.

    Returns:
        The libsecp256k1 public key object. Every 64 bytes decode to a
        point, which is what makes the encoding indistinguishable from
        random: there is nothing to reject.

    Raises:
        ValueError: if the input is not 64 bytes.
        RuntimeError: if libsecp256k1 fails to decode, which no 64 bytes
            can make it do.
    """
    ell_bytes = octets(ell_bytes, "ElligatorSwift public key", 64)

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ellswift_decode(ctx, pubkey, ell_bytes):
        raise RuntimeError("ElligatorSwift decoding failed")
    return pubkey


def decode(ell_bytes: BytesLike, compressed: bool = True) -> bytes:
    """Decode a 64-byte ElligatorSwift public key into a public key.

    Args:
        ell_bytes: the 64-byte encoding.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized public key. Every 64 bytes decode to a point,
        which is what makes the encoding indistinguishable from random:
        there is nothing to reject.

    Raises:
        ValueError: if the input is not 64 bytes.
        RuntimeError: if libsecp256k1 fails to decode or serialize,
            which no 64 bytes can make it do.
    """
    return serialize(_decode_(ell_bytes), compressed)


def xdh(
    ell_a_bytes: BytesLike, ell_b_bytes: BytesLike, prvkey: BytesLike | int, party: int
) -> bytes:
    """Compute the x-only ECDH shared secret of two ElligatorSwift keys.

    The private key must be the one of the given party: 0 for party A,
    1 for party B; the correspondence is not checked. The 32-byte secret
    is derived with the BIP324 hash function.

    Args:
        ell_a_bytes: the 64-byte encoding of party A's key.
        ell_b_bytes: the 64-byte encoding of party B's key.
        prvkey: the private key of the party below, 32 bytes or an int
            below 2**256.
        party: 0 if the private key is A's, 1 if it is B's.

    Returns:
        The 32-byte shared secret, which both parties compute alike. The
        two encodings enter the hash in the order they are given here,
        so BIP324's initiator goes first.

    Raises:
        TypeError: if the party is not an int.
        ValueError: if either encoding is not 64 bytes, if party is not
            0 or 1, or if the private key is not 32 bytes, does not fit
            in them, or is not a valid scalar.
    """
    ell_a_bytes = octets(ell_a_bytes, "ElligatorSwift public key of A", 64)
    ell_b_bytes = octets(ell_b_bytes, "ElligatorSwift public key of B", 64)
    # 0 is A and 1 is B, which is what the argument's own name says
    party = in_range(party, "party", 1)

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
    return take(output)

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Secp256k1 point multiplication.

The two spellings of generator multiplication for a caller who thinks of
it as an operation on a scalar rather than as the public key of a private
key: serialized uncompressed, and as a pair of coordinates. The C call is
`keys.pubkey_from_prvkey`, which is the same multiplication answering in
either serialization.

`mult_bytes` used to be `mult_`, and was renamed for the trailing
underscore rather than for anything it does: that underscore now means a
private half speaking in parsed objects, and this is a public function
answering octets. `_bytes` is what the rest of this package calls the
octets of a thing.
"""

from __future__ import annotations

from . import BytesLike
from .keys import pubkey_from_prvkey


def mult_bytes(num: BytesLike | int) -> bytes:
    """Multiply the generator point, in serialized form.

    Args:
        num: the scalar to multiply the generator by, 32 bytes or an int
            below 2**256.

    Returns:
        The resulting point, uncompressed: 65 bytes opening with 0x04.
        This is `keys.pubkey_from_prvkey(num, compressed=False)`, whose
        default is the compressed form of the same point.

    Raises:
        ValueError: if the scalar is not 32 bytes or does not fit in
            them, or if it is not in [1, n-1]. The message names a
            private key, that being what the scalar of a generator
            multiplication is to libsecp256k1.
        RuntimeError: if libsecp256k1 fails to serialize the point,
            which no input can make it do.

    Example:
        >>> from btclib_secp256k1 import mult
        >>> mult.mult_bytes(1).hex()[:10]
        '0479be667e'
    """
    return pubkey_from_prvkey(num, compressed=False)


def mult(num: BytesLike | int) -> tuple[int, int]:
    """Multiply the generator point, as a pair of coordinates.

    Args:
        num: the scalar to multiply the generator by, 32 bytes or an int
            below 2**256.

    Returns:
        The affine coordinates (x, y) of the resulting point, as ints.
        This is `mult_bytes` with the two halves of its output read as
        big endian integers; a caller that wants bytes wants
        `mult_bytes`, or `keys.pubkey_from_prvkey` for the compressed
        form.

    Raises:
        ValueError: if the scalar is not 32 bytes or does not fit in
            them, or if it is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the point,
            which no input can make it do.
    """
    result = mult_bytes(num)
    return int.from_bytes(result[1:33], "big"), int.from_bytes(result[33:], "big")

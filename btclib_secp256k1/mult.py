# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Secp256k1 point multiplication.

Generator multiplication for a caller who thinks of it as an operation on
a scalar rather than as the public key of a private key. The C call is
`keys.pubkey_from_prvkey`, which is the same multiplication with the
serialization flag every producer of a key takes; this is its
`compressed=False` case under the name the operation has.

`mult` was here too, and answered the pair of coordinates as ints. It is
gone: a point of the curve left this package as numbers in that one
place, where every other answer is octets or a verdict, and reading the
two halves of these 65 octets is `int.from_bytes` twice -- 0.138
microseconds of a call that is some 8.5, which is 1.6% of it and the
whole of what the exception was worth. Measured in the caller because
that is where it now happens: the function that used to do it held the
same two conversions inside a python frame that cost about as much
again, so the two spellings are the same call and neither is reliably
the faster. What a caller wanting coordinates writes is:

    sec = mult.mult_bytes(num)
    x, y = int.from_bytes(sec[1:33], "big"), int.from_bytes(sec[33:], "big")
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

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Secp256k1 point multiplication."""

from __future__ import annotations

from . import ffi, lib
from ._scalar import scalar
from .context import ctx


def mult_(num: bytes | int) -> bytes:
    """Multiply the generator point, in serialized form.

    Args:
        num: the scalar to multiply the generator by, 32 bytes or an int
            below 2**256.

    Returns:
        The resulting point, uncompressed: 65 bytes opening with 0x04.
        `keys.serialize(keys.parse(...))` is the compressed form of it.

    Raises:
        ValueError: if the scalar is not 32 bytes or does not fit in
            them, or if it is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the point,
            which no input can make it do.

    Example:
        >>> from btclib_libsecp256k1 import mult
        >>> mult.mult_(1).hex()[:10]
        '0479be667e'
    """
    num_bytes = scalar(num, "scalar")
    point = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_create(ctx, point, num_bytes):
        raise ValueError("invalid scalar: not in [1, n-1]")

    output = ffi.new("char[65]")
    length = ffi.new("size_t *", 65)

    if lib.secp256k1_ec_pubkey_serialize(ctx, output, length, point, 2):
        return ffi.unpack(output, 65)
    raise RuntimeError("point serialization failed")


def mult(num: bytes | int) -> tuple[int, int]:
    """Multiply the generator point, as a pair of coordinates.

    Args:
        num: the scalar to multiply the generator by, 32 bytes or an int
            below 2**256.

    Returns:
        The affine coordinates (x, y) of the resulting point, as ints.
        This is `mult_` with the two halves of its output read as big
        endian integers; a caller that wants bytes wants `mult_`.

    Raises:
        ValueError: if the scalar is not 32 bytes or does not fit in
            them, or if it is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the point,
            which no input can make it do.
    """
    result = mult_(num)
    return int.from_bytes(result[1:33], "big"), int.from_bytes(result[33:], "big")

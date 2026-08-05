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
    """Multiply the generator point."""

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
    """Multiply the generator point."""

    result = mult_(num)
    return int.from_bytes(result[1:33], "big"), int.from_bytes(result[33:], "big")

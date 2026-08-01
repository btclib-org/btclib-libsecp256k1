# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Normalization of the scalar arguments of the bindings."""

from __future__ import annotations


def scalar(num: bytes | int, name: str) -> bytes:
    """Normalize a scalar argument to 32 bytes.

    An int is serialized big endian, as libsecp256k1 expects; bytes are
    passed through. The length is checked here because libsecp256k1
    takes a bare pointer and would read past the end of a shorter one.
    A short bytes is not padded to that length while an int is
    serialized to it, and the asymmetry is not a leniency: bytes state a
    value and a width, one of which would have to be disbelieved,
    whereas an int states only a value and the width is the curve's.

    A secret is better passed as bytes, for a narrow reason. Not the
    serialization, which is a loop over nine CPython digits and measures
    as noise, but the python arithmetic that produced the int, variable
    in time with the magnitude of its operands and leaving unzeroized
    copies of every intermediate on the heap — all of it before this
    call. bytes are not zeroized either, so what they buy is only that
    no arithmetic on the secret happened here; scalar arithmetic that
    must not leak belongs where that can be promised.
    """

    if isinstance(num, int):
        # an int outside the 32-byte range is out of domain like any
        # other invalid argument, and must be reported the same way:
        # to_bytes would raise OverflowError instead. Whether the value
        # is a valid scalar, i.e. in [1, n-1], is for libsecp256k1 to say
        if not 0 <= num < 2**256:
            raise ValueError(f"the {name} must fit in 32 bytes")
        num_bytes = num.to_bytes(32, "big")
    else:
        num_bytes = num
    if len(num_bytes) != 32:
        raise ValueError(f"the {name} must be 32 bytes")
    return num_bytes

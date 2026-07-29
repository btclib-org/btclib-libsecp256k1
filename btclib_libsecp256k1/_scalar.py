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
    """

    num_bytes = num.to_bytes(32, "big") if isinstance(num, int) else num
    if len(num_bytes) != 32:
        raise ValueError(f"the {name} must be 32 bytes")
    return num_bytes

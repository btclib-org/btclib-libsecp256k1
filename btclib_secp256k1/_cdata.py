# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The arrays of borrowed pointers libsecp256k1 takes several objects in."""

from __future__ import annotations

from collections.abc import Sequence

from . import CData, ffi


def array(cdecl: str, items: Sequence[CData]) -> CData:
    """Build the array of pointers libsecp256k1 reads a sequence through.

    The array holds borrowed pointers: what keeps the objects alive is
    the sequence the caller passes, which has to outlive the call, and
    what libsecp256k1 reorders where it sorts is this array rather than
    the objects it points at.

    An empty sequence answers NULL, which is what libsecp256k1 requires
    rather than merely accepts: it reads the count against the pointer,
    and a non-NULL one with a count of zero fails an ARG_CHECK --
    `n_xonly_pubkeys > 0` in the Silent Payments summary, reported
    through the illegal callback. cffi would hand over an array of
    length zero quite happily, so it is this call that has to say NULL.

    Args:
        cdecl: the cffi declaration of the array type.
        items: the objects to point at, which the caller keeps alive.

    Returns:
        The array, or NULL where there is nothing to point at.
    """
    return ffi.new(cdecl, list(items)) if items else ffi.NULL

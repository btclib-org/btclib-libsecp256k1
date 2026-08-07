# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the arguments of the bindings are held to before they cross."""

from __future__ import annotations

from . import BytesLike


def octets(value: BytesLike, name: str, size: int | None = None) -> bytes:
    """Normalize an argument to the bytes a bare pointer needs, of a length.

    Both halves of that, and they are one question. The length, because
    libsecp256k1 reads a fixed number of octets from a pointer whose
    length never reached C to be checked. The type, because `len`
    answers for anything with a length: a `bytearray` of 32 passed the
    size check on its own and left cffi to refuse it one call later, in
    its own words and about a ctype -- `initializer for ctype 'unsigned
    char *' must be a cdata pointer` -- which names neither the argument
    nor what was wrong with it. A `float` did not even get that far, and
    came back as `object of type 'float' has no len()`.

    A `bytearray` and a `memoryview` are converted rather than refused,
    and that is not the leniency the short value is: they state a value
    and a width, both of them, so nothing has to be disbelieved and
    nothing supplied. The `int` this package already accepts for a
    scalar is the wider door of the two, the 32-octet width being the
    curve's rather than the caller's. What the conversion is not is a
    pass-through: the copy is taken here, so a caller who overwrites
    their own buffer -- which is the reason to hold a secret in a
    mutable one -- cannot change what libsecp256k1 is about to read.

    Args:
        value: the argument, as the caller passed it.
        name: what the argument is, as the exception should call it.
        size: the number of octets libsecp256k1 will read, or None where
            the encoding carries its own length.

    Returns:
        The value as bytes: itself, if that is what it already was.

    Raises:
        TypeError: if the value is not one of those three types.
        ValueError: if a size is given and the value is not that long.
    """
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"the {name} must be bytes, not {type(value).__name__}")
    # bytes of bytes is bytes, so nothing is copied in the ordinary case
    value_bytes = bytes(value)
    if size is not None and len(value_bytes) != size:
        raise ValueError(f"the {name} must be {size} bytes")
    return value_bytes


def scalar(num: BytesLike | int, name: str) -> bytes:
    """Normalize a scalar argument to 32 bytes.

    An int is serialized big endian, as libsecp256k1 expects; anything
    `octets` takes goes to it. The length is checked there because
    libsecp256k1 takes a bare pointer and would read past the end of a
    shorter one. A short value is not padded to that length while an int
    is serialized to it, and the asymmetry is not a leniency: 20 octets
    state a value and a width, one of which would have to be
    disbelieved, whereas an int states only a value and the width is the
    curve's.

    A secret is better passed as bytes, for a narrow reason. Not the
    serialization, which is a loop over nine CPython digits and measures
    as noise, but the python arithmetic that produced the int, variable
    in time with the magnitude of its operands and leaving unzeroized
    copies of every intermediate on the heap — all of it before this
    call. bytes are not zeroized either, so what they buy is only that
    no arithmetic on the secret happened here; scalar arithmetic that
    must not leak belongs where that can be promised.

    Args:
        num: the scalar, exactly 32 octets or an int in [0, 2**256).
        name: what the scalar is, as the exception should call it.

    Returns:
        The scalar as 32 bytes, big endian.

    Raises:
        TypeError: if the value is neither an int nor one of the types
            `octets` takes, a bool counting as neither although python
            makes it an int.
        ValueError: if it is not exactly 32 octets long, or if an int
            does not fit in 32 bytes. Whether the value is a valid
            scalar, i.e. in [1, n-1], is for libsecp256k1 to say.
    """
    # a bool is an int in python, and would be the scalar 1 or 0 without
    # the second test: `prvkey_verify(False)` then answers False, which
    # is the right verdict on a question nobody asked, and
    # `pubkey_from_prvkey(True)` answers the generator. Neither can be
    # told from the answer to the question that was meant, which is what
    # makes this worth refusing where a `float` would only be a typo
    if isinstance(num, int) and not isinstance(num, bool):
        # an int outside the 32-byte range is out of domain like any
        # other invalid argument, and must be reported the same way:
        # to_bytes would raise OverflowError instead. Whether the value
        # is a valid scalar, i.e. in [1, n-1], is for libsecp256k1 to say
        if not 0 <= num < 2**256:
            raise ValueError(f"the {name} must fit in 32 bytes")
        return num.to_bytes(32, "big")
    # the domain here is octets' plus the int above, so a value that is
    # neither is named here: what is left for octets is the length
    if not isinstance(num, (bytes, bytearray, memoryview)):
        raise TypeError(f"the {name} must be bytes or an int, not {type(num).__name__}")
    return octets(num, name, 32)

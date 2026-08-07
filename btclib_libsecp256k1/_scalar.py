# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the arguments of the bindings are held to before they cross."""

from __future__ import annotations


def octets(value: bytes, name: str, size: int | None = None) -> bytes:
    """Hold an argument to the type and the length a bare pointer needs.

    Both halves of that, and they are one question.
    The length, because libsecp256k1 reads a fixed number of octets from
    a pointer whose length never reached C to be checked. The type,
    because `len` answers for anything with a length: a `bytearray` of
    32 passed that check and left cffi to refuse it one call later, in
    its own words and about a ctype -- `initializer for ctype 'unsigned
    char *' must be a cdata pointer` -- which names neither the argument
    nor what was wrong with it. A `float` did not even get that far, and
    came back as `object of type 'float' has no len()`.

    `bytes` and nothing else. A `bytearray` or a `memoryview` states the
    same value and the same width, and converting one would be no guess
    at all -- but it would widen what every signature here promises, and
    that is the caller's to ask for, spelled `bytes(x)` where they can
    see it.

    Args:
        value: the argument, as the caller passed it.
        name: what the argument is, as the exception should call it.
        size: the number of octets libsecp256k1 will read, or None where
            the encoding carries its own length.

    Returns:
        The same bytes, so that a call may wrap the argument it checks.

    Raises:
        TypeError: if the value is not bytes.
        ValueError: if a size is given and the value is not that long.
    """
    if not isinstance(value, bytes):
        raise TypeError(f"the {name} must be bytes, not {type(value).__name__}")
    if size is not None and len(value) != size:
        raise ValueError(f"the {name} must be {size} bytes")
    return value


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

    Args:
        num: the scalar, exactly 32 bytes or an int in [0, 2**256).
        name: what the scalar is, as the exception should call it.

    Returns:
        The scalar as 32 bytes, big endian.

    Raises:
        TypeError: if the value is neither bytes nor an int, a bool
            counting as neither although python makes it an int.
        ValueError: if bytes are not exactly 32 long, or if an int does
            not fit in 32 bytes. Whether the value is a valid scalar,
            i.e. in [1, n-1], is for libsecp256k1 to say.
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
    # the domain here is wider than octets', so the type is said here:
    # what is left for it is the length
    if not isinstance(num, bytes):
        raise TypeError(f"the {name} must be bytes or an int, not {type(num).__name__}")
    return octets(num, name, 32)

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the arguments of the bindings are held to before they cross."""

from __future__ import annotations

import secrets

from . import BytesLike, CData, ffi


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
        TypeError: if the value is not one of those three types, or is a
            memoryview whose items are wider than an octet.
        ValueError: if a size is given and the value is not that long.
    """
    # `bytes` is what all but a handful of calls pass, and every question
    # the block below asks is already answered for it: it is one of the
    # three types, its items are octets, and the copy it would take is the
    # object itself. Asking the type once and skipping the rest measures
    # 0.031 microseconds against 0.078 -- an Apple M5, macOS 26.6, arm64,
    # CPython 3.13.14, minimum of 7 rounds of a million calls -- and every
    # entry point here pays it at least once, several of them three times.
    # `type(...) is` rather than `isinstance`, deliberately: a subclass of
    # bytes may override `__len__`, so what the fast path is allowed to
    # trust is the exact type
    if type(value) is bytes:
        value_bytes = value
    else:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError(f"the {name} must be bytes, not {type(value).__name__}")
        # a memoryview states its width in items, and `bytes` of one reads
        # the octets underneath them: eight uint32 are 32 octets of
        # whatever this machine's byte order made of them, which passes
        # the size check below as a scalar nobody wrote -- the one way in
        # which a memoryview does not state the width this reads it for.
        # Refused rather than reinterpreted, for the reason a 20-octet
        # value is: `value.cast("B")` is how a caller says that the octets
        # are what they meant.
        #
        # Nothing else about the shape needs asking. Where the items are
        # octets, `bytes` answers the ones the view logically holds --
        # through a stride, and over every dimension of a multidimensional
        # view -- so the length checked below is the length libsecp256k1
        # will read
        if isinstance(value, memoryview) and value.itemsize != 1:
            msg = (
                f"the {name} must be a memoryview of bytes, "
                f"not of {value.itemsize}-byte items"
            )
            raise TypeError(msg)
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
    # the two tests below answer for `bytes` before `octets` asks its
    # own, and every scalar these bindings are handed in a loop is bytes:
    # asking the exact type once and going straight there is what the
    # same fast path in `octets` is for, and for the same reason
    if type(num) is bytes:
        return octets(num, name, 32)
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


def entropy(aux_rand32: BytesLike | None, name: str = "aux_rand32") -> bytes:
    """Normalize 32 bytes of entropy, generating them where none was given.

    Entropy is not a serialization: a shorter value is a caller mistake
    rather than a small number, and padding it here would turn one into a
    valid argument. Omitting it altogether is not that mistake, and is
    what every caller with no entropy of its own should do -- BIP340
    recommends fresh randomness at every signature, and the
    ElligatorSwift encoding requires randomness that is not a function of
    the key it encodes.

    Args:
        aux_rand32: the 32 bytes given by the caller, or None.
        name: what the entropy is, as the exception should call it.

    Returns:
        Those 32 bytes, or 32 freshly generated ones.

    Raises:
        TypeError: if a value is given and is not bytes.
        ValueError: if a value is given and is not 32 bytes.
    """
    if aux_rand32 is None:
        return secrets.token_bytes(32)
    return octets(aux_rand32, name, 32)


def optional_entropy(
    aux_rand32: BytesLike | None, name: str = "aux_rand32"
) -> bytes | CData:
    """Normalize 32 bytes of entropy, or the NULL that asks for none.

    What `entropy` is where omitting the argument means fresh randomness,
    this is where it means none at all: the RFC6979 nonce is a function
    of the message and the key, and the extra entropy libsecp256k1 mixes
    into it is what a NULL pointer declines. Generating it here instead
    would take determinism away from a caller who asked for it by saying
    nothing.

    Args:
        aux_rand32: the 32 bytes given by the caller, or None.
        name: what the entropy is, as the exception should call it.

    Returns:
        Those 32 bytes, or NULL.

    Raises:
        TypeError: if a value is given and is not bytes.
        ValueError: if a value is given and is not 32 bytes.
    """
    if aux_rand32 is None:
        return ffi.NULL
    return octets(aux_rand32, name, 32)


def in_range(value: int, name: str, upper: int) -> int:
    """Normalize an int the caller chose from a small closed set.

    A recovery id, a y parity, an ElligatorSwift party, a label index:
    each is a small number libsecp256k1 takes as a C int, and each is out
    of domain in the same way. Refused here rather than at the boundary,
    where cffi answers an out of range value with OverflowError and a
    float with a TypeError about a ctype, neither of which names the
    argument.

    A bool passes, where `scalar` refuses one, and the two are the same
    rule rather than opposite ones: there a `True` would be the scalar 1
    and the answer to a question nobody asked, indistinguishable from
    the answer to the one that was meant, while here the value *is* the
    number, and `bool(recid)` of a recovery id that is 0 or 1 says
    exactly what it says. What is refused is what is not a number at
    all: `0.0` passes an `in (0, 1)` test and reaches cffi as a float.

    Args:
        value: the number, as the caller passed it.
        name: what the number is, as the exception should call it.
        upper: the largest value the set holds, the smallest being zero.

    Returns:
        The value itself, that being what it already is.

    Raises:
        TypeError: if it is not an int.
        ValueError: if it is outside [0, upper].
    """
    if not isinstance(value, int):
        raise TypeError(f"the {name} must be an int, not {type(value).__name__}")
    if not 0 <= value <= upper:
        raise ValueError(f"the {name} must be in [0, {upper}]")
    return value

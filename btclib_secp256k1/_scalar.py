# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the arguments of the bindings are held to before they cross."""

from __future__ import annotations

import secrets

from . import BytesLike, CData, ffi

# the one item type cffi will pass where libsecp256k1 declares
# `const unsigned char *`, resolved once at import as the buffer types of
# the wrappers are: `_owned_octets` re-views a caller's 32 octets as this,
# whatever they declared them
_OCTETS_TYPE = ffi.typeof("unsigned char[32]")


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
    # 0.034 microseconds against 0.080 -- an Apple M5, macOS 26.6, arm64,
    # CPython 3.13.14, minimum of 9 rounds of a million calls -- and every
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


def _owned_octets(num: CData, name: str) -> CData:
    """Accept 32 octets of memory the caller owns, unconverted.

    The one argument of these bindings that is not copied on the way in,
    and the reason is what a copy would be: an immutable `bytes` of a
    secret, which nothing can overwrite and which stays until the
    collector gets to it. A caller holding the key in memory it can zero
    -- `ffi.new("unsigned char[32]")`, wiped with `_secret.wipe` -- would
    otherwise have one made per call, so what `octets` is right to do for
    a value is wrong for this one.

    What that gives up is stated where `octets` states the opposite: the
    copy taken there is what stops a caller overwriting their own buffer
    while libsecp256k1 reads it. **Three obligations pass to the caller
    with the copy**, and none of them exists for a `bytes`:

    - the octets stay put for the whole call, and the whole call is more
      than one read. `secp256k1_ecdsa_sign` loads the scalar
      (`secp256k1/src/secp256k1.c:555`) and then hands the same pointer
      to the nonce derivation (:563), and above it `dsa._sign_` reads it
      again for every grinding attempt and once more in `_checked`'s
      failing branch. So a write in between is not "a different key
      signed": it is a nonce and a signature derived from two different
      keys, which arrives as the fault `RuntimeError` and looks like
      hardware;
    - the memory outlives the call, which no python argument has ever had
      to promise. A cdata view does not keep its owner alive:
      `ffi.new("unsigned char[64]")[0:32]` and `ffi.cast(...)` over a
      temporary read freed memory, measured -- zeros here by the
      allocator's grace, and a plausible scalar on a busier heap. What
      this function returns is safe in that respect, `from_buffer`
      keeping its view alive, but it cannot rescue a dangling argument;
    - the declaration is the truth about the length, because `ffi.sizeof`
      answers what the *type* says rather than what was allocated:
      `ffi.cast("unsigned char[32]", <8 octets>)` clears every refusal
      below and has libsecp256k1 read 24 octets of whatever follows.
      cffi has nothing to check that against, so neither has this.

    The alternative on offer is the copy that cannot be wiped, which is
    why the trade is a caller's to make and not a default.

    Any 1-octet array is taken, whatever the caller declared it as, and
    what makes that safe is a re-view rather than a conversion:
    `ffi.from_buffer` over `ffi.buffer` answers an `unsigned char[32]`
    pointing at the caller's own memory, which is the one item type cffi
    will pass to `const unsigned char *`. Without it the acceptance would
    be `char` and `unsigned char` alone -- cffi holds `uint8_t` and
    `signed char` to be primitives of their own, so `uint8_t[32]`, which
    is what a C programmer writes for 32 octets, would clear every check
    here and die at the boundary in cffi's words.

    **Not `ffi.cast`, and this is the trap in the neighbourhood.** It
    would answer the same pointer for nothing, and it does not keep the
    memory alive: a cast whose owner is dropped reads freed memory, which
    was measured rather than read off the documentation -- 32 octets that
    no longer hold the key, with no error anywhere. `from_buffer` keeps a
    reference to what it views, and the buffer it views keeps the cdata,
    so the chain holds for as long as the value is in use.

    Which shapes are refused is the whole of the care here, because what
    follows is a bare pointer libsecp256k1 reads 32 octets from:

    - a *pointer* rather than an array, whose `ffi.sizeof` is 8 on this
      machine and says nothing about what it points at. That is the trap
      `_secret.wipe` records from the other side, where `ffi.sizeof`
      would have wiped a quarter of a private key and reported success
    - an array whose items are wider than an octet. `uint32_t[8]` is 32
      octets of whatever this machine's byte order made of them, which
      is exactly what `octets` refuses a `memoryview` of wider items
      for, and refused rather than reinterpreted for the same reason
    - an array of the wrong length, which is the check every other
      scalar gets and the one a bare pointer cannot be given later

    Args:
        num: the cdata, as the caller passed it.
        name: what the scalar is, as the exception should call it.

    Returns:
        The caller's own 32 octets as an `unsigned char[32]`, which is a
        view of that memory and not a copy of it: writing through the
        original changes what libsecp256k1 reads.

    Raises:
        TypeError: if it is not a cdata at all, or is not an array of
            octets. A cdata's own `cname` is in the message, that being
            what a caller declared.
        ValueError: if it is an array of octets and not 32 of them.
    """
    # what reaches here is whatever was neither bytes nor an int, and the
    # message for it is `scalar`'s own, stated once for the two ways of
    # arriving at it
    not_a_scalar = f"the {name} must be bytes or an int, not {type(num).__name__}"
    # a `str` is refused before the question rather than by it, because
    # `ffi.typeof` reads a str as a *cdecl*: `"x" * 32` comes back as
    # cffi's own `error: undefined type name`, which is not this
    # function's TypeError and not about the argument -- and `"char[32]"`
    # is worse, being a cdecl that resolves, 32 octets wide, so the str
    # would have been accepted and handed to libsecp256k1 as a str.
    # `tests/test_core.py` holds both
    if isinstance(num, str):
        raise TypeError(not_a_scalar)
    try:
        ctype = ffi.typeof(num)
    except TypeError:
        raise TypeError(not_a_scalar) from None
    if ctype.kind != "array" or ffi.sizeof(ctype.item) != 1:
        msg = f"the {name} must be a cffi array of octets, not {ctype.cname}"
        raise TypeError(msg)
    if ffi.sizeof(num) != 32:
        raise ValueError(f"the {name} must be 32 bytes")
    return ffi.from_buffer(_OCTETS_TYPE, ffi.buffer(num))


def scalar(num: BytesLike | int | CData, name: str) -> bytes | CData:
    """Normalize a scalar argument to 32 bytes.

    An int is serialized big endian, as libsecp256k1 expects; anything
    `octets` takes goes to it. The length is checked there because
    libsecp256k1 takes a bare pointer and would read past the end of a
    shorter one. A short value is not padded to that length while an int
    is serialized to it, and the asymmetry is not a leniency: 20 octets
    state a value and a width, one of which would have to be
    disbelieved, whereas an int states only a value and the width is the
    curve's.

    A cffi array of 32 octets is the one thing not copied. It is memory
    the caller owns and can overwrite, so converting it would make the
    copy that cannot be -- `_owned_octets` is that decision, what it
    refuses, and the re-view that lets any 1-octet spelling through.
    Where libsecp256k1 writes through the pointer instead of reading it,
    or where this package wipes the buffer afterwards, a copy is owed and
    `_secret.scalar_buffer` is the one that takes it.

    Where it matters is not the per-signature path, the private halves
    handing libsecp256k1 the pointer without coming through here at all,
    but the *derivation*:
    `keys._pubkey_from_prvkey_` asks for a scalar, so before this a key
    held in a buffer could not have its public key derived -- and
    `dsa._checked`'s failing branch, which derives in order to tell a
    wrong argument from a fault, answered a `TypeError` about the
    argument instead of the diagnosis it exists for.

    A secret is better passed as bytes, for a narrow reason. Not the
    serialization, which is a loop over nine CPython digits and measures
    as noise, but the python arithmetic that produced the int, variable
    in time with the magnitude of its operands and leaving unzeroized
    copies of every intermediate on the heap — all of it before this
    call. bytes are not zeroized either, so what they buy is only that
    no arithmetic on the secret happened here; scalar arithmetic that
    must not leak belongs where that can be promised.

    Args:
        num: the scalar, exactly 32 octets or an int in [0, 2**256). The
            octets may be a cffi array of them, which is passed on as it
            stands rather than copied.
        name: what the scalar is, as the exception should call it.

    Returns:
        The scalar as 32 bytes, big endian -- or the caller's own cdata,
        where that is what was handed in.

    Raises:
        TypeError: if the value is neither an int nor one of the types
            `octets` takes nor a cffi array of octets, a bool counting as
            none of them although python makes it an int.
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
    # the domain here is octets' plus the int above plus a cdata, and it
    # is asked in that order: everything a value can be is settled before
    # `ffi.typeof` is called at all, so the common paths pay nothing for
    # this one. What is left for octets is the length
    if not isinstance(num, (bytes, bytearray, memoryview)):
        return _owned_octets(num, name)
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

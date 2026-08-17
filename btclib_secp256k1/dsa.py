# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Digital Signature Algorithm (ECDSA).

A signature crosses this boundary in one of its two serializations, DER
or the 64-byte compact form, and `parse_der`, `parse_compact`,
`serialize_der` and `serialize_compact` are what open and close each of
them. They are here for the reason `keys.parse` is: a caller doing more
than one thing with one signature -- asking whether it is low-s and then
verifying it, verifying it against several keys, storing it in the other
form -- parses it once and hands the object to the private halves, where
`normalize`, `is_low_s`, `is_low_r`, `to_der` and `to_compact` each parse
and serialize one of their own.
"""

from __future__ import annotations

from typing import overload

from . import BytesLike, CData, MutableBytesLike, ffi, keys, lib
from ._scalar import in_range, octets, optional_entropy, scalar
from ._secret import take
from .context import ctx

# the two buffers a signature is serialized into, and the lengths that go
# with them in both directions: `_parsed` accepts a compact signature of
# the width `serialize_compact` writes, so one statement of it answers
# for the argument check as well. `ffi.sizeof` of a cdata is asked at
# neither call, which is worth a hundredth of a microsecond of the 0.278
# the DER serialization costs and of the 0.182 the compact one does --
# 0.012 and 0.006 in the session `xonly.py` names, and not a figure this
# site can be held to between sessions: that comment says why.
#
# The compact width is an int and the DER capacity is not, which is the
# one place this module departs from the other five, and `length[0]` is
# the reason: what `serialize_der` unpacks is the length libsecp256k1
# reports back, so a capacity above 72 is absorbed on the way out and no
# test can tell it from 72 -- verified, 73 leaves the suite passing where
# 71 fails `test_der_reaches_all_72_octets`. Written as an int it would
# be a number the mutation operator reaches and nothing checks, which is
# the shape `.github/mutation/bindings.toml` records as closed, six of
# thirteen survivors having been it. So it stays inside the cdecl, where
# the width is still stated once and `ffi.sizeof` derives the capacity
# from the buffer's own type -- at import, not per call.
#
# 72 is the maximum a signature of this curve can encode to, and it is
# structural rather than generous: secp256k1_ecdsa_sig_serialize writes
# 6 + lenR + lenS, and each of those is at most 33 -- 32 octets of
# scalar and the leading zero DER wants when the top bit is set.
# `to_der` reaches it, a high-s signature being one it serializes rather
# than refuses
_DER_BUFFER_TYPE = ffi.typeof("char[72]")
_DER_SIZE = ffi.sizeof(_DER_BUFFER_TYPE)
_COMPACT_SIZE = 64
_COMPACT_BUFFER_TYPE = ffi.typeof(f"char[{_COMPACT_SIZE}]")


@overload
def nonce_rfc6979(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    attempt: int = 0,
) -> bytes: ...
@overload
def nonce_rfc6979(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    attempt: int = 0,
    *,
    into: MutableBytesLike,
) -> None: ...
@overload
def nonce_rfc6979(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    attempt: int = 0,
    *,
    into: MutableBytesLike | None,
) -> bytes | None: ...
def nonce_rfc6979(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    attempt: int = 0,
    *,
    into: MutableBytesLike | None = None,
) -> bytes | None:
    """Return the RFC6979 nonce `sign` derives for a message and a key.

    libsecp256k1 exports its nonce function as a callable pointer, and
    this calls through it with what `secp256k1_ecdsa_sign` passes: the
    message hash, the key, no algorithm tag, and the extra entropy. That
    signing call selects the *default* nonce function, which libsecp256k1
    documents as the same pointer as this one -- an identity
    `tests/test_nonces.py` asserts rather than assumes. So what comes back
    is the `k` of the signature `sign` makes of the same arguments: `r` is
    the x of `k` times the generator, reduced, which is what that same
    file holds it to.

    It is here because a nonce is the one part of signing these bindings
    compute and never show, which leaves a python implementation of
    RFC6979 with published vectors and no oracle. `recovery.sign` derives
    its nonce the same way and this answers for it too.

    **The nonce is the secret the signature is built on.** Read into
    python it has left constant-time code, and a caller that signs with
    one it read here is doing the arithmetic this package delegates
    precisely so that it is not done in python. What this is for is
    checking a derivation, not driving one.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: the 32 bytes of extra entropy `sign` mixes in, or
            None for the RFC6979 nonce alone. Whichever was given to
            `sign` is what reproduces its nonce, `None` included.
        attempt: which candidate to answer. RFC6979 retries when the one
            it derives is not a scalar in [1, n-1], and libsecp256k1
            drives that counter itself; 0 is what it takes first and what
            every signature this package makes has used.

        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32-byte nonce -- or None where `into` was given and holds it.

    Raises:
        TypeError: if the attempt is not an int, if an argument is not
            bytes, or if `into` is not a writable bytearray or
            memoryview of octets.
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, if the private key is not 32 bytes
            or does not fit in them, or if the attempt is out of range.
        RuntimeError: if libsecp256k1 fails to derive one, which RFC6979
            answers for every input.

    Example:
        >>> from btclib_secp256k1 import dsa
        >>> nonce = dsa.nonce_rfc6979(bytes(32), 1)
        >>> len(nonce)
        32
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)
    prvkey_bytes = scalar(prvkey, "private key")
    # unsigned int, and out of range is out of domain like any other
    # argument rather than the OverflowError cffi would answer with
    attempt = in_range(attempt, "attempt", 2**32 - 1)
    # the entropy has to outlive the call: cffi keeps alive what a
    # variable points to, and this pointer is read inside it
    ndata = optional_entropy(aux_rand32)

    nonce = ffi.new("unsigned char[32]")
    # NULL where the algorithm tag goes, which is what
    # secp256k1_ecdsa_sign passes: a tag is what tells one derivation
    # from another, and this is the one ECDSA signing uses
    if not lib.secp256k1_nonce_function_rfc6979(
        nonce, msg_bytes, prvkey_bytes, ffi.NULL, ndata, attempt
    ):
        raise RuntimeError("RFC6979 nonce derivation failed")
    return take(nonce, into=into)


def _signed(
    signature: CData, msg_bytes: bytes, prvkey_bytes: bytes, ndata: bytes | CData
) -> None:
    """Sign into a signature object the caller owns.

    The one signing call of this module, written once because `_sign_`
    makes it and `_grind` makes it again for every attempt after the
    first. Every argument is checked before it gets here, so what this
    is for is the call itself and the one failure of it: two spellings of
    it would be two chances to pass a different nonce function.

    Args:
        signature: the signature object to sign into, overwritten.
        msg_bytes: the 32-byte hash of the message, already checked.
        prvkey_bytes: the 32-byte private key, already checked.
        ndata: the extra entropy to mix into the nonce, or NULL for none,
            as `optional_entropy` returns it.

    Raises:
        ValueError: if the private key is not in [1, n-1], which is the
            one thing about it libsecp256k1 answers for and `scalar`
            cannot.
    """
    # secp256k1_ecdsa_sign takes the nonce function and its data: NULL
    # for the first selects the RFC6979 default, and it is the only one
    # these bindings pass -- a python nonce function would be called from
    # inside the signature, with the secret passing through a python
    # object on every call. The contribution beside it is 32 bytes of
    # entropy, and `optional_entropy` says what omitting it means here
    noncefp = ffi.NULL
    if not lib.secp256k1_ecdsa_sign(
        ctx, signature, msg_bytes, prvkey_bytes, noncefp, ndata
    ):
        raise ValueError("invalid private key: not in [1, n-1]")


def _grind(signature: CData, msg_bytes: bytes, prvkey_bytes: bytes) -> None:
    """Sign again into the same object until r is the low one.

    Bitcoin Core's `CKey::Sign` scheme, and it has to be that one octet
    for octet: what makes a ground signature reproducible by anybody else
    is the counter, not the idea. The first attempt is the plain RFC6979
    signature the caller already holds; each retry mixes a `uint32`
    counter, little endian in the first 4 of 32 octets, into the nonce
    that derives the next one. Where the high bit of r is clear, DER
    spends no leading zero octet on it and the encoding is one octet
    shorter -- which is the whole of the benefit, and why this is a
    signer's policy rather than an operation of the curve.

    What an attempt is asked is `_is_low_r_`, which is the question
    `is_low_r` answers for a caller and is written once for both. It
    serializes per attempt where a compact buffer kept by this loop
    would be written into, and that costs about 0.2 microseconds of the
    24.8 a ground signature takes -- the two loops alternated in one
    process, three runs putting the difference between 0.13 and 0.31,
    against a noise row that runs the same loop twice and moves 0.1.
    What it buys is that the predicate a caller can check a signature
    against is the predicate this loop ground to.

    The entropy buffer is the one thing held across attempts, and it is
    allocated per call rather than at module level: a package with one
    shared context and a documented thread-safety story does not get to
    hold scratch memory anywhere a second thread can reach it.

    Args:
        signature: the signature of the first attempt, signed over in
            place until its r is the low one.
        msg_bytes: the 32-byte hash of the message, already checked.
        prvkey_bytes: the 32-byte private key, already checked.

    Raises:
        RuntimeError: propagated from `_is_low_r_`, which serializes
            every attempt in order to read the top octet of r; a
            signature libsecp256k1 has just made cannot make it fail.
    """
    # the counter goes in the first 4 octets and the other 28 stay zero,
    # so the buffer is written into rather than rebuilt
    entropy = ffi.new("unsigned char[32]")
    counter = 0
    while not _is_low_r_(signature):
        counter += 1
        entropy[0:4] = counter.to_bytes(4, "little")
        _signed(signature, msg_bytes, prvkey_bytes, entropy)


def _sign_(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    grind: bool = False,
    *,
    verify: bool = True,
) -> CData:
    """Create an ECDSA signature, as the parsed signature.

    The private half of `sign`, and the one that answers with the object
    rather than with its DER encoding: see the package docstring for what
    the two underscores mean throughout. A signer wanting the compact
    form is this and `serialize_compact`, where `sign` and `to_compact`
    are a DER serialization and a parse of what was just serialized.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone.
        grind: whether to sign again until r is the low one, as `sign`
            documents. Not with aux_rand32: the two write the same 32
            octets, so asking for both is refused rather than resolved
            here.
        verify: whether to check the signature under the public key of
            the key that made it before answering with it, as `sign`
            documents. Where `grind` asks too, what is checked is the
            signature the grinding settled on: the attempts it discarded
            are never answered with, so a fault in one of them is a
            wasted attempt rather than a published signature.

    Returns:
        The libsecp256k1 signature object, in the lower-s form
        libsecp256k1 always produces.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, if aux_rand32 and grind are given
            together, or if the private key is not 32 bytes, does not fit
            in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize an attempt while
            grinding, which a signature it has just made cannot do, or if
            `verify` asks and the signature does not verify.
    """
    prvkey_bytes = scalar(prvkey, "private key")
    msg_bytes = octets(msg_bytes, "message hash", 32)
    if grind and aux_rand32 is not None:
        raise ValueError("aux_rand32 and grind are the same 32 octets")

    signature = ffi.new("secp256k1_ecdsa_signature *")
    _signed(signature, msg_bytes, prvkey_bytes, optional_entropy(aux_rand32))
    if grind:
        _grind(signature, msg_bytes, prvkey_bytes)
    if verify:
        # through `_verify_` and `keys._pubkey_from_prvkey_` rather than
        # through the two public halves, which would serialize this
        # signature into DER and the point into octets only to parse both
        # straight back -- and for a compressed key that parse is a field
        # square root. `normalize` is not passed: libsecp256k1 has just
        # answered the lower-s form, so there is nothing to normalize
        pubkey = keys._pubkey_from_prvkey_(prvkey_bytes)
        if not _verify_(msg_bytes, pubkey, signature):
            raise RuntimeError("signing produced a signature that does not verify")
    return signature


# six arguments, where PLR0913 allows five. The alternative is an options
# object, and it would be one for this function alone: `aux_rand32`,
# `compact` and `grind` are ECDSA's own three questions, `verify` is the
# fourth these bindings add, and none of the four is a group with either
# of the others. `verify` is keyword-only, as the two before it should
# have been, so what a call site actually carries is named
def sign(  # noqa: PLR0913
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    compact: bool = False,
    grind: bool = False,
    *,
    verify: bool = True,
) -> bytes:
    """Create an ECDSA signature.

    The nonce is the deterministic RFC6979 one, so the signature is a
    function of the message and the key alone unless aux_rand32 is given.

    Which serialization to answer with is the caller's, as it is
    everywhere a key is answered: a signature is `r` and `s`, and DER is
    what the wire carries rather than what a caller holds. Asking for the
    compact form is `serialize_compact` in place of `serialize_der`, where
    reaching it through `to_compact` is that DER encoding parsed straight
    back apart.

    `grind` is the one thing here that is more than a libsecp256k1 call,
    and it is Bitcoin Core's `CKey::Sign` scheme rather than an invention
    of this package: signing again, with a counter mixed into the nonce,
    until r has its high bit clear and DER therefore spends no leading
    zero octet on it. It costs what the octet is worth -- two signatures
    on average, and the tail is longer than that -- so it is asked for
    and never done by default. `s` is not ground for and could not be:
    libsecp256k1 has already returned the lower of the two.

    `verify` is the second thing beyond a libsecp256k1 call, and it is
    the other half of that same `CKey::Sign`: the signature is checked
    under the public key of the very key that made it, and one that
    fails is never answered with. What it catches is not a bad argument
    -- those have all raised by then -- but a computation that went
    wrong, a bit flipped in memory or a fault induced on purpose, whose
    cost is a published signature that is invalid and may say something
    about the key. It is the one argument here that is on by default,
    and the asymmetry with `grind` is the point: grinding buys an octet
    of DER, this buys the guarantee that what was answered is a
    signature. Core pays it on every signature and offers no way not to;
    here there is one, because the check is a point multiplication and a
    verification and the caller who has measured that against its own
    threat model is the one entitled to refuse it -- `ssa.sign` refuses
    it more cheaply, BIP340 needing the public key to sign at all where
    ECDSA needs it for neither of the two things `sign` does.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone. Never a shorter value:
            entropy is not a serialization, and padding one would make a
            caller mistake a valid argument.
        compact: whether to answer the 64-byte `r || s` rather than DER.
        grind: whether to sign again until r is the low one. Refused
            together with aux_rand32: grinding is written into those very
            32 octets, so a caller asking for both is asking for two
            different values of one argument, and Core's counter is what
            makes the result reproducible by anyone else.
        verify: whether to check the signature under the public key of
            the key that made it before returning it. It costs a point
            multiplication and a verification, and False is what a
            caller that has measured those against its own threat model
            passes.

    Returns:
        The signature, in the lower-s form libsecp256k1 always produces:
        DER, or the 64 octets of `r || s` where `compact` asks for them.
        Where `grind` asks for it, of the low r as well.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, if aux_rand32 and grind are given
            together, or if the private key is not 32 bytes, does not fit
            in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the signature,
            which no input can make it do.

    Example:
        >>> import hashlib
        >>> from btclib_secp256k1 import dsa
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.is_low_s(dsa.sign(msg, 1))
        True
        >>> dsa.sign(msg, 1, grind=True, compact=True)[0] < 0x80
        True
    """
    # composed, where `verify` below is spelled out: the frames this
    # would save were measured and are not there. Shipped against a
    # spelling with `_sign_` inlined, with the DER serialization inlined,
    # and with both, alternated in one process over 9 rounds of 20 000
    # calls -- an Apple M5, macOS 26.6, arm64, CPython 3.13.14 -- all
    # three land within 0.03 microseconds of this one and on the wrong
    # side of it. A signature is 11.9 microseconds of libsecp256k1, and
    # two python frames do not show against it
    signature = _sign_(msg_bytes, prvkey, aux_rand32, grind, verify=verify)
    return serialize_compact(signature) if compact else serialize_der(signature)


def _verify_(
    msg_bytes: BytesLike,
    pubkey: CData,
    signature: CData,
    normalize: bool = False,
) -> bool:
    """Verify an ECDSA signature against an already-parsed key and signature.

    The private half of `verify`, for a caller who already holds both --
    one that validated the key before verifying with it, one checking
    several signatures against the same key, or one that has just asked
    `_is_low_s_` about the signature: see the package docstring for what
    the two underscores mean throughout. For a compressed key that parse
    is a field square root, which is a measurable part of the
    verification it precedes rather than a rounding error.

    Args:
        msg_bytes: the 32-byte hash of the message.
        pubkey: the already-parsed public key, as `keys.parse` returns.
        signature: the already-parsed signature, as `parse_der` and
            `parse_compact` return. Mutated in place where `normalize`
            asks for it.
        normalize: whether to verify the lower-s form of the signature
            rather than reject a signature that is not in it.

    Returns:
        True if the signature is valid for that key and message -- and
        False where libsecp256k1 could not read one of the two objects,
        which is the same answer it gives a signature that simply does
        not verify. This raises nothing for it: a caller passing objects
        of its own is the one that can be handed an unreadable one, and
        `context.check` immediately after the call is what says the
        False is not a verdict. `verify` parses both from octets and so
        has no such case.

    Raises:
        ValueError: if the message hash is not 32 bytes.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)
    if normalize:
        _normalize_(signature)
    verified = lib.secp256k1_ecdsa_verify(ctx, signature, msg_bytes, pubkey)
    return bool(verified)


def verify(
    msg_bytes: BytesLike,
    pubkey_bytes: BytesLike,
    signature_bytes: BytesLike,
    normalize: bool = False,
    compact: bool = False,
) -> bool:
    """Verify a ECDSA signature.

    A signature which is not in the normalized lower-s form is rejected,
    unless `normalize` is set: which of the two forms a signature carries
    was the signer's choice, so a caller checking signatures it did not
    make normalizes rather than refuses, and says so here rather than
    round-tripping the signature through `normalize` and back into DER.
    The default is the refusal, that being what a caller enforcing the
    lower-s form of its own signatures wants.

    Args:
        msg_bytes: the 32-byte hash of the message.
        pubkey_bytes: the public key, 33 or 65 bytes.
        signature_bytes: the signature, DER encoded or the 64 octets of
            `r || s`, as `compact` says.
        normalize: whether to verify the lower-s form of the signature
            rather than reject a signature that is not in it.
        compact: whether the signature is the 64-byte `r || s` rather
            than DER. Which of the two it is has to be said and cannot be
            read off the length: a DER signature of 64 octets exists,
            `r` and `s` of 29 bytes each, and it begins with the 0x30 a
            compact `r` may begin with too.

    Returns:
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the message hash is not 32 bytes, if the signature
            is malformed in the serialization it was said to be in, or if
            the public key is not a valid point. A well-formed signature
            that simply does not verify is False, not an exception.

    Example:
        >>> import hashlib
        >>> from btclib_secp256k1 import dsa, keys
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.verify(msg, keys.pubkey_from_prvkey(1), dsa.sign(msg, 1))
        True
    """
    # spelled out rather than composed of `keys.parse`, a `parse_` and
    # `_verify_`: those frames are 0.035 microseconds of the 11.813 this
    # call costs -- an Apple M5, macOS 26.6, arm64, CPython 3.13.14, the
    # two spellings alternated in one process over 7 rounds of 20 000
    # calls, minimum kept for each. `_verify_` makes the same calls for a
    # caller holding both objects, and tests/test_parsed_keys.py asserts
    # the two answer alike
    pubkey_bytes = octets(pubkey_bytes, "public key")
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    signature = _parsed(signature_bytes, compact)
    if signature is None:
        raise ValueError(
            "invalid compact signature" if compact else "invalid DER signature"
        )
    if normalize:
        _normalize_(signature)

    msg_bytes = octets(msg_bytes, "message hash", 32)
    return bool(lib.secp256k1_ecdsa_verify(ctx, signature, msg_bytes, pubkey))


def _normalize_(signature: CData) -> CData:
    """Convert an already-parsed signature to its lower-s form.

    The private half of `normalize`, for a caller who already holds the
    parsed signature: see the package docstring for what the two
    underscores mean throughout. Normalizing in order to verify is
    `_verify_(..., normalize=True)`, which is this call inside that one.

    Args:
        signature: the already-parsed signature, as `parse_der` and
            `parse_compact` return. Mutated in place.

    Returns:
        The same object passed in, with s replaced by n - s where s was
        the higher of the two. A signature already normalized is left as
        it is, and so is one libsecp256k1 cannot read: this raises
        nothing, and `context.check` immediately after the call is what
        says which of the two happened.
    """
    # libsecp256k1 takes the same object as input and output here,
    # documenting sigout == sigin. The return value says whether
    # anything was changed, which is what `_is_low_s_` asks and this
    # does not
    lib.secp256k1_ecdsa_signature_normalize(ctx, signature, signature)
    return signature


def normalize(signature_bytes: BytesLike) -> bytes:
    """Convert a DER signature to its normalized lower-s form.

    This is for a caller that needs the normalized bytes -- storing them,
    forwarding them, comparing them. Normalizing in order to verify is
    `verify(..., normalize=True)` instead, which is the same
    normalization without the serialization and the second parse between
    it and the verification.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        The same signature with s replaced by n - s where s was the
        higher of the two, in DER encoding. A signature already
        normalized is returned unchanged.

    Raises:
        ValueError: if the DER signature is malformed.
        RuntimeError: if libsecp256k1 fails to serialize the result,
            which no input can make it do.
    """
    return serialize_der(_normalize_(parse_der(signature_bytes)))


def _is_low_s_(signature: CData) -> bool:
    """Return True if an already-parsed signature is in the lower-s form.

    The private half of `is_low_s`, for a caller who already holds the
    parsed signature -- one about to verify it, `_verify_` taking the
    same object: see the package docstring for what the two underscores
    mean throughout.

    Args:
        signature: the already-parsed signature, as `parse_der` and
            `parse_compact` return. Not mutated: this asks.

    Returns:
        True if s is the lower of the two -- and True, too, for an
        object libsecp256k1 cannot read, which it reports as unchanged
        exactly as it reports an already-normalized signature. This
        raises nothing, and `context.check` immediately after the call
        is what separates them. `is_low_s` parses its octets and so has
        no such case.
    """
    # a NULL output only checks the input, which is reported as
    # not normalized by a return value of 1
    changed = lib.secp256k1_ecdsa_signature_normalize(ctx, ffi.NULL, signature)
    return not changed


def is_low_s(signature_bytes: BytesLike) -> bool:
    """Return True if the DER signature is in the normalized lower-s form.

    ECDSA signatures are malleable: negating s modulo the group order
    yields a second valid signature of the same message, which the
    lower-s requirement rules out.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        True if s is the lower of the two, which is what `verify`
        requires and what `sign` always produces.

    Raises:
        ValueError: if the DER signature is malformed.
    """
    return _is_low_s_(parse_der(signature_bytes))


def _is_low_r_(signature: CData) -> bool:
    """Return True if an already-parsed signature has the low r.

    The private half of `is_low_r`, for a caller who already holds the
    parsed signature, and the question `_grind` asks of every attempt it
    makes: see the package docstring for what the two underscores mean
    throughout.

    It is a serialization and a comparison rather than a libsecp256k1
    call of its own, there being none that answers this: `r` is the
    first 32 octets of the compact form, big endian, so its leading
    octet is the one DER would have to put a zero in front of. Reading
    it out of the opaque signature object instead is not open to
    anybody -- those 64 octets are internal scalar representation, in
    the limb order of whatever built the library.

    Args:
        signature: the already-parsed signature, as `parse_der` and
            `parse_compact` return. Not mutated: this asks.

    Returns:
        True if the high bit of r is clear, which is the form
        `sign(grind=True)` produces and the one Bitcoin Core's
        `SigHasLowR` reads.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails to serialize it for any other
            reason; `serialize_compact` is where that is said, and
            `context.check` is what tells the two apart. Unlike
            `_is_low_s_`, an unreadable object does not get an answer
            here: a serialization that did not happen leaves no octet to
            read.
    """
    return serialize_compact(signature)[0] < 0x80


def is_low_r(signature_bytes: BytesLike) -> bool:
    """Return True if the DER signature has the low r.

    Not a rule of ECDSA, unlike `is_low_s`, and not something `verify`
    asks: a high-r signature is valid and always was. It is a size
    policy, and what it says is that this signature is one octet shorter
    in DER than it might have been -- which is what a caller enforcing
    it on its own signatures, or measuring how many of somebody else's
    carry it, is asking about. `sign(grind=True)` is how one is made.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        True if the high bit of r is clear.

    Raises:
        ValueError: if the DER signature is malformed.
        RuntimeError: if libsecp256k1 fails to serialize it, which no
            signature it parsed can make it do.

    Example:
        >>> import hashlib
        >>> from btclib_secp256k1 import dsa
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.is_low_r(dsa.sign(msg, 1, grind=True))
        True
    """
    return _is_low_r_(parse_der(signature_bytes))


def to_compact(signature_bytes: BytesLike) -> bytes:
    """Convert a DER signature into its 64-byte compact form.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        The 64 bytes of r and s, each big endian and zero padded.

    Raises:
        ValueError: if the DER signature is malformed.
        RuntimeError: if libsecp256k1 fails to serialize it, which no
            input can make it do.
    """
    return serialize_compact(parse_der(signature_bytes))


def to_der(signature_bytes: BytesLike) -> bytes:
    """Convert a 64-byte compact signature into its DER form.

    Args:
        signature_bytes: the 64 bytes of r and s.

    Returns:
        The same signature in DER encoding. s is not normalized: a
        high-s input gives a DER signature `verify` refuses, which
        `normalize` is for.

    Raises:
        ValueError: if the input is not 64 bytes, or if r or s is not
            below the group order.
        RuntimeError: if libsecp256k1 fails to serialize it, which no
            input can make it do.
    """
    return serialize_der(parse_compact(signature_bytes))


def parse_der(signature_bytes: BytesLike) -> CData:
    """Parse a DER signature into its internal representation.

    What `keys.parse` is to a public key, and the argument of every
    private half here: `serialize_der` is what turns it back into bytes,
    and `parse_compact` reads the other serialization into the same
    object.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        The libsecp256k1 signature object.

    Raises:
        ValueError: if the DER signature is malformed.
    """
    signature = _parsed(signature_bytes, compact=False)
    if signature is None:
        raise ValueError("invalid DER signature")
    return signature


def parse_compact(signature_bytes: BytesLike) -> CData:
    """Parse a 64-byte compact signature into its internal representation.

    The other way into the object `parse_der` answers with, and the
    cheaper one: there is no encoding to walk, only two scalars to prove
    below the group order.

    Args:
        signature_bytes: the 64 bytes of r and s.

    Returns:
        The libsecp256k1 signature object. s is not normalized, which is
        what `_is_low_s_` asks and `_normalize_` changes.

    Raises:
        ValueError: if the input is not 64 bytes, or if r or s is not
            below the group order.
    """
    signature = _parsed(signature_bytes, compact=True)
    if signature is None:
        raise ValueError("invalid compact signature")
    return signature


def _parsed(signature_bytes: BytesLike, compact: bool) -> CData | None:
    """Parse a signature, answering None where it is not one.

    The parse both serializations reach, and the one thing to do with a
    signature that is not a signature: `parse_der` and `parse_compact`
    raise where this answers None, `signature_verify` answers the verdict.
    Written twice, the two would be one call each until a check moved in
    one of them -- `keys._parsed` is the same helper for a public key,
    and says what it costs.

    The length is part of what a compact signature is, and is refused
    like the rest of it: `secp256k1_ecdsa_signature_parse_compact` takes
    a bare pointer to 64 octets, so it is python that has to count them,
    and answering False for 63 is what `keys.pubkey_verify` answers for a
    key of 34. The DER parse is given the length instead, that encoding
    carrying its own.

    Args:
        signature_bytes: the signature, in the serialization below.
        compact: whether it is the 64 octets of `r || s` rather than DER.

    Returns:
        The libsecp256k1 signature object, or None if the octets are not
        a signature in that serialization.

    Raises:
        TypeError: if the value is not bytes, which is a malformed
            argument rather than a signature that fails to parse.
    """
    name = "compact signature" if compact else "DER signature"
    signature_bytes = octets(signature_bytes, name)
    signature = ffi.new("secp256k1_ecdsa_signature *")
    if compact:
        if len(signature_bytes) != _COMPACT_SIZE:
            return None
        parsed = lib.secp256k1_ecdsa_signature_parse_compact(
            ctx, signature, signature_bytes
        )
    else:
        parsed = lib.secp256k1_ecdsa_signature_parse_der(
            ctx, signature, signature_bytes, len(signature_bytes)
        )
    return signature if parsed else None


def signature_verify(signature_bytes: BytesLike, compact: bool = False) -> bool:
    """Return True if the octets are a signature libsecp256k1 accepts.

    What `keys.pubkey_verify` is to a public key: the proof a `parse`
    makes, with nothing kept and no exception to catch. A library
    validating an input at its own boundary has this; what the octets are
    wrong about is its own to phrase.

    It says nothing about a message or a key, `verify` being that
    question, and nothing about the lower-s form, which is `is_low_s`: a
    signature is `r` and `s` below the group order, and that is what this
    answers for.

    Args:
        signature_bytes: the signature, in the serialization below.
        compact: whether it is the 64 octets of `r || s` rather than DER,
            which cannot be read off the length: see `verify`.

    Returns:
        True if the octets are a signature in that serialization; False
        for octets of any other length too, as `keys.pubkey_verify`
        answers for a key.

    Raises:
        TypeError: if the value is not bytes at all, which is a malformed
            argument and not a signature to have a verdict on.

    Example:
        >>> from btclib_secp256k1 import dsa
        >>> dsa.signature_verify(dsa.sign(bytes(32), 1))
        True
        >>> dsa.signature_verify(bytes.fromhex("3006"))
        False
    """
    return _parsed(signature_bytes, compact) is not None


def serialize_der(signature: CData) -> bytes:
    """Serialize an internal signature in DER form.

    Args:
        signature: the libsecp256k1 signature object, as `parse_der` and
            `parse_compact` return.

    Returns:
        Its DER encoding, at most 72 bytes.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails for any other reason, which the
            72-byte buffer makes unreachable. `context.check` is what
            tells the two apart.
    """
    # the length passed in is `ffi.sizeof` of the buffer's own type, so
    # the two cannot drift apart -- the top of this module says where 72
    # comes from and why it is the one width not spelled as an int -- and
    # what comes out is what libsecp256k1 says it wrote, this being the
    # one serialization here whose length varies, 70 to 72 depending on
    # how many octets r and s need. Where the length is fixed the width
    # itself is unpacked instead, and keys.serialize says why.
    #
    # The length *object* is built per call and not hoisted, for the
    # thread-safety reason keys.serialize gives: libsecp256k1 writes 0
    # into it before it does anything and a shared one left at zero would
    # refuse every later serialization
    sig_bytes = ffi.new(_DER_BUFFER_TYPE)
    length = ffi.new("size_t *", _DER_SIZE)
    serialized = lib.secp256k1_ecdsa_signature_serialize_der(
        ctx, sig_bytes, length, signature
    )
    if not serialized:
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, length[0])


def serialize_compact(signature: CData) -> bytes:
    """Serialize an internal signature in its 64-byte compact form.

    Args:
        signature: the libsecp256k1 signature object, as `parse_der` and
            `parse_compact` return.

    Returns:
        The 64 bytes of r and s, each big endian and zero padded.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails for any other reason, which a
            signature it parsed cannot make it do. `context.check` is
            what tells the two apart.
    """
    sig_bytes = ffi.new(_COMPACT_BUFFER_TYPE)
    serialized = lib.secp256k1_ecdsa_signature_serialize_compact(
        ctx, sig_bytes, signature
    )
    if not serialized:
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, _COMPACT_SIZE)

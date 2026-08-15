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
`normalize`, `is_low_s`, `to_der` and `to_compact` each parse and
serialize one of their own.
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, keys, lib
from ._scalar import octets, optional_entropy, scalar
from .context import ctx, guarded


def _sign_(
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
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

    Returns:
        The libsecp256k1 signature object, in the lower-s form
        libsecp256k1 always produces.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
    """
    prvkey_bytes = scalar(prvkey, "private key")
    msg_bytes = octets(msg_bytes, "message hash", 32)

    signature = ffi.new("secp256k1_ecdsa_signature *")

    # secp256k1_ecdsa_sign takes the nonce function and its data: NULL
    # for the first selects the RFC6979 default, and it is the only one
    # these bindings pass -- a python nonce function would be called from
    # inside the signature, with the secret passing through a python
    # object on every call. The contribution beside it is 32 bytes of
    # entropy, and `optional_entropy` says what omitting it means here
    noncefp = ffi.NULL
    if not lib.secp256k1_ecdsa_sign(
        ctx,
        signature,
        msg_bytes,
        prvkey_bytes,
        noncefp,
        optional_entropy(aux_rand32),
    ):
        raise ValueError("invalid private key: not in [1, n-1]")
    return signature


def sign(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    compact: bool = False,
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

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone. Never a shorter value:
            entropy is not a serialization, and padding one would make a
            caller mistake a valid argument.
        compact: whether to answer the 64-byte `r || s` rather than DER.

    Returns:
        The signature, in the lower-s form libsecp256k1 always produces:
        DER, or the 64 octets of `r || s` where `compact` asks for them.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the signature,
            which no input can make it do.

    Example:
        >>> import hashlib
        >>> from btclib_secp256k1 import dsa
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.is_low_s(dsa.sign(msg, 1))
        True
    """
    signature = _sign_(msg_bytes, prvkey, aux_rand32)
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
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the message hash is not 32 bytes, or if either
            object is not one libsecp256k1 will read; see
            `context.guarded`, without which an unreadable key would
            answer False, which is a verdict a caller would believe.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)
    if normalize:
        _normalize_(signature)
    with guarded():
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
        >>> from btclib_secp256k1 import dsa, mult
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.verify(msg, mult.mult_bytes(1), dsa.sign(msg, 1))
        True
    """
    parse = parse_compact if compact else parse_der
    return _verify_(
        msg_bytes, keys.parse(pubkey_bytes), parse(signature_bytes), normalize
    )


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
        it is.

    Raises:
        ValueError: if the object is not a signature libsecp256k1 will
            read; see `context.guarded`.
    """
    # libsecp256k1 takes the same object as input and output here,
    # documenting sigout == sigin. The return value says whether
    # anything was changed, which is what `_is_low_s_` asks and this
    # does not
    with guarded():
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
        True if s is the lower of the two.

    Raises:
        ValueError: if the object is not a signature libsecp256k1 will
            read; see `context.guarded`.
    """
    # a NULL output only checks the input, which is reported as
    # not normalized by a return value of 1
    with guarded():
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
    signature_bytes = octets(signature_bytes, "DER signature")
    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_der(
        ctx, signature, signature_bytes, len(signature_bytes)
    ):
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
    signature_bytes = octets(signature_bytes, "compact signature", 64)

    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_compact(ctx, signature, signature_bytes):
        raise ValueError("invalid compact signature")
    return signature


def serialize_der(signature: CData) -> bytes:
    """Serialize an internal signature in DER form.

    Args:
        signature: the libsecp256k1 signature object, as `parse_der` and
            `parse_compact` return.

    Returns:
        Its DER encoding, at most 72 bytes.

    Raises:
        ValueError: if the object is not a signature libsecp256k1 will
            read; see `context.guarded`.
        RuntimeError: if libsecp256k1 fails for any other reason, which
            the 72-byte buffer makes unreachable.
    """
    # 72 is the maximum a signature of this curve can encode to, and it
    # is structural rather than generous: secp256k1_ecdsa_sig_serialize
    # writes 6 + lenR + lenS, and each of those is at most 33 -- 32
    # octets of scalar and the leading zero DER wants when the top bit
    # is set. `to_der` reaches it, a high-s signature being one it
    # serializes rather than refuses.
    #
    # The number is written once and the rest is derived from it: the
    # length passed in is the buffer's own size, so the two cannot drift
    # apart, and what comes out is what libsecp256k1 says it wrote --
    # this being the one serialization here whose length varies, 70 to 72
    # depending on how many octets r and s need. Where the length is
    # fixed the buffer is unpacked instead, and keys.serialize says why
    sig_bytes = ffi.new("char[72]")
    length = ffi.new("size_t *", ffi.sizeof(sig_bytes))
    with guarded():
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
        ValueError: if the object is not a signature libsecp256k1 will
            read; see `context.guarded`.
        RuntimeError: if libsecp256k1 fails for any other reason, which
            a signature it parsed cannot make it do.
    """
    sig_bytes = ffi.new("char[64]")
    with guarded():
        serialized = lib.secp256k1_ecdsa_signature_serialize_compact(
            ctx, sig_bytes, signature
        )
    if not serialized:
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, ffi.sizeof(sig_bytes))

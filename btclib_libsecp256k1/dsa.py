# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Digital Signature Algorithm (ECDSA)."""

from __future__ import annotations

from . import CData, ffi, lib
from ._scalar import octets, scalar
from .context import ctx


def sign(msg_bytes: bytes, prvkey: bytes | int, ndata: bytes | None = None) -> bytes:
    """Create an ECDSA signature.

    The nonce is the deterministic RFC6979 one, so the signature is a
    function of the message and the key alone unless ndata is given.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        ndata: 32 bytes of extra entropy mixed into the nonce, or None
            for the RFC6979 nonce alone. Never a shorter value: entropy
            is not a serialization, and padding one would make a caller
            mistake a valid argument.

    Returns:
        The signature in DER encoding, in the lower-s form libsecp256k1
        always produces.

    Raises:
        ValueError: if the message hash is not 32 bytes, if ndata is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the signature,
            which no input can make it do.

    Example:
        >>> import hashlib
        >>> from btclib_libsecp256k1 import dsa
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.is_low_s(dsa.sign(msg, 1))
        True
    """
    prvkey_bytes = scalar(prvkey, "private key")
    octets(msg_bytes, "message hash", 32)

    sig = ffi.new("secp256k1_ecdsa_signature *")

    noncefc = ffi.NULL
    # the nonce contribution is 32 bytes of entropy, not a serialization:
    # a shorter value is a caller mistake rather than a small number, and
    # padding it here would turn one into a valid argument. Omitted, the
    # nonce is the RFC6979 one alone
    if ndata is None:
        ndata = ffi.NULL
    else:
        octets(ndata, "ndata", 32)
    if not lib.secp256k1_ecdsa_sign(ctx, sig, msg_bytes, prvkey_bytes, noncefc, ndata):
        raise ValueError("invalid private key")
    return _serialize_der(sig)


def verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify a ECDSA signature.

    A signature which is not in the normalized lower-s form is rejected;
    normalize it first if it comes from a system not enforcing it.

    Args:
        msg_bytes: the 32-byte hash of the message.
        pubkey_bytes: the public key, 33 or 65 bytes.
        signature_bytes: the signature in DER encoding.

    Returns:
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the message hash is not 32 bytes, if the DER
            signature is malformed, or if the public key is not a valid
            point. A well-formed signature that simply does not verify
            is False, not an exception.

    Example:
        >>> import hashlib
        >>> from btclib_libsecp256k1 import dsa, mult
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> dsa.verify(msg, mult.mult_(1), dsa.sign(msg, 1))
        True
    """
    octets(msg_bytes, "message hash", 32)

    signature = _parse_der(signature_bytes)

    octets(pubkey_bytes, "public key")
    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    return bool(lib.secp256k1_ecdsa_verify(ctx, signature, msg_bytes, pubkey))


def normalize(signature_bytes: bytes) -> bytes:
    """Convert a DER signature to its normalized lower-s form.

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
    signature = _parse_der(signature_bytes)
    normalized = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_signature_normalize(ctx, normalized, signature)
    return _serialize_der(normalized)


def is_low_s(signature_bytes: bytes) -> bool:
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
    signature = _parse_der(signature_bytes)
    # a NULL output only checks the input, which is reported as
    # not normalized by a return value of 1
    return not lib.secp256k1_ecdsa_signature_normalize(ctx, ffi.NULL, signature)


def to_compact(signature_bytes: bytes) -> bytes:
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
    signature = _parse_der(signature_bytes)
    sig_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ecdsa_signature_serialize_compact(ctx, sig_bytes, signature):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, ffi.sizeof(sig_bytes))


def to_der(signature_bytes: bytes) -> bytes:
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
    octets(signature_bytes, "compact signature", 64)

    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_compact(ctx, signature, signature_bytes):
        raise ValueError("invalid compact signature")
    return _serialize_der(signature)


def _parse_der(signature_bytes: bytes) -> CData:
    """Parse a DER signature into its internal representation.

    Args:
        signature_bytes: the signature in DER encoding.

    Returns:
        The libsecp256k1 signature object.

    Raises:
        ValueError: if the DER signature is malformed.
    """
    octets(signature_bytes, "DER signature")
    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_der(
        ctx, signature, signature_bytes, len(signature_bytes)
    ):
        raise ValueError("invalid DER signature")
    return signature


def _serialize_der(sig: CData) -> bytes:
    """Serialize an internal signature in DER form.

    Args:
        sig: the libsecp256k1 signature object.

    Returns:
        Its DER encoding, at most 72 bytes.

    Raises:
        RuntimeError: if libsecp256k1 fails, which the 72-byte buffer
            makes unreachable.
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
    if not lib.secp256k1_ecdsa_signature_serialize_der(ctx, sig_bytes, length, sig):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, length[0])

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic Curve Digital Signature Algorithm (ECDSA)."""

from __future__ import annotations

from . import CData, ffi, lib
from ._scalar import scalar
from .context import ctx


def sign(msg_bytes: bytes, prvkey: bytes | int, ndata: bytes | None = None) -> bytes:
    """Create an ECDSA signature."""

    prvkey_bytes = scalar(prvkey, "private key")
    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")

    sig = ffi.new("secp256k1_ecdsa_signature *")

    noncefc = ffi.NULL
    if ndata:
        if len(ndata) > 32:
            raise ValueError("ndata must be at most 32 bytes")
        ndata = b"\x00" * (32 - len(ndata)) + ndata
    else:
        ndata = ffi.NULL
    if not lib.secp256k1_ecdsa_sign(ctx, sig, msg_bytes, prvkey_bytes, noncefc, ndata):
        raise ValueError("invalid private key")
    return _serialize_der(sig)


def verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify a ECDSA signature.

    A signature which is not in the normalized lower-s form is rejected;
    normalize it first if it comes from a system not enforcing it.
    """

    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")

    signature = _parse_der(signature_bytes)

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ec_pubkey_parse(ctx, pubkey, pubkey_bytes, len(pubkey_bytes)):
        raise ValueError("invalid public key")

    return bool(lib.secp256k1_ecdsa_verify(ctx, signature, msg_bytes, pubkey))


def normalize(signature_bytes: bytes) -> bytes:
    """Convert a DER signature to its normalized lower-s form."""

    signature = _parse_der(signature_bytes)
    normalized = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_signature_normalize(ctx, normalized, signature)
    return _serialize_der(normalized)


def is_low_s(signature_bytes: bytes) -> bool:
    """Return True if the DER signature is in the normalized lower-s form.

    ECDSA signatures are malleable: negating s modulo the group order
    yields a second valid signature of the same message, which the
    lower-s requirement rules out.
    """

    signature = _parse_der(signature_bytes)
    # a NULL output only checks the input, which is reported as
    # not normalized by a return value of 1
    return not lib.secp256k1_ecdsa_signature_normalize(ctx, ffi.NULL, signature)


def to_compact(signature_bytes: bytes) -> bytes:
    """Convert a DER signature into its 64-byte compact form."""

    signature = _parse_der(signature_bytes)
    sig_bytes = ffi.new("char[64]")
    if not lib.secp256k1_ecdsa_signature_serialize_compact(ctx, sig_bytes, signature):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, 64)


def to_der(signature_bytes: bytes) -> bytes:
    """Convert a 64-byte compact signature into its DER form."""

    if len(signature_bytes) != 64:
        raise ValueError("the compact signature must be 64 bytes")

    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_compact(ctx, signature, signature_bytes):
        raise ValueError("invalid compact signature")
    return _serialize_der(signature)


def _parse_der(signature_bytes: bytes) -> CData:
    """Parse a DER signature into its internal representation."""

    signature = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_signature_parse_der(
        ctx, signature, signature_bytes, len(signature_bytes)
    ):
        raise ValueError("invalid DER signature")
    return signature


def _serialize_der(sig: CData) -> bytes:
    """Serialize an internal signature in DER form."""

    sig_bytes = ffi.new("char[73]")
    length = ffi.new("size_t *", 73)
    if not lib.secp256k1_ecdsa_signature_serialize_der(ctx, sig_bytes, length, sig):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, length[0])

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""ECDSA public key recovery."""
from __future__ import annotations

from . import ffi, lib
from .context import ctx

# SECP256K1_EC_COMPRESSED: the libsecp256k1 flag macros do not survive
# the preprocessing of the headers into cffi definitions
COMPRESSED = 258


def sign(
    msg_bytes: bytes, prvkey: bytes | int, ndata: bytes | None = None
) -> tuple[bytes, int]:
    """Create a recoverable ECDSA signature.

    Return the 64-byte compact signature and its recovery id.
    """

    if isinstance(prvkey, int):
        prvkey_bytes = prvkey.to_bytes(32, "big")
    else:
        prvkey_bytes = prvkey
    if len(prvkey_bytes) != 32:
        raise ValueError("the private key must be 32 bytes")
    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")

    sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")

    noncefc = ffi.NULL
    if ndata:
        if len(ndata) > 32:
            raise ValueError("ndata must be at most 32 bytes")
        ndata = b"\x00" * (32 - len(ndata)) + ndata
    else:
        ndata = ffi.NULL
    if not lib.secp256k1_ecdsa_sign_recoverable(
        ctx, sig, msg_bytes, prvkey_bytes, noncefc, ndata
    ):
        raise ValueError("invalid private key")

    sig_bytes = ffi.new("char[64]")
    recid = ffi.new("int *")
    if not lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, sig_bytes, recid, sig
    ):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, 64), recid[0]


def recover(msg_bytes: bytes, signature_bytes: bytes, recid: int) -> bytes:
    """Recover the compressed public key from a recoverable ECDSA signature."""

    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")
    if len(signature_bytes) != 64:
        raise ValueError("the signature must be 64 bytes")
    if recid not in (0, 1, 2, 3):
        raise ValueError("the recovery id must be 0, 1, 2, or 3")

    signature = _parse(signature_bytes, recid)

    pubkey = ffi.new("secp256k1_pubkey *")
    if not lib.secp256k1_ecdsa_recover(ctx, pubkey, signature, msg_bytes):
        raise ValueError("public key recovery failed")

    output = ffi.new("char[33]")
    length = ffi.new("size_t *", 33)
    if not lib.secp256k1_ec_pubkey_serialize(ctx, output, length, pubkey, COMPRESSED):
        raise RuntimeError("point serialization failed")
    return ffi.unpack(output, 33)


def to_der(signature_bytes: bytes, recid: int) -> bytes:
    """Convert a recoverable signature into a plain DER signature.

    The recovery id is dropped, as it is not part of the DER encoding.
    Beware: the conversion does not normalize the signature, so a
    high-s input is rejected by dsa.verify; signatures produced by
    sign are always low-s.
    """

    if len(signature_bytes) != 64:
        raise ValueError("the signature must be 64 bytes")
    if recid not in (0, 1, 2, 3):
        raise ValueError("the recovery id must be 0, 1, 2, or 3")

    signature = _parse(signature_bytes, recid)

    dsa_sig = ffi.new("secp256k1_ecdsa_signature *")
    if not lib.secp256k1_ecdsa_recoverable_signature_convert(ctx, dsa_sig, signature):
        raise RuntimeError("signature conversion failed")

    sig_bytes = ffi.new("char[73]")
    length = ffi.new("size_t *", 73)
    if not lib.secp256k1_ecdsa_signature_serialize_der(ctx, sig_bytes, length, dsa_sig):
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, length[0])


def _parse(signature_bytes: bytes, recid: int):
    """Parse a compact signature and its recovery id."""

    signature = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    if not lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx, signature, signature_bytes, recid
    ):
        raise ValueError("invalid compact signature")
    return signature

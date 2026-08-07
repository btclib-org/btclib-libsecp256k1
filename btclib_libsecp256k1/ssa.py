# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Variant of Elliptic Curve Schnorr Signature Algorithm (ECSSA).

According to BIP340-Schnorr:
https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
"""

from __future__ import annotations

import secrets

from . import CData, ffi, lib
from ._scalar import scalar
from .context import ctx

# SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC: the libsecp256k1 macros do not
# survive the preprocessing of the headers into cffi definitions
EXTRAPARAMS_MAGIC = b"\xda\x6f\xb3\x8c"


def sign(
    msg_bytes: bytes, prvkey: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature of a 32-byte message hash.

    Args:
        msg_bytes: the 32-byte message hash.
        prvkey: the private key, 32 bytes or an int below 2**256. The
            signature is of its x-only public key, so the key is negated
            first where its y is odd, as BIP340 prescribes.
        aux_rand32: the 32 bytes of auxiliary randomness BIP340 defines,
            or None for fresh randomness. Never a shorter value: BIP340
            defines a 32-byte a, and padding a short one would make a
            caller mistake a valid argument.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32
            is given and is not 32 bytes, or if the private key is not
            32 bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do.

    Example:
        >>> from btclib_libsecp256k1 import ssa, xonly, mult
        >>> msg, prvkey = bytes(32), 1
        >>> pubkey, _ = xonly.from_pubkey(mult.mult_(prvkey))
        >>> ssa.verify(msg, pubkey, ssa.sign(msg, prvkey, bytes(32)))
        True
    """
    if len(msg_bytes) != 32:
        raise ValueError("the message hash must be 32 bytes")
    keypair = _keypair(prvkey)

    sig = ffi.new("char[64]")
    if lib.secp256k1_schnorrsig_sign32(
        ctx, sig, msg_bytes, keypair, _aux_rand32(aux_rand32)
    ):
        return ffi.unpack(sig, ffi.sizeof(sig))
    raise RuntimeError("schnorr signing failed")


def sign_custom(
    msg_bytes: bytes, prvkey: bytes | int, aux_rand32: bytes | None = None
) -> bytes:
    """Create a Schnorr signature of a message of any length.

    BIP340 signs messages of arbitrary length, while bitcoin only ever
    signs a 32-byte hash of what it commits to: unless the protocol at
    hand says otherwise, hash the message with a tag of its own
    (hashes.tagged_sha256) and sign that instead, so that a signature
    cannot be read as one of a different protocol. For a 32-byte message
    the signature is the one sign returns.

    Args:
        msg_bytes: the message, of any length.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for
            fresh randomness.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes, or if
            the private key is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do.
    """
    keypair = _keypair(prvkey)

    ndata = ffi.new("char[32]", _aux_rand32(aux_rand32))
    extraparams = ffi.new("secp256k1_schnorrsig_extraparams *")
    extraparams.magic = EXTRAPARAMS_MAGIC
    extraparams.noncefp = ffi.NULL
    # ndata has to stay referenced until the call is over: cffi keeps
    # alive what a variable points to, not what a struct field does
    extraparams.ndata = ndata

    sig = ffi.new("char[64]")
    if lib.secp256k1_schnorrsig_sign_custom(
        ctx, sig, msg_bytes, len(msg_bytes), keypair, extraparams
    ):
        return ffi.unpack(sig, ffi.sizeof(sig))
    raise RuntimeError("schnorr signing failed")


def verify(msg_bytes: bytes, pubkey_bytes: bytes, signature_bytes: bytes) -> bool:
    """Verify a Schnorr signature against a 32-byte x-only public key.

    The public key is the x-only one BIP340 verifies against, and only
    that: dropping the y coordinate of a full public key is a decision
    of the caller, `xonly.from_pubkey` being the conversion, because a
    key with odd y verifies as the point that is not the one passed.

    Args:
        msg_bytes: the message, of any length. It is the 32-byte hash
            for a signature made by `sign`.
        pubkey_bytes: the 32-byte x-only public key, and only that.
        signature_bytes: the 64-byte signature.

    Returns:
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the signature is not 64 bytes, if the public key
            is not 32 bytes, or if it is not a valid x coordinate. A
            well-formed signature that simply does not verify is False,
            not an exception.
    """
    if len(signature_bytes) != 64:
        raise ValueError("the signature must be 64 bytes")
    # secp256k1_xonly_pubkey_parse takes a bare pointer to 32 bytes
    if len(pubkey_bytes) != 32:
        raise ValueError("the x-only public key must be 32 bytes")

    xonly_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    if not lib.secp256k1_xonly_pubkey_parse(ctx, xonly_pubkey, pubkey_bytes):
        raise ValueError("invalid x-only public key")

    return bool(
        lib.secp256k1_schnorrsig_verify(
            ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
        )
    )


def _keypair(prvkey: bytes | int) -> CData:
    """Create a keypair from a private key.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256.

    Returns:
        The libsecp256k1 keypair object.

    Raises:
        ValueError: if the key is not 32 bytes, does not fit in them, or
            is not in [1, n-1].
    """
    keypair = ffi.new("secp256k1_keypair *")
    if not lib.secp256k1_keypair_create(ctx, keypair, scalar(prvkey, "private key")):
        raise ValueError("invalid private key")
    return keypair


def _aux_rand32(aux_rand32: bytes | None) -> bytes:
    """Check the auxiliary randomness of BIP340 signing.

    It is freshly generated when not provided, BIP340 recommending fresh
    randomness at every signature; given, it is exactly 32 bytes, being
    the entropy of a nonce and not a serialization: a shorter value is a
    caller mistake rather than a small number, and padding it here would
    turn one into a valid argument.

    Args:
        aux_rand32: the 32 bytes given by the caller, or None.

    Returns:
        Those 32 bytes, or 32 freshly generated ones.

    Raises:
        ValueError: if a value is given and is not 32 bytes.
    """
    if aux_rand32 is None:
        return secrets.token_bytes(32)
    if len(aux_rand32) != 32:
        raise ValueError("aux_rand32 must be 32 bytes")
    return aux_rand32

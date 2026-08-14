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

from . import BytesLike, CData, ffi, lib, xonly
from ._scalar import octets, scalar
from ._secret import wipe
from .context import ctx

# SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC: the libsecp256k1 macros do not
# survive the preprocessing of the headers into cffi definitions
EXTRAPARAMS_MAGIC = b"\xda\x6f\xb3\x8c"


def sign(
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
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
        >>> from btclib_secp256k1 import ssa, xonly, mult
        >>> msg, prvkey = bytes(32), 1
        >>> pubkey, _ = xonly.from_pubkey(mult.mult_(prvkey))
        >>> ssa.verify(msg, pubkey, ssa.sign(msg, prvkey, bytes(32)))
        True
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)
    keypair = _keypair(prvkey)

    sig = ffi.new("char[64]")
    try:
        signed = lib.secp256k1_schnorrsig_sign32(
            ctx, sig, msg_bytes, keypair, _aux_rand32(aux_rand32)
        )
    finally:
        # a keypair carries the private key: overwrite it whether the
        # signature was made, refused, or never attempted, _aux_rand32
        # being able to raise between the two
        wipe(keypair)
    if signed:
        return ffi.unpack(sig, ffi.sizeof(sig))
    raise RuntimeError("schnorr signing failed")


def sign_custom(
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
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
    msg_bytes = octets(msg_bytes, "message")
    keypair = _keypair(prvkey)

    sig = ffi.new("char[64]")
    try:
        ndata = ffi.new("char[32]", _aux_rand32(aux_rand32))
        extraparams = ffi.new("secp256k1_schnorrsig_extraparams *")
        extraparams.magic = EXTRAPARAMS_MAGIC
        extraparams.noncefp = ffi.NULL
        # ndata has to stay referenced until the call is over: cffi keeps
        # alive what a variable points to, not what a struct field does
        extraparams.ndata = ndata

        signed = lib.secp256k1_schnorrsig_sign_custom(
            ctx, sig, msg_bytes, len(msg_bytes), keypair, extraparams
        )
    finally:
        # the keypair carries the private key: see sign
        wipe(keypair)
    if signed:
        return ffi.unpack(sig, ffi.sizeof(sig))
    raise RuntimeError("schnorr signing failed")


def verify_(
    msg_bytes: BytesLike, xonly_pubkey: CData, signature_bytes: BytesLike
) -> bool:
    """Verify a Schnorr signature against an already-parsed x-only key.

    The inner half of `verify`, for a caller who already holds the parsed
    key -- one that proved 32 bytes to be the x coordinate of a point,
    which is what `xonly.parse` answers and what this verification would
    ask again, or one checking several signatures against the same key:
    see `keys.parse` for what the underscore means throughout.

    Args:
        msg_bytes: the message, of any length.
        xonly_pubkey: the already-parsed x-only public key, as
            `xonly.parse` returns.
        signature_bytes: the 64-byte signature.

    Returns:
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the signature is not 64 bytes. A well-formed
            signature that simply does not verify is False, not an
            exception.
    """
    msg_bytes = octets(msg_bytes, "message")
    signature_bytes = octets(signature_bytes, "signature", 64)

    return bool(
        lib.secp256k1_schnorrsig_verify(
            ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
        )
    )


def verify(
    msg_bytes: BytesLike, pubkey_bytes: BytesLike, signature_bytes: BytesLike
) -> bool:
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
    return verify_(msg_bytes, xonly.parse(pubkey_bytes), signature_bytes)


def _keypair(prvkey: BytesLike | int) -> CData:
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


def _aux_rand32(aux_rand32: BytesLike | None) -> bytes:
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
    return octets(aux_rand32, "aux_rand32", 32)

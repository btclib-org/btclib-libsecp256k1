# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ECDSA public key recovery.

A recoverable signature is the compact one and the recovery id together,
and `parse_compact` and `serialize_compact` are what open and close that
pair; `dsa.serialize_der` is what writes the same signature without the
id, which is what `to_der` drops.
"""

from __future__ import annotations

from . import BytesLike, CData, ffi, lib
from ._scalar import in_range, octets, optional_entropy, scalar
from .context import ctx, guarded
from .dsa import serialize_der
from .keys import serialize


def _sign_(
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
) -> CData:
    """Create a recoverable ECDSA signature, as the parsed signature.

    The private half of `sign`, and the one that answers with the object
    rather than with the compact bytes and the id: see the package
    docstring for what the two underscores mean throughout. A signer
    about to recover the key it just signed with, or to write the
    signature as DER, is this and `_recover_` or `_to_der_`, where the
    public halves serialize the pair only to parse it back.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone.

    Returns:
        The libsecp256k1 recoverable signature object.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
    """
    prvkey_bytes = scalar(prvkey, "private key")
    msg_bytes = octets(msg_bytes, "message hash", 32)

    signature = ffi.new("secp256k1_ecdsa_recoverable_signature *")

    # the default nonce function, and 32 bytes of entropy or nothing:
    # see the comment in dsa._sign_
    noncefp = ffi.NULL
    if not lib.secp256k1_ecdsa_sign_recoverable(
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
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
) -> tuple[bytes, int]:
    """Create a recoverable ECDSA signature.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone.

    Returns:
        The 64-byte compact signature and its recovery id. The id is 0
        or 1 for any signature this function produces; 2 and 3 exist for
        a nonce point whose x exceeded the group order, which no key
        reaches in practice.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to serialize the signature,
            which no input can make it do.
    """
    return serialize_compact(_sign_(msg_bytes, prvkey, aux_rand32))


def _recover_(msg_bytes: BytesLike, signature: CData) -> CData:
    """Recover the public key of an already-parsed recoverable signature.

    The private half of `recover`, in both directions at once: it takes
    the parsed signature and answers the parsed key. See the package
    docstring for what the two underscores mean throughout. Recovery is
    how a caller gets a key it did not have, so what usually follows is a
    use of it -- verifying the signature against it, comparing it with an
    expected key, deriving an address -- and libsecp256k1 hands it over
    already lifted.

    Args:
        msg_bytes: the 32-byte hash the signature was made over.
        signature: the already-parsed recoverable signature, as
            `parse_compact` returns.

    Returns:
        The libsecp256k1 public key object of the recovered key.

    Raises:
        ValueError: if the message hash is not 32 bytes, if no key can be
            recovered, or if the object is not a recoverable signature
            libsecp256k1 will read; see `context.guarded`.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)

    pubkey = ffi.new("secp256k1_pubkey *")
    with guarded():
        recovered = lib.secp256k1_ecdsa_recover(ctx, pubkey, signature, msg_bytes)
    if not recovered:
        raise ValueError("public key recovery failed")
    return pubkey


def recover(
    msg_bytes: BytesLike,
    signature_bytes: BytesLike,
    recid: int,
    compressed: bool = True,
) -> bytes:
    """Recover the public key from a recoverable ECDSA signature.

    Args:
        msg_bytes: the 32-byte hash the signature was made over.
        signature_bytes: the 64-byte compact signature.
        recid: the recovery id, 0 to 3. A wrong one recovers a different
            key rather than failing, so it is part of the signature and
            not a guess.
        compressed: whether to return 33 bytes rather than 65.

    Returns:
        The serialized recovered public key.

    Raises:
        TypeError: if the recovery id is not an int.
        ValueError: if the message hash is not 32 bytes, if the
            signature is not 64 bytes or has r or s at or above the
            group order, if recid is outside 0 to 3, or if no key can be
            recovered.
        RuntimeError: if libsecp256k1 fails to serialize the key, which
            no input can make it do.
    """
    return serialize(
        _recover_(msg_bytes, parse_compact(signature_bytes, recid)), compressed
    )


def _to_der_(signature: CData) -> bytes:
    """Convert an already-parsed recoverable signature into DER.

    The private half of `to_der`, for a caller who already holds the
    parsed signature: see the package docstring for what the two
    underscores mean throughout.

    Args:
        signature: the already-parsed recoverable signature, as
            `parse_compact` returns.

    Returns:
        The same signature in DER encoding, s unchanged and the recovery
        id dropped.

    Raises:
        ValueError: if the object is not a recoverable signature
            libsecp256k1 will read; see `context.guarded`.
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no input can make it do.
    """
    dsa_signature = ffi.new("secp256k1_ecdsa_signature *")
    with guarded():
        converted = lib.secp256k1_ecdsa_recoverable_signature_convert(
            ctx, dsa_signature, signature
        )
    if not converted:
        raise RuntimeError("signature conversion failed")
    return serialize_der(dsa_signature)


def to_der(signature_bytes: BytesLike, recid: int) -> bytes:
    """Convert a recoverable signature into a plain DER signature.

    The recovery id is dropped, as it is not part of the DER encoding.
    Beware: the conversion does not normalize the signature, so a
    high-s input is rejected by dsa.verify; signatures produced by
    sign are always low-s.

    Args:
        signature_bytes: the 64-byte compact signature.
        recid: the recovery id, 0 to 3. It is required because
            libsecp256k1 parses the pair before dropping the id, and
            refuses one out of range.

    Returns:
        The same signature in DER encoding, s unchanged.

    Raises:
        TypeError: if the recovery id is not an int.
        ValueError: if the signature is not 64 bytes or has r or s at or
            above the group order, or if recid is outside 0 to 3.
        RuntimeError: if libsecp256k1 fails to convert or serialize the
            signature, which no input can make it do.
    """
    return _to_der_(parse_compact(signature_bytes, recid))


def parse_compact(signature_bytes: BytesLike, recid: int) -> CData:
    """Parse a compact signature and its recovery id.

    What `dsa.parse_compact` is to a signature without an id, and the
    argument of the private halves here.

    Args:
        signature_bytes: the 64-byte compact signature.
        recid: the recovery id, 0 to 3.

    Returns:
        The libsecp256k1 recoverable signature object.

    Raises:
        TypeError: if the recovery id is not an int.
        ValueError: if the signature is not 64 bytes, if r or s is at or
            above the group order, or if recid is outside 0 to 3.
    """
    signature_bytes = octets(signature_bytes, "signature", 64)
    recid = in_range(recid, "recovery id", 3)

    signature = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    if not lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx, signature, signature_bytes, recid
    ):
        raise ValueError("invalid compact signature")
    return signature


def serialize_compact(signature: CData) -> tuple[bytes, int]:
    """Serialize an internal recoverable signature, id and all.

    Args:
        signature: the libsecp256k1 recoverable signature object, as
            `parse_compact` returns.

    Returns:
        The 64-byte compact signature and its recovery id, which is the
        pair `parse_compact` reads back.

    Raises:
        ValueError: if the object is not a recoverable signature
            libsecp256k1 will read; see `context.guarded`.
        RuntimeError: if libsecp256k1 fails for any other reason, which
            a signature it parsed cannot make it do.
    """
    sig_bytes = ffi.new("char[64]")
    recid = ffi.new("int *")
    with guarded():
        serialized = lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, sig_bytes, recid, signature
        )
    if not serialized:
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, ffi.sizeof(sig_bytes)), recid[0]

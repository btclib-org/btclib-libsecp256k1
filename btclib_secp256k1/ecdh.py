# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Elliptic Curve Diffie-Hellman (ECDH)."""

from __future__ import annotations

from typing import overload

from . import BytesLike, CData, MutableBytesLike, ffi, keys, lib
from ._scalar import scalar
from ._secret import take
from .context import ctx, guarded


@overload
def _shared_secret_(pubkey: CData, prvkey: BytesLike | int) -> bytes: ...
@overload
def _shared_secret_(
    pubkey: CData, prvkey: BytesLike | int, *, into: MutableBytesLike
) -> None: ...
@overload
def _shared_secret_(
    pubkey: CData, prvkey: BytesLike | int, *, into: MutableBytesLike | None
) -> bytes | None: ...
def _shared_secret_(
    pubkey: CData, prvkey: BytesLike | int, *, into: MutableBytesLike | None = None
) -> bytes | None:
    """Compute the ECDH shared secret from an already-parsed public key.

    The private half of `shared_secret`, for a caller who already holds
    the other party's parsed key -- one exchanging with the same
    counterparty more than once, or one that validated the key on
    receipt: see the package docstring for what the two underscores mean
    throughout.

    Args:
        pubkey: the other party's already-parsed public key, as
            `keys.parse` returns.
        prvkey: this party's private key, 32 bytes or an int below
            2**256.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32-byte shared secret, the SHA256 of the compressed shared
        point as `shared_secret` documents it -- or None where `into`
        was given and holds it.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if the private key is not 32 bytes, does not fit in
            them, is not a valid scalar, or if the object is not a public
            key libsecp256k1 will read; see `context.guarded`, without
            which an unreadable key would answer success and 32 bytes
            that are a shared secret with nobody.
    """
    prvkey_bytes = scalar(prvkey, "private key")

    output = ffi.new("char[32]")
    # a NULL hash function selects secp256k1_ecdh_hash_function_sha256,
    # which writes 32 bytes to output
    with guarded():
        computed = lib.secp256k1_ecdh(
            ctx, output, pubkey, prvkey_bytes, ffi.NULL, ffi.NULL
        )
    if not computed:
        raise ValueError("invalid private key")
    return take(output, into=into)


@overload
def shared_secret(pubkey_bytes: BytesLike, prvkey: BytesLike | int) -> bytes: ...
@overload
def shared_secret(
    pubkey_bytes: BytesLike, prvkey: BytesLike | int, *, into: MutableBytesLike
) -> None: ...
@overload
def shared_secret(
    pubkey_bytes: BytesLike, prvkey: BytesLike | int, *, into: MutableBytesLike | None
) -> bytes | None: ...
def shared_secret(
    pubkey_bytes: BytesLike,
    prvkey: BytesLike | int,
    *,
    into: MutableBytesLike | None = None,
) -> bytes | None:
    """Compute the ECDH shared secret.

    The result is the SHA256 of the compressed shared point, i.e. the
    libsecp256k1 default hash function; it is computed in constant time.

    The hash function is not configurable, by decision. libsecp256k1
    takes it as a C callback, so exposing it would mean calling back into
    python from the middle of the computation, with the shared point
    passing through python objects; and it would buy nothing, the point
    being available as keys.pubkey_tweak_mul(pubkey_bytes, prvkey),
    itself constant time. A protocol needing another derivation applies
    it to that: SHA256 of it is what this function returns. Wanting both
    of them is where the private halves earn their keep -- one
    `keys.parse`, then `_shared_secret_` and `keys._pubkey_tweak_mul_` of
    it -- the two public halves parsing the same key twice.

    Args:
        pubkey_bytes: the other party's public key, 33 or 65 bytes.
        prvkey: this party's private key, 32 bytes or an int below
            2**256.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32-byte shared secret -- or None where `into` was given and
        holds it.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if the public key is not a valid point, if the
            private key is not 32 bytes or does not fit in them, or if
            it is not a valid scalar.
    """
    return _shared_secret_(keys.parse(pubkey_bytes), prvkey, into=into)

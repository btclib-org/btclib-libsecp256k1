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

from . import BytesLike, CData, ffi, keys, lib
from ._scalar import in_range, octets, optional_entropy, scalar
from .context import ctx
from .dsa import serialize_der
from .keys import serialize

# the width of a compact signature, in both directions: it is what
# `serialize_compact` writes and what `parse_compact` accepts, so the
# statement of it serves the argument check too, and the buffer's type is
# built from it. `ffi.sizeof` of a cdata is not asked per call, which is
# worth a hundredth of a microsecond of the 0.272 that serialization
# costs -- 0.015 in the session `xonly.py` names, and not a figure this
# site can be held to between sessions: that comment says why. The
# recovery id is the `int *` beside it and is not a buffer anything
# unpacks, so its cdecl stays spelled in full. `xonly.py` carries the
# session behind the spelling
_COMPACT_SIZE = 64
_COMPACT_BUFFER_TYPE = ffi.typeof(f"char[{_COMPACT_SIZE}]")


def _abort_unless_recovered(
    signature: CData, msg_bytes: bytes, prvkey_bytes: bytes
) -> None:
    """Recover from a signature just made, and refuse another key.

    What `dsa` and `ssa` do after signing, in the shape a recoverable
    signature asks for. Bitcoin Core makes the same distinction:
    `CKey::Sign` ends in `secp256k1_ecdsa_verify`, and `CKey::SignCompact`
    ends in `secp256k1_ecdsa_recover` followed by
    `secp256k1_ec_pubkey_cmp` against the key that signed.

    The reason is the recovery id, which is what this signature has
    beyond a plain one and what a verification does not look at. A
    signature carrying the wrong id verifies perfectly and recovers
    somebody else's key -- and recovering a key is the one thing a caller
    of this module is going to do with it, so the check has to be the one
    the id answers.

    It subsumes the verification exactly rather than probably, which is
    what makes not verifying safe here. Recovery is not selective: for a
    given id it answers *the* key under which that `r` and `s` verify, so
    an inconsistent pair does not fail, it comes back as a different key
    -- and fails only where `r` is not the x of a point at all, which is
    the branch below that reports no key recovering.
    So the recovered key is by construction the key that verifies the
    signature, and `recovered == signer` is a verification with the id
    checked besides.

    Named as `ssa._abort_unless_verified` is, and for the same reason:
    it raises where a `_foo_` half would answer, and the verb is the one
    BIP340 uses of the step.

    **Neither call below needs a `context.check` behind it, and both are
    the kind that usually would.** `keys._pubkey_cmp_` answers an
    ordering that means nothing where libsecp256k1 could not read an
    object, and that answer is a security decision here -- but both
    objects come from calls that returned success a line earlier, so the
    only way its `0` could lie is both keys being unreadable at once,
    which is not a state either call can leave behind. And
    `keys._pubkey_from_prvkey_` raises a `ValueError` for a key outside
    [1, n-1], which this one is not: libsecp256k1 accepted it for signing
    immediately above. That is why `_recover_`'s `ValueError` is
    converted below and this one is not -- the first reports a property
    of the signature, which a fault can change, and the second a property
    of an argument that has already been proved. `dsa._sign_` leaves the
    same call unconverted for the same reason.

    Args:
        signature: the recoverable signature just made.
        msg_bytes: the 32-byte hash it was made over, already checked.
        prvkey_bytes: the 32-byte private key that made it, already
            checked.

    Raises:
        RuntimeError: if no key recovers from the signature, or if the
            one that does is not the signer's. Neither is reachable by
            any input: what they report is the computation itself having
            gone wrong.
    """
    try:
        recovered = _recover_(msg_bytes, signature)
    except ValueError as failure:
        # `_recover_` reports "no key can be recovered" as a ValueError,
        # that being an argument error for a signature a caller handed
        # in. For one made a line ago it is not: nothing was passed that
        # could have caused it
        raise RuntimeError("signing produced a signature no key recovers from") from (
            failure
        )
    if keys._pubkey_cmp_(recovered, keys._pubkey_from_prvkey_(prvkey_bytes)):
        raise RuntimeError("signing produced a signature that recovers another key")


def _sign_(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
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
        verify: whether to recover the key from the signature and refuse
            one that is not the signer's, as `sign` documents and
            `_abort_unless_recovered` reasons about.

    Returns:
        The libsecp256k1 recoverable signature object.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, or if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if `verify` asks and the signature does not recover
            the key that made it.
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
    if verify:
        _abort_unless_recovered(signature, msg_bytes, prvkey_bytes)
    return signature


def sign(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
) -> tuple[bytes, int]:
    """Create a recoverable ECDSA signature.

    `verify` is what `dsa.sign` and `ssa.sign` take, in the shape this
    signature asks for: the key is recovered from the signature and
    compared with the signer's, rather than the signature verified
    against it. That is Bitcoin Core's own distinction between
    `CKey::Sign` and `CKey::SignCompact`, and the reason is the recovery
    id -- a verification does not look at it, so a signature carrying the
    wrong one verifies and then recovers a key that is not the signer's.
    Recovering is what a caller of this module does with the answer, so
    the check is the one that question deserves.

    What it catches is not a bad argument -- those have all raised by
    then -- but a computation gone wrong, by bad memory or by a fault
    induced on purpose, whose cost is a published signature that is
    invalid or attributes itself to somebody else.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone.
        verify: whether to recover the key and refuse a signature that
            does not give the signer's back. It costs a recovery, a point
            multiplication and a comparison, and False is what a caller
            that has measured those against its own threat model passes.

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
            which no input can make it do, or if `verify` asks and the
            signature does not recover the key that made it.

    Example:
        >>> import hashlib
        >>> from btclib_secp256k1 import keys, recovery
        >>> msg = hashlib.sha256(b"hello").digest()
        >>> signature, recid = recovery.sign(msg, 1)
        >>> pubkey = recovery.recover(msg, signature, recid)
        >>> pubkey == keys.pubkey_from_prvkey(1)
        True
    """
    return serialize_compact(_sign_(msg_bytes, prvkey, aux_rand32, verify=verify))


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
            libsecp256k1 will read, those last two being one message
            here -- `context.check` is what tells them apart.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)

    pubkey = ffi.new("secp256k1_pubkey *")
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
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails to convert for any other reason,
            which a signature it parsed cannot make it do.
            `context.check` is what tells the two apart.
        RuntimeError: if libsecp256k1 fails to convert or serialize it,
            which no input can make it do.
    """
    dsa_signature = ffi.new("secp256k1_ecdsa_signature *")
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
    signature_bytes = octets(signature_bytes, "signature", _COMPACT_SIZE)
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
        RuntimeError: if libsecp256k1 refuses the object -- one it
            cannot read -- or fails to serialize for any other reason,
            which a signature it parsed cannot make it do.
            `context.check` is what tells the two apart.
        RuntimeError: if libsecp256k1 fails for any other reason, which
            a signature it parsed cannot make it do.
    """
    sig_bytes = ffi.new(_COMPACT_BUFFER_TYPE)
    recid = ffi.new("int *")
    serialized = lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
        ctx, sig_bytes, recid, signature
    )
    if not serialized:
        raise RuntimeError("signature serialization failed")
    return ffi.unpack(sig_bytes, _COMPACT_SIZE), recid[0]

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
    signature: CData, msg_bytes: bytes, prvkey_bytes: bytes, pubkey: CData | None
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

    **A key handed in is compared with instead of derived**, which is
    `dsa._checked`'s arrangement and buys the same
    `secp256k1_ec_pubkey_create` here, at the same price it costs there:
    what is dearest in this package is the check, not the saving. What it
    costs is that a mismatch now has three causes where `dsa`'s has two:
    the key given is not this private key's, the recovery id is not the
    signature's, or
    the computation faulted. The first is an argument and the other two
    are not, and one comparison separates them -- the recovered key
    against the derived one, paid only where something already went
    wrong. Where they agree, the signature is the signer's and it is the
    argument that is wrong; where they do not, the signature does not
    recover its own signer, which is what a wrong id and a fault both
    look like from here and neither is anything the caller passed.

    That those two share an answer is the decision rather than an
    oversight. A caller of `sign` cannot pass an id at all -- it comes
    back from `secp256k1_ecdsa_sign_recoverable` beside the signature --
    so an id that is not the signature's is a fault by the time this
    runs, and `test_the_recovery_id_is_what_the_check_catches` reaches
    that state the only way anything can: through the parsed signature
    this private half takes.

    **Neither call below needs a `context.check` behind it, and both are
    the kind that usually would.** `keys._pubkey_cmp_` answers an
    ordering that means nothing where libsecp256k1 could not read an
    object, and that answer is a security decision here. One of the two
    objects is no longer proved by a preceding success: `recovered` is,
    but `pubkey` is what this half takes on trust, and a caller handing
    in a `secp256k1_pubkey` nothing has written to reaches
    `secp256k1_ec_pubkey_cmp` with it -- so an illegal argument *is*
    recorded on the thread here, which the comparison against a derived
    key could not do. What holds instead is the comparison itself:
    libsecp256k1 serializes a key it cannot load as 33 zero octets,
    documented there as "less than any valid public key", and the
    recovered key is readable and serializes with an `0x02` or `0x03`
    prefix. So the `0` still cannot lie -- an unreadable key compares
    *unequal*, the fall-through derives, and what the caller is told is
    that the key they gave is not this private key's, which is the truth
    about it. `dsa._verify_` documents the same trust from the other
    side, and `dsa._checked` passes such a key straight into it. And
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
            checked, and what the failing branch derives from.
        pubkey: the public key the recovered one is compared with,
            parsed, or None to derive it -- which is what a caller
            holding nothing gets.

    Raises:
        RuntimeError: if no key recovers from the signature, or if the
            one that does is not the signer's. Neither is reachable by
            any input to `sign`: what they report is the computation
            itself having gone wrong, the recovery id included.
        ValueError: if the recovered key is the signer's and not the one
            handed in, which is the wrong key given -- or a private key
            that was already corrupt when it was signed with, as
            `dsa._checked` says of the same branch.
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
    if pubkey is not None and not keys._pubkey_cmp_(recovered, pubkey):
        return
    # either nothing was handed in, or what was did not match: the
    # derivation the common path skipped is what says which
    if keys._pubkey_cmp_(recovered, keys._pubkey_from_prvkey_(prvkey_bytes)):
        raise RuntimeError("signing produced a signature that recovers another key")
    if pubkey is not None:
        raise ValueError("the public key given is not this private key's")


def _sign_(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
    pubkey: CData | None = None,
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
        pubkey: the public key the recovered one is compared with,
            parsed, where the caller already holds it and would rather
            not have it derived again. Taken on trust;
            `_abort_unless_recovered` says what that does and does not
            risk. Refused beside `verify=False`, which declines the
            check it is for.

    Returns:
        The libsecp256k1 recoverable signature object.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1], if a
            `pubkey` is given beside `verify=False`, or if the recovered
            key is this private key's and not the one given -- the wrong
            key handed in, most likely, and `_abort_unless_recovered`
            says what else it can be.
        RuntimeError: if `verify` asks and the signature does not recover
            the key that made it.
    """
    prvkey_bytes = scalar(prvkey, "private key")
    msg_bytes = octets(msg_bytes, "message hash", 32)

    if pubkey is not None and not verify:
        raise ValueError("pubkey is for the check that verify=False declines")

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
        _abort_unless_recovered(signature, msg_bytes, prvkey_bytes, pubkey)
    return signature


def sign(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
    pubkey: BytesLike | None = None,
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

    It is also the dearest of the three, which is the other half of what
    a caller weighing it needs: 34.41 microseconds against 12.02, where
    `dsa.sign` measured beside it in the same session was 31.54 against
    12.06 and `ssa.sign` is 28.57 against 15.87. A recovery is about a
    verification's work, and the comparison and the derivation are the
    rest. CHANGELOG.md names the session.

    `pubkey` is how a caller already holding the key stops the comparison
    deriving it, and what it removes is the same call `dsa.sign` removes,
    at the same price: the check here is the dearest of the three, the
    saving is not. In a session of its own: 35.00 microseconds with the
    key derived, 29.67 with a compressed one handed in, 27.49 with an
    uncompressed one, against 12.07 unchecked and a noise of
    ±0.02. The 7.51 that removes is `secp256k1_ec_pubkey_create`, which
    timed alone there is 7.53, and what stays is the recovery and the
    comparison -- about 3 microseconds over what `dsa.sign` pays for a
    verification, whether the key is handed in or derived. The README
    carries both tables, and `_abort_unless_recovered` what the trust
    costs in diagnosis.

    Args:
        msg_bytes: the 32-byte hash of the message.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: 32 bytes of extra entropy mixed into the nonce, or
            None for the RFC6979 nonce alone.
        verify: whether to recover the key and refuse a signature that
            does not give the signer's back. It costs a recovery, a point
            multiplication and a comparison, and False is what a caller
            that has measured those against its own threat model passes.
        pubkey: the public key of this private key, where the caller
            already holds it, so that the comparison does not derive it
            again. That derivation is the multiplication named above, and
            this is how not to pay it twice. It is taken on trust rather
            than checked against the private key, which would cost the
            multiplication it saves; where it is wrong, the check says so
            and says which of the three things went wrong. Refused
            beside `verify=False`, which declines the check it is for.

    Returns:
        The 64-byte compact signature and its recovery id. The id is 0
        or 1 for any signature this function produces; 2 and 3 exist for
        a nonce point whose x exceeded the group order, which no key
        reaches in practice.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32 is
            given and is not 32 bytes, if the private key is not 32
            bytes, does not fit in them, or is not in [1, n-1], if pubkey
            is not a public key or is given beside `verify=False`, or if
            pubkey is not this private key's -- which is told apart from
            the failure below rather than reported as it.
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
    # the contradiction before the value, as `dsa.sign` answers it and
    # for the same reason: a caller who asked for no check and handed in
    # a key to check with should hear about the two arguments rather than
    # about the octets of one of them
    if pubkey is not None and not verify:
        raise ValueError("pubkey is for the check that verify=False declines")

    return serialize_compact(
        _sign_(
            msg_bytes,
            prvkey,
            aux_rand32,
            verify=verify,
            # parsed here rather than inside the check, so that octets
            # which are not a public key are refused before anything is
            # signed: a caller who mistyped an argument should not be
            # told about it by a check on a signature they now hold
            pubkey=None if pubkey is None else keys.parse(pubkey),
        )
    )


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

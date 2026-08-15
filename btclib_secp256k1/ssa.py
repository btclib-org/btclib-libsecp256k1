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
from types import TracebackType

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

    The keypair this needs is built from the private key and wiped
    before returning, which is the right cost for one signature and
    half the cost of each of several: signing more than once under one
    key is `Signer`, which builds it once.

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
    keypair = _keypair(prvkey)
    try:
        return _sign32(msg_bytes, keypair, aux_rand32)
    finally:
        # a keypair carries the private key: overwrite it whether the
        # signature was made, refused, or never attempted, the argument
        # checks inside being able to raise between the two
        wipe(keypair)


def sign_custom(
    msg_bytes: BytesLike, prvkey: BytesLike | int, aux_rand32: BytesLike | None = None
) -> bytes:
    """Create a Schnorr signature of a message of any length.

    BIP340 signs messages of arbitrary length, while bitcoin only ever
    signs a 32-byte hash of what it commits to: unless the protocol at
    hand says otherwise, hash the message with a tag of its own
    (hashes.tagged_sha256) and sign that instead, so that a signature
    cannot be read as one of a different protocol. For a 32-byte message
    the signature is the one sign returns. Signing more than one message
    under one key is `Signer.sign_custom`, for the reason given there.

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
    try:
        return _sign_custom(msg_bytes, keypair, aux_rand32)
    finally:
        # the keypair carries the private key: see sign
        wipe(keypair)


class Signer:
    """Sign under one private key repeatedly, building the keypair once.

    `sign` builds a `secp256k1_keypair` and wipes it before returning, so
    a caller signing a second message under the same key builds it again
    -- and that keypair is about half of what a BIP340 signature costs
    here, being the point multiplication of the public key. This holds
    one across calls instead, so the first signature is the only one
    paying for it, and `sign` and `sign_custom` are the same signatures
    over it.

    What that hands the caller is the lifetime of a secret, and it is the
    trade this makes deliberately. A keypair is the private key in
    libsecp256k1's own layout, in memory this package owns and can
    overwrite; the two functions own one for the length of a call and
    wipe it in a `finally`, while a signer holds it until it is told to
    let go. `wipe` is that instruction, and the `with` statement is how
    to give it without having to remember: on the way out of the block
    the keypair is overwritten, whether the block ended in a signature or
    in an exception. A wiped signer refuses to sign rather than signing
    with the zeros, and it cannot be revived -- the private key is kept
    nowhere else here, which is the point -- so signing again means
    building another one.

    What it does not change is the python side: the `bytes` or `int`
    handed in here is a python object like any other, and SECURITY.md
    records why that copy cannot be taken back.

    Args:
        prvkey: the private key, 32 bytes or an int below 2**256. Every
            signature is of its x-only public key, so the key is negated
            first where its y is odd, as BIP340 prescribes -- once here,
            rather than once per signature.

    Raises:
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1].

    Example:
        >>> from btclib_secp256k1 import ssa, xonly, mult
        >>> msg, prvkey = bytes(32), 1
        >>> pubkey, _ = xonly.from_pubkey(mult.mult_(prvkey))
        >>> with ssa.Signer(prvkey) as signer:
        ...     sig = signer.sign(msg, bytes(32))
        >>> sig == ssa.sign(msg, prvkey, bytes(32))
        True
        >>> ssa.verify(msg, pubkey, sig)
        True
    """

    # pydoclint (DOC301) asks that this carry no docstring of its own,
    # the class docstring above being where the constructor is documented
    def __init__(self, prvkey: BytesLike | int) -> None:  # noqa: D107
        # None once wiped, which is what tells the two states apart: a
        # wiped keypair is 96 zero octets and looks like any other
        self._keypair: CData | None = _keypair(prvkey)

    def sign(self, msg_bytes: BytesLike, aux_rand32: BytesLike | None = None) -> bytes:
        """Create a Schnorr signature of a 32-byte message hash.

        The signature `ssa.sign` makes of the same arguments, over the
        keypair built when this signer was.

        Args:
            msg_bytes: the 32-byte message hash.
            aux_rand32: the 32 bytes of auxiliary randomness BIP340
                defines, or None for fresh randomness.

        Returns:
            The 64-byte signature.

        Raises:
            ValueError: if the message hash is not 32 bytes, if
                aux_rand32 is given and is not 32 bytes, or if this
                signer has been wiped.
            RuntimeError: if libsecp256k1 fails to sign, which no input
                can make it do.
        """
        return _sign32(msg_bytes, self._held(), aux_rand32)

    def sign_custom(
        self, msg_bytes: BytesLike, aux_rand32: BytesLike | None = None
    ) -> bytes:
        """Create a Schnorr signature of a message of any length.

        The signature `ssa.sign_custom` makes of the same arguments, and
        what that function says about hashing a message first holds here
        too.

        Args:
            msg_bytes: the message, of any length.
            aux_rand32: the 32 bytes of auxiliary randomness, or None
                for fresh randomness.

        Returns:
            The 64-byte signature.

        Raises:
            ValueError: if aux_rand32 is given and is not 32 bytes, or
                if this signer has been wiped.
            RuntimeError: if libsecp256k1 fails to sign, which no input
                can make it do.
        """
        return _sign_custom(msg_bytes, self._held(), aux_rand32)

    def wipe(self) -> None:
        """Overwrite the keypair, ending what this signer can do.

        The deliberate half of the trade above, and what `__exit__`
        calls. Signing afterwards raises rather than signing with the
        zeros left behind, and wiping twice is not an error: a signer
        used as a context manager and wiped inside the block is the case
        that makes it one.
        """
        if self._keypair is not None:
            wipe(self._keypair)
            self._keypair = None

    # PYI034 asks for `typing.Self` here, and that is 3.11 while this
    # package supports 3.10. The class itself says the same thing of a
    # class nothing subclasses, and `typing_extensions` is a dependency
    # this package does not have and would not add for one annotation
    def __enter__(self) -> Signer:  # noqa: PYI034
        """Return this signer, for the `with` block that wipes it.

        Returns:
            The signer itself, nothing being built here that the
            constructor did not already build.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Wipe the keypair, whatever ended the block.

        Nothing is suppressed: returning None lets an exception raised
        inside the block go on being raised, the wipe having happened
        first.

        Args:
            exc_type: the class of the exception ending the block, if
                one is.
            exc_value: that exception.
            traceback: its traceback.
        """
        self.wipe()

    def _held(self) -> CData:
        """Return the keypair, or refuse if it has been wiped.

        Returns:
            The libsecp256k1 keypair this signer holds.

        Raises:
            ValueError: if `wipe` has already overwritten it.
        """
        if self._keypair is None:
            raise ValueError("this signer has been wiped")
        return self._keypair


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


def _sign32(
    msg_bytes: BytesLike, keypair: CData, aux_rand32: BytesLike | None
) -> bytes:
    """Sign a 32-byte message hash with a keypair somebody else owns.

    The whole of `sign` and of `Signer.sign` except for the keypair:
    where it comes from and who overwrites it is the only difference
    between the two, so every argument check is here rather than at each
    of the two call sites, where a second spelling could drift from this
    one. Named after the libsecp256k1 call it is.

    Args:
        msg_bytes: the 32-byte message hash.
        keypair: the libsecp256k1 keypair to sign with, wiped by
            whoever built it and not here.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for
            fresh randomness.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if the message hash is not 32 bytes, or if
            aux_rand32 is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)

    sig = ffi.new("char[64]")
    if not lib.secp256k1_schnorrsig_sign32(
        ctx, sig, msg_bytes, keypair, _aux_rand32(aux_rand32)
    ):
        raise RuntimeError("schnorr signing failed")
    return ffi.unpack(sig, ffi.sizeof(sig))


def _sign_custom(
    msg_bytes: BytesLike, keypair: CData, aux_rand32: BytesLike | None
) -> bytes:
    """Sign a message of any length with a keypair somebody else owns.

    What `_sign32` is to `sign`, this is to `sign_custom`.

    Args:
        msg_bytes: the message, of any length.
        keypair: the libsecp256k1 keypair to sign with, wiped by
            whoever built it and not here.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for
            fresh randomness.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do.
    """
    msg_bytes = octets(msg_bytes, "message")

    sig = ffi.new("char[64]")
    ndata = ffi.new("char[32]", _aux_rand32(aux_rand32))
    extraparams = ffi.new("secp256k1_schnorrsig_extraparams *")
    extraparams.magic = EXTRAPARAMS_MAGIC
    extraparams.noncefp = ffi.NULL
    # ndata has to stay referenced until the call is over: cffi keeps
    # alive what a variable points to, not what a struct field does
    extraparams.ndata = ndata

    if not lib.secp256k1_schnorrsig_sign_custom(
        ctx, sig, msg_bytes, len(msg_bytes), keypair, extraparams
    ):
        raise RuntimeError("schnorr signing failed")
    return ffi.unpack(sig, ffi.sizeof(sig))


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

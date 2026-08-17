# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Variant of Elliptic Curve Schnorr Signature Algorithm (ECSSA).

According to BIP340-Schnorr:
https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
"""

from __future__ import annotations

from types import TracebackType
from typing import overload

from . import BytesLike, CData, MutableBytesLike, ffi, keys, lib, xonly
from ._scalar import entropy, octets, optional_entropy, scalar
from ._secret import keypair, take, wipe
from .context import ctx

# SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC: the libsecp256k1 macros do not
# survive the preprocessing of the headers into cffi definitions
EXTRAPARAMS_MAGIC = b"\xda\x6f\xb3\x8c"

# the width of a BIP340 signature: 64 bytes, which is what `_sign32` and
# `_sign_custom` write and what `_verify_` and `verify` read back, so the
# one statement of it answers for the argument checks as well as for the
# buffer, whose type is built from it. It saves some hundredths of a
# microsecond on calls of 30.20 and 30.54, where timing each of those
# against itself moves 0.08 and 0.003: nothing that measurement resolves,
# and not the reason either -- `xonly.py` says the reason
_SIGNATURE_SIZE = 64
_SIGNATURE_BUFFER_TYPE = ffi.typeof(f"char[{_SIGNATURE_SIZE}]")

# the tag secp256k1_schnorrsig_sign gives its nonce function, and what
# makes the derivation BIP340's rather than another protocol's
_NONCE_ALGO = b"BIP0340/nonce"


@overload
def nonce_bip340(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
) -> bytes: ...
@overload
def nonce_bip340(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    into: MutableBytesLike,
) -> None: ...
@overload
def nonce_bip340(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    into: MutableBytesLike | None,
) -> bytes | None: ...
def nonce_bip340(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    into: MutableBytesLike | None = None,
) -> bytes | None:
    """Return the BIP340 nonce `sign` derives for a message and a key.

    libsecp256k1 exports its nonce function as a callable pointer, and
    this calls through it with what `secp256k1_schnorrsig_sign` passes:
    the message, the key the signature is made with, the x-only public
    key, the `BIP0340/nonce` tag and the auxiliary randomness. So what
    comes back is the `k` of the signature `sign` makes of the same
    arguments -- the first 32 octets of that signature are the x of `k`
    times the generator, which is what `tests/test_nonces.py` holds it to.

    The key BIP340 signs with is the one of the even-y point, so a
    private key whose point has odd y enters the derivation negated, and
    the x-only public key with it. Both are derived here rather than
    asked of the caller: that is what makes the answer the nonce of the
    signature rather than of a key nobody signs with.

    It is here for the reason `dsa.nonce_rfc6979` is: a python
    implementation of BIP340's nonce derivation has published vectors and
    no oracle, and the aux is where implementations diverge.

    **The nonce is the secret the signature is built on**, and reading it
    into python takes it out of constant-time code: see
    `dsa.nonce_rfc6979`, which says what that means.

    Args:
        msg_bytes: the message, of any length.
        prvkey: the private key, 32 bytes or an int below 2**256.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for the
            derivation libsecp256k1 makes without any -- which answers
            what 32 zero octets answer, the tagged hash of those zeros
            being what it substitutes. `sign` given None generates 32
            fresh octets instead of passing none, so what reproduces a
            signature's nonce is the aux that signature was made with.
        into: a writable 32-byte buffer to receive the result, instead
            of the `bytes` this otherwise returns. See `_secret.take`
            and SECURITY.md for what that does and does not buy.

    Returns:
        The 32-byte nonce -- or None where `into` was given and holds it.

    Raises:
        TypeError: if `into` is not a writable bytearray or memoryview
            of octets.
        ValueError: if aux_rand32 is given and is not 32 bytes, or if the
            private key is not 32 bytes, does not fit in them, or is not
            in [1, n-1].
        RuntimeError: if libsecp256k1 fails to derive one, which the tag
            above keeps it from doing.

    Example:
        >>> from btclib_secp256k1 import ssa
        >>> nonce = ssa.nonce_bip340(bytes(32), 1, bytes(32))
        >>> len(nonce)
        32
    """
    msg_bytes = octets(msg_bytes, "message")
    xonly_pubkey, parity = xonly.from_prvkey(prvkey)
    # the key that signs, which BIP340 negates where the point has odd y
    prvkey_bytes = (
        keys.prvkey_negate(prvkey) if parity else scalar(prvkey, "private key")
    )
    aux = optional_entropy(aux_rand32)

    nonce = ffi.new("unsigned char[32]")
    if not lib.secp256k1_nonce_function_bip340(
        nonce,
        msg_bytes,
        len(msg_bytes),
        prvkey_bytes,
        xonly_pubkey,
        _NONCE_ALGO,
        len(_NONCE_ALGO),
        aux,
    ):
        raise RuntimeError("BIP340 nonce derivation failed")
    return take(nonce, into=into)


def sign(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
) -> bytes:
    """Create a Schnorr signature of a 32-byte message hash.

    The keypair this needs is built from the private key and wiped
    before returning, which is the right cost for one signature and
    half the cost of each of several: signing more than once under one
    key is `Signer`, which builds it once.

    `verify` is BIP340's own last step -- "If Verify(bytes(P), m, sig)
    returns failure, abort" -- and the one thing here that is more than a
    libsecp256k1 call. A computation gone wrong, memory gone bad or a
    fault induced on purpose, yields a signature that is invalid and may
    leak something about the secret key, and not answering with one is
    the whole of the protection. It is on by default because the BIP
    puts it inside the algorithm rather than beside it, and it can be
    turned off because the BIP says that too, "if the computation cost
    is prohibitive" -- which here is one verification and no
    multiplication: 28.57 microseconds against 15.87, where ECDSA's same
    check is 31.67 against 12.15 for having to derive the public key
    first. The cheaper of the two is the one a specification asks for.
    CHANGELOG.md names the session those come from, and
    `_abort_unless_verified` carries the rest of the reasoning.

    Args:
        msg_bytes: the 32-byte message hash.
        prvkey: the private key, 32 bytes or an int below 2**256. The
            signature is of its x-only public key, so the key is negated
            first where its y is odd, as BIP340 prescribes.
        aux_rand32: the 32 bytes of auxiliary randomness BIP340 defines,
            or None for fresh randomness. Never a shorter value: BIP340
            defines a 32-byte a, and padding a short one would make a
            caller mistake a valid argument.
        verify: whether to check the signature under its own public key
            before returning it. It costs a verification and no point
            multiplication, the keypair already holding the point, and
            False is what a caller that has measured that against its
            own threat model passes.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if the message hash is not 32 bytes, if aux_rand32
            is given and is not 32 bytes, or if the private key is not
            32 bytes, does not fit in them, or is not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do, or if `verify` asks and the signature does not
            verify.

    Example:
        >>> from btclib_secp256k1 import keys, ssa, xonly
        >>> msg, prvkey = bytes(32), 1
        >>> pubkey, _ = xonly.from_pubkey(keys.pubkey_from_prvkey(prvkey))
        >>> sig = ssa.sign(msg, prvkey, bytes(32))
        >>> ssa.verify(msg, pubkey, sig)
        True
        >>> ssa.sign(msg, prvkey, bytes(32), verify=False) == sig
        True
    """
    keypair_obj = keypair(prvkey)
    try:
        return _sign32(msg_bytes, keypair_obj, aux_rand32, verify=verify)
    finally:
        # a keypair carries the private key: overwrite it whether the
        # signature was made, refused, or never attempted, the argument
        # checks inside being able to raise between the two
        wipe(keypair_obj)


def sign_custom(
    msg_bytes: BytesLike,
    prvkey: BytesLike | int,
    aux_rand32: BytesLike | None = None,
    *,
    verify: bool = True,
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
        verify: whether to check the signature under its own public key
            before returning it, as `sign` documents and BIP340
            prescribes. One verification and no point multiplication,
            which on a 32-byte message is `sign`'s 28.57 microseconds
            against 15.87, the extraparams struct this fills aside;
            a longer message costs more to sign and to check by the
            same hash.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes, or if
            the private key is not 32 bytes, does not fit in them, or is
            not in [1, n-1].
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do, or if `verify` asks and the signature does not
            verify.
    """
    keypair_obj = keypair(prvkey)
    try:
        return _sign_custom(msg_bytes, keypair_obj, aux_rand32, verify=verify)
    finally:
        # the keypair carries the private key: see sign
        wipe(keypair_obj)


class Signer:
    """Sign under one private key repeatedly, building the keypair once.

    `sign` builds a `secp256k1_keypair` and wipes it before returning, so
    a caller signing a second message under the same key builds it again
    -- and that keypair is about half of what a BIP340 signature costs
    here, being the point multiplication of the public key. This holds
    one across calls instead, so the first signature is the only one
    paying for it, and `sign` and `sign_custom` are the same signatures
    over it. `pubkey()` is the x-only key those signatures verify
    against, read off that same keypair rather than derived a second
    time.

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

    A signer told neither way is dropped holding the key: cffi frees the
    keypair without overwriting it, and nothing here runs behind it to
    do so. A finalizer would, at a time nothing specifies, which is a
    guarantee in the shape of one and not in fact -- so the instruction
    stays the caller's to give, and SECURITY.md records this as the one
    buffer of the package whose zeroing is asked for rather than done.

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
        >>> from btclib_secp256k1 import keys, ssa, xonly
        >>> msg, prvkey = bytes(32), 1
        >>> pubkey, _ = xonly.from_pubkey(keys.pubkey_from_prvkey(prvkey))
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
        self._keypair: CData | None = keypair(prvkey)

    def sign(
        self,
        msg_bytes: BytesLike,
        aux_rand32: BytesLike | None = None,
        *,
        verify: bool = True,
    ) -> bytes:
        """Create a Schnorr signature of a 32-byte message hash.

        The signature `ssa.sign` makes of the same arguments, over the
        keypair built when this signer was.

        Args:
            msg_bytes: the 32-byte message hash.
            aux_rand32: the 32 bytes of auxiliary randomness BIP340
                defines, or None for fresh randomness.
            verify: whether to check the signature under this signer's
                own public key before returning it, as `ssa.sign`
                documents and BIP340 prescribes. It is the same cost
                here as there, the point being read off the keypair
                either way -- and because the signature is the cheaper,
                the keypair being built already, it is the larger share:
                20.82 microseconds against 8.18, where `ssa.sign` is
                28.57 against 15.87. The check is more than half again
                this signature and four fifths of that one, which is the
                same increment either way. 1.545 of a signature here
                against `dsa.sign`'s 1.607 is the reading worth having:
                this is where BIP340's cheaper check costs what ECDSA's
                does, the keypair already built having taken the
                signature down to where the increment dominates.

        Returns:
            The 64-byte signature.

        Raises:
            ValueError: if the message hash is not 32 bytes, if
                aux_rand32 is given and is not 32 bytes, or if this
                signer has been wiped.
            RuntimeError: if libsecp256k1 fails to sign, which no input
                can make it do, or if `verify` asks and the signature
                does not verify.
        """
        return _sign32(msg_bytes, self._held(), aux_rand32, verify=verify)

    def sign_custom(
        self,
        msg_bytes: BytesLike,
        aux_rand32: BytesLike | None = None,
        *,
        verify: bool = True,
    ) -> bytes:
        """Create a Schnorr signature of a message of any length.

        The signature `ssa.sign_custom` makes of the same arguments, and
        what that function says about hashing a message first holds here
        too.

        Args:
            msg_bytes: the message, of any length.
            aux_rand32: the 32 bytes of auxiliary randomness, or None
                for fresh randomness.
            verify: whether to check the signature under this signer's
                own public key before returning it, as `ssa.sign`
                documents and BIP340 prescribes.

        Returns:
            The 64-byte signature.

        Raises:
            ValueError: if aux_rand32 is given and is not 32 bytes, or
                if this signer has been wiped.
            RuntimeError: if libsecp256k1 fails to sign, which no input
                can make it do, or if `verify` asks and the signature
                does not verify.
        """
        return _sign_custom(msg_bytes, self._held(), aux_rand32, verify=verify)

    def pubkey(self) -> tuple[bytes, int]:
        """Return the x-only public key this signer signs under.

        The keypair already holds the point, so this is a read of it and
        not a multiplication: `xonly.from_prvkey` is the same answer
        derived from the private key, and costs the point multiplication
        this signer has already paid for.

        Returns:
            The 32-byte x coordinate BIP340 verifies against, and the
            parity of the y of the private key's own point: 0 for even,
            1 for odd. A signature made here verifies against the 32
            bytes whichever the parity is, which is what the negation
            BIP340 prescribes is for.

        Raises:
            ValueError: if this signer has been wiped.
            RuntimeError: if libsecp256k1 fails to convert or serialize
                the key, which a keypair it built cannot make it do.
        """
        return xonly.from_keypair(self._held())

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


def _verify_(
    msg_bytes: BytesLike, xonly_pubkey: CData, signature_bytes: BytesLike
) -> bool:
    """Verify a Schnorr signature against an already-parsed x-only key.

    The private half of `verify`, for a caller who already holds the
    parsed key -- one that proved octets the x coordinate of a point,
    which is what `xonly.parse` answers and what this verification would
    ask again, or one checking several signatures against the same key:
    see the package docstring for what the two underscores mean
    throughout.

    Args:
        msg_bytes: the message, of any length.
        xonly_pubkey: the already-parsed x-only public key, as
            `xonly.parse` returns.
        signature_bytes: the 64-byte signature.

    Returns:
        True if the signature is valid for that key and message -- and
        False where libsecp256k1 could not read the key, which is the
        same answer it gives a signature that simply does not verify.
        This raises nothing for it: a caller passing an object of its
        own is the one that can be handed an unreadable one, and
        `context.check` immediately after the call is what says the
        False is not a verdict. `verify` parses the key from octets and
        so has no such case.

    Raises:
        ValueError: if the signature is not 64 bytes.
    """
    msg_bytes = octets(msg_bytes, "message")
    signature_bytes = octets(signature_bytes, "signature", _SIGNATURE_SIZE)

    verified = lib.secp256k1_schnorrsig_verify(
        ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
    )
    return bool(verified)


def verify(
    msg_bytes: BytesLike, pubkey_bytes: BytesLike, signature_bytes: BytesLike
) -> bool:
    """Verify a Schnorr signature against a public key, in any of its forms.

    BIP340 verifies against an x coordinate, so `02 || x`, `03 || x` and
    `04 || x || y` are one key and any of the three is accepted: the y is
    not consulted, a signer whose point has odd y having signed with
    `n - d` for exactly that reason. Which form to hand in is a question
    of cost -- the uncompressed one is read rather than lifted, see
    `xonly.parse`.

    Args:
        msg_bytes: the message, of any length. It is the 32-byte hash
            for a signature made by `sign`.
        pubkey_bytes: the public key, 32, 33 or 65 bytes.
        signature_bytes: the 64-byte signature.

    Returns:
        True if the signature is valid for that key and message.

    Raises:
        ValueError: if the signature is not 64 bytes, or if the public
            key is not a valid point in one of the three serializations.
            A well-formed signature that simply does not verify is False,
            not an exception.
    """
    # spelled out rather than composed of `xonly.parse` and `_verify_`:
    # the frame between them is 0.009 microseconds of the 14.275 this
    # call costs -- an Apple M5, macOS 26.6, arm64, CPython 3.13.14, the
    # two spellings alternated in one process over 7 rounds of 20 000
    # calls, minimum kept for each. That is the smallest of these and is
    # kept for consistency with the rest rather than on its own account.
    # `_verify_` makes the same calls for a caller holding the x-only
    # key, and tests/test_parsed_keys.py asserts the two answer alike
    xonly_pubkey = xonly.parse(pubkey_bytes)
    msg_bytes = octets(msg_bytes, "message")
    signature_bytes = octets(signature_bytes, "signature", _SIGNATURE_SIZE)
    return bool(
        lib.secp256k1_schnorrsig_verify(
            ctx, signature_bytes, msg_bytes, len(msg_bytes), xonly_pubkey
        )
    )


def _abort_unless_verified(
    keypair_obj: CData, msg_bytes: BytesLike, signature_bytes: bytes
) -> None:
    """Check a signature just made, under the keypair that made it.

    Named for what it does rather than for what it asks: `_verify_` is
    thirty lines up, answers `bool` and is what a caller composes with,
    where this one raises and answers nothing. Two neighbours told apart
    by tense would invite `if _abort_unless_verified(...)`, which is
    syntactically fine and means nothing at all. The verb is BIP340's
    own -- "returns failure, abort".

    BIP340's *Default Signing* ends with this step -- "If Verify(bytes(P),
    m, sig) returns failure, abort" -- and says what it is for: a random
    or attacker provoked computation error yields a signature that is
    invalid and may leak something about the secret key, and not
    publishing one is the whole of the protection. Schnorr is linear, so
    what leaks is not vague: two signatures over one nonce and two
    challenges give up `d` by subtraction. The BIP puts the step inside
    the algorithm and allows omitting it where the cost is prohibitive,
    which is why `sign` does it unless told not to rather than the other
    way round.

    Written once because `_sign32` and `_sign_custom` both end in it, and
    because the key has to be the one that signed: two spellings would be
    two chances for it to be some other key, and a check against the
    wrong key proves nothing while looking like proof.

    The key is read off the keypair rather than derived, which is what
    makes this cheaper than the same step is in `dsa`: BIP340 needs the
    public key to sign at all, so the multiplication is already paid and
    what is left is the verification.

    Args:
        keypair_obj: the keypair that made the signature.
        msg_bytes: the message it was made of, already checked.
        signature_bytes: the 64-byte signature just made.

    Raises:
        RuntimeError: if the signature does not verify, which no input
            can make happen: what it reports is the computation itself
            having gone wrong.
    """
    xonly_pubkey = xonly._from_keypair_(keypair_obj)
    if not _verify_(msg_bytes, xonly_pubkey, signature_bytes):
        raise RuntimeError("signing produced a signature that does not verify")


def _sign32(
    msg_bytes: BytesLike,
    keypair_obj: CData,
    aux_rand32: BytesLike | None,
    *,
    verify: bool = True,
) -> bytes:
    """Sign a 32-byte message hash with a keypair somebody else owns.

    The whole of `sign` and of `Signer.sign` except for the keypair:
    where it comes from and who overwrites it is the only difference
    between the two, so every argument check is here rather than at each
    of the two call sites, where a second spelling could drift from this
    one. Named after the libsecp256k1 call it is.

    Args:
        msg_bytes: the 32-byte message hash.
        keypair_obj: the libsecp256k1 keypair to sign with, wiped by
            whoever built it and not here.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for
            fresh randomness.
        verify: whether to check the signature before answering with it,
            as `_abort_unless_verified` documents and BIP340 prescribes.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if the message hash is not 32 bytes, or if
            aux_rand32 is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do, or if `verify` asks and the signature does not
            verify.
    """
    msg_bytes = octets(msg_bytes, "message hash", 32)

    sig = ffi.new(_SIGNATURE_BUFFER_TYPE)
    if not lib.secp256k1_schnorrsig_sign32(
        ctx, sig, msg_bytes, keypair_obj, entropy(aux_rand32)
    ):
        raise RuntimeError("schnorr signing failed")
    signature_bytes = ffi.unpack(sig, _SIGNATURE_SIZE)
    if verify:
        _abort_unless_verified(keypair_obj, msg_bytes, signature_bytes)
    return signature_bytes


def _sign_custom(
    msg_bytes: BytesLike,
    keypair_obj: CData,
    aux_rand32: BytesLike | None,
    *,
    verify: bool = True,
) -> bytes:
    """Sign a message of any length with a keypair somebody else owns.

    What `_sign32` is to `sign`, this is to `sign_custom`.

    Args:
        msg_bytes: the message, of any length.
        keypair_obj: the libsecp256k1 keypair to sign with, wiped by
            whoever built it and not here.
        aux_rand32: the 32 bytes of auxiliary randomness, or None for
            fresh randomness.
        verify: whether to check the signature before answering with it,
            as `_abort_unless_verified` documents and BIP340 prescribes.

    Returns:
        The 64-byte signature.

    Raises:
        ValueError: if aux_rand32 is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to sign, which no input can
            make it do, or if `verify` asks and the signature does not
            verify.
    """
    msg_bytes = octets(msg_bytes, "message")

    sig = ffi.new(_SIGNATURE_BUFFER_TYPE)
    ndata = ffi.new("char[32]", entropy(aux_rand32))
    extraparams = ffi.new("secp256k1_schnorrsig_extraparams *")
    extraparams.magic = EXTRAPARAMS_MAGIC
    extraparams.noncefp = ffi.NULL
    # ndata has to stay referenced until the call is over: cffi keeps
    # alive what a variable points to, not what a struct field does
    extraparams.ndata = ndata

    if not lib.secp256k1_schnorrsig_sign_custom(
        ctx, sig, msg_bytes, len(msg_bytes), keypair_obj, extraparams
    ):
        raise RuntimeError("schnorr signing failed")
    signature_bytes = ffi.unpack(sig, _SIGNATURE_SIZE)
    if verify:
        _abort_unless_verified(keypair_obj, msg_bytes, signature_bytes)
    return signature_bytes

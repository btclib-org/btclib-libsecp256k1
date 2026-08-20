# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""MuSig2, a two-round multi-signature scheme for BIP340 keys.

According to BIP327:
https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki

The final signature this protocol produces is a plain BIP340 one, over
the aggregate (and possibly tweaked) key `pubkey_agg` computes:
`ssa.verify` is what checks it, and nothing here duplicates that call.

**Two of the five libsecp256k1 objects this module wraps have no
serialization.** `secp256k1_musig_keyagg_cache` and `secp256k1_musig_session`
are, in the header's own words, structures with "no serialization and
parsing functions (yet)", so they cannot cross this package's boundary as
octets -- which is the rule the package docstring states for everything
else. #87 declined an opaque *handle* for the reason that "a handle is a
lifetime someone has to own and invalidate", and `_secret.py` records the
clause that reopens it: the handle "belongs where the signing state
lives". A MuSig2 session is exactly that, so `KeyAggCache` and `Session`
below are that exception, taken rather than refused -- refusing it would
leave this module unable to do anything a caller could not already do
through the raw `lib`. Neither object is secret: a keyagg cache is
aggregated *public* keys, and the header says of a session that it "is
not required to be kept secret for the signing protocol to be secure".
So the two are ordinary held state, the third outpost past the boundary
alongside `ssa.Signer` and `keys.PubkeyTweakChain` -- and, unlike either
of those, one this module cannot build any other way.

**A third object, the secret nonce, is the one that must be wiped, and
`SecretNonce` is the model `ssa.Signer` already set for a held secret:**
a `with` statement that overwrites it on the way out, whether the block
ended in a signature or in an exception, and a wiped object that refuses
to sign rather than signing with the zeros left behind. libsecp256k1
already zeroes a secnonce inside `partial_sign` -- "overwrites the given
secnonce with zeros and will abort if given a secnonce that is all
zeros" -- which covers a session that runs to completion. What `wipe` and
the `with` statement add is the session that does not: one abandoned
between `nonce_gen` and `partial_sign`, which the C side never sees and
so never overwrites. SECURITY.md records this as the second buffer in
this package whose zeroing is asked for rather than done, `ssa.Signer`'s
keypair being the first.

**`partial_sign` verifies the partial signature it produces, by
default.** `secp256k1_musig_partial_sign` "does not verify the output
partial signature, deviating from the BIP 327 specification", and its
header recommends verifying it with `secp256k1_musig_partial_sig_verify`
"to prevent random or adversarially provoked computation errors" --
which is BIP340's own argument for `ssa.sign`'s `verify`, on a signature
made from more moving parts than a solo one. `verify=True` is the
default for the same reason it is there: the cost is a verification
against a nonce and a key already in hand, and BIP327 recommends paying
it.

**A parse failure and a tweak failure both tell this package nothing.**
Verified against `secp256k1_musig_pubnonce_parse`: a refusal answers a
bare `0`, through an empty illegal callback, with no message for
`context.check` to raise. `pubkey_agg`, `nonce_agg` and `partial_sig_agg`
all take arrays of already-parsed objects, which the C API's own
calling convention already asks a caller to build -- so `KeyAggCache`,
`nonce_agg` and `Session.partial_sig_agg` each parse their array one
contribution at a time rather than handing a comprehension to the array
helper, and the index that failed is in the `ValueError` because the
loop that found it already knew it.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Sequence
from types import TracebackType

from . import BytesLike, CData, ffi, keys, lib, xonly
from ._cdata import array
from ._scalar import in_range, octets, scalar
from ._secret import keypair, wipe
from .context import ctx

# the three serializations this module has fixed widths for: BIP327's own
# for a public and an aggregate nonce (33 octets per point, two points
# each), and libsecp256k1's compact 32-byte partial signature -- s alone,
# the nonce and the key both being implied by the session. The aggregate
# signature `Session.partial_sig_agg` answers is a plain BIP340 one, whose
# width `ssa.py` already states
_PUBNONCE_SIZE = 66
_AGGNONCE_SIZE = 66
_PARTIAL_SIG_SIZE = 32
_SIGNATURE_SIZE = 64

_PUBNONCE_BUFFER_TYPE = ffi.typeof(f"char[{_PUBNONCE_SIZE}]")
_AGGNONCE_BUFFER_TYPE = ffi.typeof(f"char[{_AGGNONCE_SIZE}]")
_PARTIAL_SIG_BUFFER_TYPE = ffi.typeof(f"char[{_PARTIAL_SIG_SIZE}]")
_SIGNATURE_BUFFER_TYPE = ffi.typeof(f"char[{_SIGNATURE_SIZE}]")


def pubnonce_parse(pubnonce_bytes: BytesLike, name: str = "public nonce") -> CData:
    """Parse a signer's public nonce into its internal representation.

    Args:
        pubnonce_bytes: the public nonce, 66 bytes, as `nonce_gen` or
            `nonce_gen_counter` answered it through the `SecretNonce`
            they built.
        name: what the nonce is, as the exception should call it, for a
            caller parsing more than one array of them.

    Returns:
        The libsecp256k1 public nonce object.

    Raises:
        ValueError: if it is not 66 bytes, or not one BIP327 defines.
    """
    pubnonce_bytes = octets(pubnonce_bytes, name, _PUBNONCE_SIZE)
    pubnonce = ffi.new("secp256k1_musig_pubnonce *")
    if not lib.secp256k1_musig_pubnonce_parse(ctx, pubnonce, pubnonce_bytes):
        raise ValueError(f"invalid {name}")
    return pubnonce


def pubnonce_serialize(pubnonce: CData) -> bytes:
    """Serialize a parsed public nonce.

    Args:
        pubnonce: the libsecp256k1 public nonce object, as `pubnonce_parse`
            returns.

    Returns:
        Its 66 bytes.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object, which one it
            produced cannot make it do.
    """
    output = ffi.new(_PUBNONCE_BUFFER_TYPE)
    if not lib.secp256k1_musig_pubnonce_serialize(ctx, output, pubnonce):
        raise RuntimeError("public nonce serialization failed")
    return ffi.unpack(output, _PUBNONCE_SIZE)


def aggnonce_parse(aggnonce_bytes: BytesLike, name: str = "aggregate nonce") -> CData:
    """Parse an aggregate public nonce into its internal representation.

    Args:
        aggnonce_bytes: the aggregate nonce, 66 bytes, as `nonce_agg`
            answered it.
        name: what the nonce is, as the exception should call it.

    Returns:
        The libsecp256k1 aggregate nonce object.

    Raises:
        ValueError: if it is not 66 bytes, or not one BIP327 defines.
    """
    aggnonce_bytes = octets(aggnonce_bytes, name, _AGGNONCE_SIZE)
    aggnonce = ffi.new("secp256k1_musig_aggnonce *")
    if not lib.secp256k1_musig_aggnonce_parse(ctx, aggnonce, aggnonce_bytes):
        raise ValueError(f"invalid {name}")
    return aggnonce


def aggnonce_serialize(aggnonce: CData) -> bytes:
    """Serialize a parsed aggregate public nonce.

    Args:
        aggnonce: the libsecp256k1 aggregate nonce object, as
            `aggnonce_parse` returns.

    Returns:
        Its 66 bytes.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object, which one it
            produced cannot make it do.
    """
    output = ffi.new(_AGGNONCE_BUFFER_TYPE)
    if not lib.secp256k1_musig_aggnonce_serialize(ctx, output, aggnonce):
        raise RuntimeError("aggregate nonce serialization failed")
    return ffi.unpack(output, _AGGNONCE_SIZE)


def partial_sig_parse(
    partial_sig_bytes: BytesLike, name: str = "partial signature"
) -> CData:
    """Parse a partial signature into its internal representation.

    Args:
        partial_sig_bytes: the partial signature, 32 bytes, as
            `SecretNonce.partial_sign` answered it.
        name: what the signature is, as the exception should call it.

    Returns:
        The libsecp256k1 partial signature object.

    Raises:
        ValueError: if it is not 32 bytes, or not one below the curve
            order.
    """
    partial_sig_bytes = octets(partial_sig_bytes, name, _PARTIAL_SIG_SIZE)
    partial_sig = ffi.new("secp256k1_musig_partial_sig *")
    if not lib.secp256k1_musig_partial_sig_parse(ctx, partial_sig, partial_sig_bytes):
        raise ValueError(f"invalid {name}")
    return partial_sig


def partial_sig_serialize(partial_sig: CData) -> bytes:
    """Serialize a parsed partial signature.

    Args:
        partial_sig: the libsecp256k1 partial signature object, as
            `partial_sig_parse` returns.

    Returns:
        Its 32 bytes.

    Raises:
        RuntimeError: if libsecp256k1 refuses the object, which one it
            produced cannot make it do.
    """
    output = ffi.new(_PARTIAL_SIG_BUFFER_TYPE)
    if not lib.secp256k1_musig_partial_sig_serialize(ctx, output, partial_sig):
        raise RuntimeError("partial signature serialization failed")
    return ffi.unpack(output, _PARTIAL_SIG_SIZE)


def nonce_agg(pubnonces_bytes: Sequence[BytesLike]) -> bytes:
    """Aggregate the signers' public nonces into one, for `Session`.

    Any party can do this, trusted or not: an aggregate nonce computed
    wrong makes the final signature invalid rather than makes it forge,
    so BIP327 lets an untrusted coordinator collect the round-one
    nonces and hand every signer this one value back instead of every
    other signer's.

    Args:
        pubnonces_bytes: the signers' public nonces, 66 bytes each, in
            the order `Session.partial_sig_agg` will later take their
            partial signatures. At least one is required.

    Returns:
        The 66-byte aggregate nonce.

    Raises:
        ValueError: if the sequence is empty, or if one of the nonces is
            not 66 bytes or not one BIP327 defines -- named by its
            position in the sequence, `pubnonces_bytes[0]` being "public
            nonce at index 0".
        RuntimeError: if libsecp256k1 fails to aggregate or serialize the
            result, which no valid input can make it do.
    """
    if not pubnonces_bytes:
        raise ValueError("at least one public nonce is required")
    # a per-contribution parse loop, not a comprehension calling
    # `pubnonce_parse` with its default name: the array this is built
    # into is what secp256k1_musig_nonce_agg takes, and a bare 0 back
    # from it says nothing about which contribution was bad -- the index
    # has to come from parsing each one under its own name, which is
    # what the module docstring's "a parse failure ... tells this
    # package nothing" is about
    pubnonces = [
        pubnonce_parse(pubnonce_bytes, f"public nonce at index {index}")
        for index, pubnonce_bytes in enumerate(pubnonces_bytes)
    ]
    aggnonce = ffi.new("secp256k1_musig_aggnonce *")
    if not lib.secp256k1_musig_nonce_agg(
        ctx, aggnonce, array("secp256k1_musig_pubnonce *[]", pubnonces), len(pubnonces)
    ):
        raise RuntimeError("nonce aggregation failed")
    return aggnonce_serialize(aggnonce)


class KeyAggCache:
    """The aggregate of a set of signers' public keys, and its tweaks.

    What `secp256k1_musig_keyagg_cache` holds: the aggregate public key
    BIP327 calls `Q`, the per-signer coefficients it is built from, and
    the running sum of any tweak applied since. It has no serialization,
    which the module docstring explains, and holding it here rather than
    parsing it back from octets on every call is not an optimization
    over some other spelling -- there is no other spelling, a cache
    built once being the only way `nonce_gen`, `Session` and
    `SecretNonce.partial_sign` can be handed the aggregation they need.

    Building one is `secp256k1_musig_pubkey_agg`, which orders the keys
    exactly as given: `keys.pubkey_sort` first is BIP327's own rule for
    reaching one aggregate key independently of the order the signers'
    public keys arrived in, and is the caller's to apply, this taking
    the sequence as it stands.

    Args:
        pubkeys_bytes: the signers' public keys, 33 or 65 bytes each, in
            aggregation order. At least one is required.

    Raises:
        ValueError: if the sequence is empty, or if one of the keys is
            not a valid point -- named by its position in the sequence,
            `pubkeys_bytes[0]` being "public key at index 0".
        RuntimeError: if libsecp256k1 fails to aggregate or serialize the
            result, which no valid input can make it do.

    Example:
        >>> from btclib_secp256k1 import keys, musig
        >>> pubkeys = [keys.pubkey_from_prvkey(1), keys.pubkey_from_prvkey(2)]
        >>> cache = musig.KeyAggCache(pubkeys)
        >>> len(cache.agg_pubkey)
        32
    """

    # pydoclint (DOC301) asks that this carry no docstring of its own,
    # the class docstring above being where the constructor is documented
    def __init__(self, pubkeys_bytes: Sequence[BytesLike]) -> None:  # noqa: D107
        if not pubkeys_bytes:
            raise ValueError("at least one public key is required")
        # a per-contribution parse loop, for the reason nonce_agg's has
        pubkeys = [
            keys.parse(pubkey_bytes, f"public key at index {index}")
            for index, pubkey_bytes in enumerate(pubkeys_bytes)
        ]
        cache = ffi.new("secp256k1_musig_keyagg_cache *")
        agg_pk = ffi.new("secp256k1_xonly_pubkey *")
        if not lib.secp256k1_musig_pubkey_agg(
            ctx, agg_pk, cache, array("secp256k1_pubkey *[]", pubkeys), len(pubkeys)
        ):
            raise RuntimeError("key aggregation failed")
        self._cache = cache
        # BIP327's Q, before any tweak: pubkey_agg is the only call that
        # answers it, so it is captured now or not at all -- pubkey_get
        # below answers the *current*, possibly tweaked aggregate instead
        self.agg_pubkey = xonly.serialize(agg_pk)

    def pubkey_get(self, compressed: bool = True) -> bytes:
        """Return the current aggregate public key, tweaks included.

        Useful for the non-xonly form of the aggregate key -- plain
        tweaking, or batch-verifying more than one key aggregation, which
        libsecp256k1 does not implement -- where `agg_pubkey` is the
        x-only one and BIP341 taproot tweaking wants the full point.

        Args:
            compressed: whether to return 33 bytes rather than 65.

        Returns:
            The serialized aggregate public key, as it stands after
            every `pubkey_ec_tweak_add` and `pubkey_xonly_tweak_add`
            made so far.

        Raises:
            RuntimeError: if libsecp256k1 fails to read or serialize it,
                which a cache this built cannot make it do.
        """
        agg_pk = ffi.new("secp256k1_pubkey *")
        if not lib.secp256k1_musig_pubkey_get(ctx, agg_pk, self._cache):
            raise RuntimeError("aggregate public key extraction failed")
        return keys.serialize(agg_pk, compressed)

    def pubkey_ec_tweak_add(
        self, tweak: BytesLike | int, compressed: bool = True
    ) -> bytes:
        """Add a plain EC tweak to the aggregate key, e.g. a BIP32 step.

        The MuSig2 counterpart of `keys.pubkey_tweak_add`: the tweaking
        method is the same, and what differs is that it is applied to
        this cache's running aggregate rather than to an argument, so
        that signing for the tweaked key is `SecretNonce.partial_sign`
        against the cache afterwards rather than against a key nobody
        holds the private share of directly.

        Args:
            tweak: the tweak, 32 bytes or an int below 2**256. Callers
                are responsible for deriving it in a way that does not
                reduce MuSig2's security, BIP32 being such a way.
            compressed: whether to return 33 bytes rather than 65.

        Returns:
            The serialized tweaked aggregate public key.

        Raises:
            ValueError: if the tweak is not 32 bytes or does not fit in
                them, or if the tweak or the resulting key is invalid.
            RuntimeError: if libsecp256k1 fails to serialize the result,
                which no valid input can make it do.
        """
        return self._tweak_add(
            lib.secp256k1_musig_pubkey_ec_tweak_add, tweak, compressed
        )

    def pubkey_xonly_tweak_add(
        self, tweak: BytesLike | int, compressed: bool = True
    ) -> bytes:
        """Add a BIP341 x-only tweak to the aggregate key, for a taproot output.

        `xonly.tweak_add`'s equation, applied to this cache instead of
        to a bare argument: `xonly.tweak_add_check` on the x-only form of
        what this returns, `agg_pubkey` and the same tweak, holds exactly
        as it does for a solo taproot key. This is required, rather than
        `xonly.tweak_add` on `agg_pubkey` directly, wherever a signature
        is wanted for the tweaked key: `xonly.tweak_add` leaves this
        cache untweaked, so a later `SecretNonce.partial_sign` would sign
        for the untweaked aggregate instead.

        Args:
            tweak: the tweak, 32 bytes or an int below 2**256. Callers
                are responsible for deriving it in a way that does not
                reduce MuSig2's security, BIP341 being such a way.
            compressed: whether to return 33 bytes rather than 65.

        Returns:
            The serialized tweaked aggregate public key.

        Raises:
            ValueError: if the tweak is not 32 bytes or does not fit in
                them, or if the tweak or the resulting key is invalid.
            RuntimeError: if libsecp256k1 fails to serialize the result,
                which no valid input can make it do.
        """
        return self._tweak_add(
            lib.secp256k1_musig_pubkey_xonly_tweak_add, tweak, compressed
        )

    def _tweak_add(
        self, tweak_add: CData, tweak: BytesLike | int, compressed: bool
    ) -> bytes:
        """Apply the tweak both public methods share, told apart by the C call.

        Args:
            tweak_add: `secp256k1_musig_pubkey_ec_tweak_add` or
                `secp256k1_musig_pubkey_xonly_tweak_add`, already bound.
            tweak: the tweak, 32 bytes or an int below 2**256.
            compressed: whether to return 33 bytes rather than 65.

        Returns:
            The serialized tweaked aggregate public key.

        Raises:
            ValueError: if the tweak is not 32 bytes or does not fit in
                them, or if the tweak or the resulting key is invalid.
            RuntimeError: if libsecp256k1 fails to serialize the result,
                which no valid input can make it do.
        """
        tweak_bytes = scalar(tweak, "tweak")
        output = ffi.new("secp256k1_pubkey *")
        if not tweak_add(ctx, output, self._cache, tweak_bytes):
            raise ValueError("invalid tweak or resulting public key")
        return keys.serialize(output, compressed)

    def _cache_(self) -> CData:
        """Return the libsecp256k1 keyagg cache object this holds.

        The private half every other entry point of this module reaches
        for: `nonce_gen`, `nonce_gen_counter`, `Session.__init__` and
        `SecretNonce.partial_sign` all take a `KeyAggCache` and read it
        through this rather than through a public attribute, so that
        nothing outside this class can replace what it points at.

        Returns:
            The libsecp256k1 keyagg cache object, mutated in place by
            `pubkey_ec_tweak_add` and `pubkey_xonly_tweak_add`.
        """
        return self._cache


def nonce_gen(
    pubkey_bytes: BytesLike,
    prvkey: BytesLike | int | None = None,
    msg32: BytesLike | None = None,
    keyagg_cache: KeyAggCache | None = None,
    extra_input32: BytesLike | None = None,
) -> SecretNonce:
    """Start a signing session by generating a nonce.

    Round one of BIP327: the public nonce this answers is sent to every
    other signer, or to whoever aggregates them, and the secret nonce is
    kept -- held by the `SecretNonce` this returns, until a matching
    `Session` exists to call its `partial_sign`.

    The 32 bytes of session randomness BIP327 requires, unique to this
    call and never reused, is not a parameter: it is generated here with
    `secrets.token_bytes`, the same source the rest of this package's
    randomness comes from, because the one thing a caller could do with
    it -- supply their own -- is the one thing the header warns against
    doing twice.

    Args:
        pubkey_bytes: the public key of the signer this nonce is for, 33
            or 65 bytes. The secnonce this answers can only sign for a
            keypair matching it, which `SecretNonce.partial_sign` asks
            libsecp256k1 to check.
        prvkey: this signer's private key, 32 bytes or an int below
            2**256, if already known. Optional, and folded into the
            nonce derivation to increase misuse-resistance where given;
            using the same private key across several MuSig2 sessions is
            fine.
        msg32: the 32-byte message this session will sign, if already
            known. Optional, for the same reason.
        keyagg_cache: the key aggregation this session signs under, if
            already known. Optional, for the same reason.
        extra_input32: 32 bytes that do not repeat in normal use, such as
            the current time, folded into the derivation alongside the
            above. Optional, and no substitute for the session
            randomness above, which is what carries the uniqueness
            requirement.

    Returns:
        The secret nonce, held rather than returned as octets: the
        module docstring says why, and `SecretNonce` is what a caller
        wipes if this session is abandoned before `partial_sign`.

    Raises:
        ValueError: if the public key is not a valid point, if the
            private key is given and is not 32 bytes, does not fit in
            them, or is not in [1, n-1], or if `msg32` or
            `extra_input32` is given and is not 32 bytes.
    """
    pubkey = keys.parse(pubkey_bytes, "public key")
    prvkey_bytes = None if prvkey is None else scalar(prvkey, "private key")
    msg_bytes = None if msg32 is None else octets(msg32, "message", 32)
    extra_bytes = (
        None if extra_input32 is None else octets(extra_input32, "extra_input32", 32)
    )
    cache = ffi.NULL if keyagg_cache is None else keyagg_cache._cache_()

    secnonce = ffi.new("secp256k1_musig_secnonce *")
    pubnonce = ffi.new("secp256k1_musig_pubnonce *")
    session_secrand = ffi.new("unsigned char[32]", secrets.token_bytes(32))
    try:
        generated = lib.secp256k1_musig_nonce_gen(
            ctx,
            secnonce,
            pubnonce,
            session_secrand,
            ffi.NULL if prvkey_bytes is None else prvkey_bytes,
            pubkey,
            ffi.NULL if msg_bytes is None else msg_bytes,
            cache,
            ffi.NULL if extra_bytes is None else extra_bytes,
        )
    finally:
        # this package's own scratch randomness, owed a wipe whether the
        # call used it or refused it first -- libsecp256k1 only zeroes it
        # itself on success, see the header of secp256k1_musig_nonce_gen
        wipe(session_secrand)
    if not generated:
        raise ValueError("invalid private key: not in [1, n-1]")
    return SecretNonce(secnonce, pubnonce, pubkey)


def nonce_gen_counter(
    prvkey: BytesLike | int,
    nonrepeating_cnt: int,
    msg32: BytesLike | None = None,
    keyagg_cache: KeyAggCache | None = None,
    extra_input32: BytesLike | None = None,
) -> SecretNonce:
    """Start a signing session, deriving the nonce from a counter instead.

    The alternative to `nonce_gen` for a signer with a non-repeating
    counter rather than good randomness available -- a hardware signer
    keeping one in place of an RNG it does not trust, which is what this
    exists for. The counter must never repeat for this private key: two
    calls with the same keypair and the same `nonrepeating_cnt`, on any
    device signing with that key, reuse the nonce.

    Args:
        prvkey: this signer's private key, 32 bytes or an int below
            2**256. Mandatory here, where `nonce_gen`'s is optional: the
            counter's uniqueness is a property of the key it counts for.
        nonrepeating_cnt: the counter value, an int in [0, 2**64 - 1],
            unique to this call for this private key.
        msg32: the 32-byte message this session will sign, if already
            known.
        keyagg_cache: the key aggregation this session signs under, if
            already known.
        extra_input32: 32 bytes that do not repeat in normal use, folded
            into the derivation alongside the above.

    Returns:
        The secret nonce, as `nonce_gen` returns it.

    Raises:
        TypeError: if `nonrepeating_cnt` is not an int.
        ValueError: if the private key is not 32 bytes, does not fit in
            them, or is not in [1, n-1], if `nonrepeating_cnt` is out of
            range, if `extra_input32` is given and is not 32 bytes, or if
            `msg32` is given and is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to extract the public key or
            to generate the nonce, which a private key already verified
            cannot make it do.
    """
    nonrepeating_cnt = in_range(nonrepeating_cnt, "nonrepeating_cnt", 2**64 - 1)
    msg_bytes = None if msg32 is None else octets(msg32, "message", 32)
    extra_bytes = (
        None if extra_input32 is None else octets(extra_input32, "extra_input32", 32)
    )
    cache = ffi.NULL if keyagg_cache is None else keyagg_cache._cache_()

    keypair_obj = keypair(prvkey)
    try:
        pubkey = ffi.new("secp256k1_pubkey *")
        if not lib.secp256k1_keypair_pub(ctx, pubkey, keypair_obj):
            raise RuntimeError("public key extraction failed")

        secnonce = ffi.new("secp256k1_musig_secnonce *")
        pubnonce = ffi.new("secp256k1_musig_pubnonce *")
        generated = lib.secp256k1_musig_nonce_gen_counter(
            ctx,
            secnonce,
            pubnonce,
            nonrepeating_cnt,
            keypair_obj,
            ffi.NULL if msg_bytes is None else msg_bytes,
            cache,
            ffi.NULL if extra_bytes is None else extra_bytes,
        )
    finally:
        # the keypair carries the private key: overwrite it whether the
        # nonce was made or refused, as ssa.sign does with its own
        wipe(keypair_obj)
    if not generated:
        raise RuntimeError("nonce generation failed")
    return SecretNonce(secnonce, pubnonce, pubkey)


class SecretNonce:
    """A signer's secret nonce, held between `nonce_gen` and `partial_sign`.

    `nonce_gen` and `nonce_gen_counter` are the two ways to obtain one --
    this is never built from octets, there being no parser for a secret
    nonce by design: "Avoid copying (or serializing) the secnonce. This
    reduces the possibility that it is used more than once for signing",
    the header says, and a parser is exactly a way to make a copy.

    What `ssa.Signer` documents about holding a keypair holds here for
    the same reason: `wipe`, or the `with` statement that calls it on the
    way out of the block, overwrites the secret nonce whether the block
    produced a signature or raised. `partial_sign` also wipes it, being
    the call whose whole point is to consume it -- so a nonce used once is
    already gone by the time `wipe` might run again, and wiping a second
    time is not an error, exactly as `ssa.Signer.wipe` is not either.

    A `SecretNonce` told neither is dropped holding the secret, cffi
    freeing the memory without overwriting it: SECURITY.md names this as
    the second buffer in this package whose zeroing is asked for rather
    than done.

    Signing at most once is the whole reason this class exists, and on
    a free-threaded interpreter that has to be true of two threads
    calling `partial_sign` on the same object, not only of one: reading
    `self._secnonce` and then clearing it are two statements, and two
    threads each passing the read before either reaches the clear would
    both go on to drive `secp256k1_musig_partial_sign` over the same
    native secnonce at once, an unsynchronized concurrent access on the
    exact memory a nonce-reuse leak comes from. `_take` is where the
    read and the clear become one statement instead of two, under a
    lock private to this instance -- there being no reason for two
    `SecretNonce` objects to serialize on each other's locks, unlike the
    one shared libsecp256k1 context. Thread safety here is that lock,
    not the constness `ssa.Signer`'s relies on: this is the one buffer
    in the package meant to be read exactly once, where a keypair is
    meant to be read any number of times.

    Args:
        secnonce: the libsecp256k1 secret nonce object `nonce_gen` or
            `nonce_gen_counter` built.
        pubnonce: the matching public nonce object, already parsed.
        pubkey: the signer's already-parsed public key, kept for
            `partial_sign`'s own `verify`.

    Example:
        >>> from btclib_secp256k1 import keys, musig
        >>> prvkey, pubkey = 1, keys.pubkey_from_prvkey(1)
        >>> with musig.nonce_gen(pubkey, prvkey) as secnonce:
        ...     len(secnonce.pubnonce)
        66
    """

    # pydoclint (DOC301) asks that this carry no docstring of its own,
    # the class docstring above being where the constructor is documented
    def __init__(self, secnonce: CData, pubnonce: CData, pubkey: CData) -> None:  # noqa: D107
        self._secnonce: CData | None = secnonce
        self._pubnonce = pubnonce
        self._pubkey = pubkey
        self.pubnonce = pubnonce_serialize(pubnonce)
        # private to this instance: what it orders is one SecretNonce's
        # own check-and-clear, not calls into libsecp256k1, so it is not
        # the shared context's lock and does not compete with it
        self._lock = threading.Lock()

    def partial_sign(
        self,
        prvkey: BytesLike | int,
        keyagg_cache: KeyAggCache,
        session: Session,
        *,
        verify: bool = True,
    ) -> bytes:
        """Produce this signer's partial signature, and wipe the secret nonce.

        Whatever the outcome -- a signature, a refusal or an exception --
        the secret nonce this holds does not survive the call: `wipe`
        below is not needed afterwards, and calling it anyway is not an
        error, as the class docstring says.

        Args:
            prvkey: this signer's private key, 32 bytes or an int below
                2**256, matching the public key `nonce_gen` or
                `nonce_gen_counter` built this nonce for.
            keyagg_cache: the key aggregation this session signs under,
                the same one the nonce was generated against if one was.
            session: the session `Session.__init__` built from the
                aggregate nonce this signer's public nonce contributed
                to.
            verify: whether to check the partial signature against this
                signer's public nonce and public key before returning
                it, as the module docstring explains and BIP327's own
                header recommends.

        Returns:
            The 32-byte partial signature.

        Raises:
            ValueError: if this secret nonce has already been spent or
                wiped, if the private key is not 32 bytes, does not fit
                in them, or is not in [1, n-1], or if it does not match
                this secret nonce, or `keyagg_cache` or `session` do not.
            RuntimeError: if `verify` asks and the partial signature does
                not verify, which no input reaching this far can make
                happen.
        """
        # _take, not _held: it clears self._secnonce as the one
        # statement that reads it, which is what keeps two threads
        # calling this on the same object from both passing a check and
        # both going on to sign -- the class docstring says why that
        # race is the one this class exists to rule out
        secnonce = self._take()
        keypair_obj: CData | None = None
        partial_sig = ffi.new("secp256k1_musig_partial_sig *")
        try:
            # keypair(prvkey) is inside the try on purpose: it is the
            # one fallible step here that runs before libsecp256k1 ever
            # sees secnonce, and the docstring's guarantee -- the secret
            # nonce does not survive the call, whatever the outcome --
            # has to hold even when this raises before that call is made
            keypair_obj = keypair(prvkey)
            signed = lib.secp256k1_musig_partial_sign(
                ctx,
                partial_sig,
                secnonce,
                keypair_obj,
                keyagg_cache._cache_(),
                session._session_(),
            )
        finally:
            # the keypair carries the private key, wiped as ssa.sign
            # wipes its own -- and only if it was built at all, a
            # private key `keypair` refused never having become one.
            # The secret nonce is spent regardless: libsecp256k1
            # zeroes it once its own call is made, right after loading
            # it and before any of its other checks can fail, but a
            # keypair that failed to build never reaches that call --
            # so this wipes it here too, unconditionally, rather than
            # trust a C side effect that this exception proves did not
            # run. Wiping twice is not a problem, so which of the two
            # happened is not asked. self._secnonce is already cleared,
            # by _take above, before this thread did anything else with
            # the object it returned
            if keypair_obj is not None:
                wipe(keypair_obj)
            wipe(secnonce)
        if not signed:
            msg = (
                "the private key, key aggregation cache or session do not"
                " match this secret nonce"
            )
            raise ValueError(msg)
        if verify and not lib.secp256k1_musig_partial_sig_verify(
            ctx,
            partial_sig,
            self._pubnonce,
            self._pubkey,
            keyagg_cache._cache_(),
            session._session_(),
        ):
            raise RuntimeError(
                "partial signing produced a signature that does not verify"
            )
        return partial_sig_serialize(partial_sig)

    def wipe(self) -> None:
        """Overwrite the secret nonce, ending what this can sign.

        Signing afterwards raises rather than signing with the zeros
        left behind, and there is no reviving it: nothing here keeps the
        nonce anywhere else, so a session abandoned this way is
        restarted with a fresh `nonce_gen` rather than resumed. Takes
        the same lock `partial_sign` does, so a `wipe` racing a
        `partial_sign` call on another thread cannot see the buffer
        between the two: whichever of them clears `self._secnonce`
        first is the one that goes on to act on it, and the other finds
        nothing left to take.
        """
        with self._lock:
            secnonce = self._secnonce
            self._secnonce = None
        if secnonce is not None:
            wipe(secnonce)

    # PYI034 asks for `typing.Self` here, and that is 3.11 while this
    # package supports 3.10, as ssa.Signer's own comment says
    def __enter__(self) -> SecretNonce:  # noqa: PYI034
        """Return this secret nonce, for the `with` block that wipes it.

        Returns:
            This object, nothing being built here that the constructor
            did not already build.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Wipe the secret nonce, whatever ended the block.

        Args:
            exc_type: the class of the exception ending the block, if
                one is.
            exc_value: that exception.
            traceback: its traceback.
        """
        self.wipe()

    def _take(self) -> CData:
        """Read the secret nonce and clear it, as one atomic step.

        The private half of the guarantee `partial_sign` and `wipe`
        both make: "is there a secret nonce" and "take it" have to be
        one operation, under `self._lock`, or two threads calling
        `partial_sign` on the same object could each pass the read
        before either reaches the clear, and both go on to sign with
        it -- the class docstring says what that race would cost.

        Returns:
            The libsecp256k1 secret nonce object. `self._secnonce` is
            already `None` by the time this returns it, so no other
            call -- from any thread -- can receive the same object
            again.

        Raises:
            ValueError: if `wipe` or a previous `partial_sign` has
                already taken it.
        """
        with self._lock:
            secnonce = self._secnonce
            self._secnonce = None
        if secnonce is None:
            raise ValueError("this secret nonce has been wiped or already spent")
        return secnonce


class Session:
    """A MuSig2 signing session, opened from the signers' aggregate nonce.

    What `secp256k1_musig_nonce_process` produces: the message, the
    aggregate nonce and the key aggregation are fixed into it, and
    `SecretNonce.partial_sign`, `partial_sig_verify` and
    `partial_sig_agg` all read the session rather than those three
    again. Like `KeyAggCache`, this has no serialization -- the module
    docstring explains why that is taken as an exception here -- and,
    also like it, holds nothing secret: the header says a session "is
    not required to be kept secret for the signing protocol to be
    secure".

    Args:
        aggnonce_bytes: the aggregate of the signers' public nonces, 66
            bytes, as `nonce_agg` answered it.
        msg32: the 32-byte message this session signs.
        keyagg_cache: the key aggregation this session signs under.

    Raises:
        ValueError: if `aggnonce_bytes` is not 66 bytes or not one
            BIP327 defines, or if the message is not 32 bytes.
        RuntimeError: if libsecp256k1 fails to build the session, which
            no valid input can make it do.

    Example:
        >>> from btclib_secp256k1 import keys, musig
        >>> pubkeys = [keys.pubkey_from_prvkey(1), keys.pubkey_from_prvkey(2)]
        >>> cache = musig.KeyAggCache(pubkeys)
        >>> secnonces = [
        ...     musig.nonce_gen(pk, i + 1) for i, pk in enumerate(pubkeys)
        ... ]
        >>> pubnonces = [s.pubnonce for s in secnonces]
        >>> aggnonce = musig.nonce_agg(pubnonces)
        >>> session = musig.Session(aggnonce, bytes(32), cache)
    """

    # pydoclint (DOC301) asks that this carry no docstring of its own,
    # the class docstring above being where the constructor is documented
    def __init__(  # noqa: D107
        self, aggnonce_bytes: BytesLike, msg32: BytesLike, keyagg_cache: KeyAggCache
    ) -> None:
        aggnonce = aggnonce_parse(aggnonce_bytes)
        msg_bytes = octets(msg32, "message", 32)
        session = ffi.new("secp256k1_musig_session *")
        if not lib.secp256k1_musig_nonce_process(
            ctx, session, aggnonce, msg_bytes, keyagg_cache._cache_()
        ):
            raise RuntimeError("nonce processing failed")
        self._session = session

    def partial_sig_verify(
        self,
        partial_sig_bytes: BytesLike,
        pubnonce_bytes: BytesLike,
        pubkey_bytes: BytesLike,
        keyagg_cache: KeyAggCache,
    ) -> bool:
        """Verify one signer's partial signature, within this session.

        Not required in a regular session: an aggregate signature that
        fails `ssa.verify` was made from at least one bad partial
        signature, but does not say which. This is the call that finds
        out, at the cost of one verification per signer instead of one
        for the aggregate.

        Args:
            partial_sig_bytes: the partial signature to verify, 32 bytes.
            pubnonce_bytes: the public nonce of the signer it is
                attributed to, 66 bytes, exactly as it went into
                `nonce_agg`.
            pubkey_bytes: the public key of that signer, 33 or 65 bytes,
                exactly as it went into the `KeyAggCache` this session's
                key aggregation came from.
            keyagg_cache: that key aggregation.

        Returns:
            True if the partial signature is valid for that signer's
            nonce and key, within this session.

        Raises:
            ValueError: if any of the three byte arguments is not the
                right length or not one libsecp256k1 will read.
        """
        partial_sig = partial_sig_parse(partial_sig_bytes)
        pubnonce = pubnonce_parse(pubnonce_bytes)
        pubkey = keys.parse(pubkey_bytes, "public key")
        return bool(
            lib.secp256k1_musig_partial_sig_verify(
                ctx,
                partial_sig,
                pubnonce,
                pubkey,
                keyagg_cache._cache_(),
                self._session,
            )
        )

    def partial_sig_agg(self, partial_sigs_bytes: Sequence[BytesLike]) -> bytes:
        """Aggregate the signers' partial signatures into the final one.

        The result is a plain BIP340 signature -- `ssa.verify` against
        the key aggregation's `pubkey_get` (or its x-only form,
        `agg_pubkey`, where no tweak was applied) is how a caller checks
        it, this answering 1 "which does NOT mean the resulting
        signature verifies", in the header's own words.

        Args:
            partial_sigs_bytes: the signers' partial signatures, 32
                bytes each, one per signer of this session. At least
                one is required.

        Returns:
            The 64-byte aggregate signature.

        Raises:
            ValueError: if the sequence is empty, or if one of the
                partial signatures is not 32 bytes or not one below the
                curve order -- named by its position in the sequence,
                `partial_sigs_bytes[0]` being "partial signature at
                index 0".
            RuntimeError: if libsecp256k1 fails to aggregate the result,
                which no valid input can make it do.
        """
        if not partial_sigs_bytes:
            raise ValueError("at least one partial signature is required")
        # a per-contribution parse loop, for the reason nonce_agg's has
        partial_sigs = [
            partial_sig_parse(partial_sig_bytes, f"partial signature at index {index}")
            for index, partial_sig_bytes in enumerate(partial_sigs_bytes)
        ]
        signature = ffi.new(_SIGNATURE_BUFFER_TYPE)
        if not lib.secp256k1_musig_partial_sig_agg(
            ctx,
            signature,
            self._session,
            array("secp256k1_musig_partial_sig *[]", partial_sigs),
            len(partial_sigs),
        ):
            raise RuntimeError("partial signature aggregation failed")
        return ffi.unpack(signature, _SIGNATURE_SIZE)

    def _session_(self) -> CData:
        """Return the libsecp256k1 session object this holds.

        Returns:
            The libsecp256k1 session object, read by
            `SecretNonce.partial_sign` and by this class's own methods.
        """
        return self._session

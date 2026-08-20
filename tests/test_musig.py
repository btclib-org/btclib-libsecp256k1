# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`musig` holds state, which is the one thing the other modules do not.

`tests/test_vectors.py` holds `musig` to BIP327's own vectors, case by
case; what is left for this file is what a vector cannot state, the same
split `tests/test_signer.py` makes for `ssa.Signer`: the lifetime the
three classes hand the caller. `KeyAggCache` and `Session` hold nothing
secret, so what is asserted of them here is the shape of a session end
to end, and that a bad contribution to `pubkey_agg`, `nonce_agg` or
`partial_sig_agg` is named by its position. `SecretNonce` does hold a
secret, and what is asserted of it is `wipe`'s cases -- overwritten,
consumed by `partial_sign`, wiped twice, dropped -- the same shape
`tests/test_signer.py` holds `ssa.Signer` to, and for the reason
SECURITY.md gives: this is the second buffer in the package whose
zeroing is asked for rather than done.
"""

from __future__ import annotations

import gc
import hashlib

import pytest

from btclib_secp256k1 import ffi, keys, lib, musig, ssa
from btclib_secp256k1.context import check, ctx

PRVKEYS = [(1).to_bytes(32, "big"), (2).to_bytes(32, "big")]
PUBKEYS = [keys.pubkey_from_prvkey(prvkey) for prvkey in PRVKEYS]
MSG = hashlib.sha256(b"btclib_secp256k1 musig").digest()


def secnonce_memory(secnonce: musig.SecretNonce) -> bytes:
    """Return the octets of the secret nonce a `SecretNonce` holds.

    Reaching into the object is the only way to ask, exactly as
    `tests/test_signer.py`'s `keypair_memory` does for `ssa.Signer`.

    Args:
        secnonce: the secret nonce to look inside.

    Returns:
        The 132 octets of the `secp256k1_musig_secnonce`, or an empty
        bytes once it has been wiped or spent.
    """
    held = secnonce._secnonce
    return b"" if held is None else bytes(ffi.buffer(held))


def two_of_two_session() -> tuple[
    musig.KeyAggCache, list[musig.SecretNonce], musig.Session
]:
    """Build a 2-of-2 key aggregation, nonces and session, up to round two.

    Returns:
        The key aggregation, one `SecretNonce` per signer in `PRVKEYS`
        order, and the session `partial_sign` and `partial_sig_verify`
        are checked against.
    """
    cache = musig.KeyAggCache(PUBKEYS)
    secnonces = [
        musig.nonce_gen(pubkey, prvkey, msg32=MSG, keyagg_cache=cache)
        for prvkey, pubkey in zip(PRVKEYS, PUBKEYS, strict=True)
    ]
    aggnonce = musig.nonce_agg([secnonce.pubnonce for secnonce in secnonces])
    session = musig.Session(aggnonce, MSG, cache)
    return cache, secnonces, session


def test_a_2_of_2_session_signs_and_verifies() -> None:
    """The usage example: aggregate, two rounds, and a plain BIP340 check.

    Every partial signature is checked with `partial_sig_verify` before
    aggregating, which a regular session does not need -- the module
    docstring says why it is worth doing anyway -- and the aggregate
    verifies under `KeyAggCache.agg_pubkey` exactly as BIP327 says it
    must, `ssa.verify` being the whole of the check: nothing in `musig`
    reimplements it.
    """
    cache, secnonces, session = two_of_two_session()
    pubnonces = [secnonce.pubnonce for secnonce in secnonces]

    partial_sigs = [
        secnonce.partial_sign(prvkey, cache, session)
        for secnonce, prvkey in zip(secnonces, PRVKEYS, strict=True)
    ]
    for partial_sig, pubnonce, pubkey in zip(
        partial_sigs, pubnonces, PUBKEYS, strict=True
    ):
        assert session.partial_sig_verify(partial_sig, pubnonce, pubkey, cache)

    signature = session.partial_sig_agg(partial_sigs)
    assert len(signature) == 64
    assert ssa.verify(MSG, cache.agg_pubkey, signature)


def test_partial_sign_without_verify_answers_the_same_signature() -> None:
    """`verify=False` skips the check and not the arithmetic.

    `secp256k1_musig_partial_sign` does not verify on its own -- the
    module docstring quotes the header on it -- so what `verify=True`
    adds on top is a call and not a different signature: the same
    secnonce, signed unverified, answers what `nonce_process` over the
    same aggregate nonce and message always would.
    """
    cache, secnonces, session = two_of_two_session()
    unverified = secnonces[0].partial_sign(PRVKEYS[0], cache, session, verify=False)
    assert session.partial_sig_verify(
        unverified, secnonces[0].pubnonce, PUBKEYS[0], cache
    )


def test_key_agg_cache_requires_at_least_one_key() -> None:
    """An empty sequence has no aggregate to compute."""
    with pytest.raises(ValueError, match="at least one public key"):
        musig.KeyAggCache([])


def test_key_agg_cache_reports_which_key_failed_to_parse() -> None:
    """The index of the bad key, not just that the aggregation failed.

    `secp256k1_musig_pubkey_agg` answers a bare 0 for it, the module
    docstring's own point about a parse failure telling this package
    nothing: the index is only available because `KeyAggCache` parses
    each contribution itself, under its own name.
    """
    with pytest.raises(ValueError, match="public key at index 1"):
        musig.KeyAggCache([PUBKEYS[0], b"\x00" * 33])


def test_nonce_agg_requires_at_least_one_pubnonce() -> None:
    """An empty sequence has no aggregate to compute."""
    with pytest.raises(ValueError, match="at least one public nonce"):
        musig.nonce_agg([])


def test_nonce_agg_reports_which_pubnonce_failed_to_parse() -> None:
    """The index of the bad nonce, as the key aggregation test has above."""
    _cache, secnonces, _session = two_of_two_session()
    with pytest.raises(ValueError, match="public nonce at index 1"):
        musig.nonce_agg([secnonces[0].pubnonce, bytes(66)])


def test_partial_sig_agg_requires_at_least_one_signature() -> None:
    """An empty sequence has no signature to aggregate."""
    _cache, _secnonces, session = two_of_two_session()
    with pytest.raises(ValueError, match="at least one partial signature"):
        session.partial_sig_agg([])


def test_partial_sig_agg_reports_which_signature_failed_to_parse() -> None:
    """The index of the bad signature, for the reason the two tests above have.

    32 octets above the curve order are what `partial_sig_parse` refuses:
    zero, and every other value below the order, parses fine and is
    caught only by `partial_sig_verify`, if at all.
    """
    cache, secnonces, session = two_of_two_session()
    good = secnonces[0].partial_sign(PRVKEYS[0], cache, session)
    with pytest.raises(ValueError, match="partial signature at index 1"):
        session.partial_sig_agg([good, b"\xff" * 32])


def test_key_agg_cache_tweaks_leave_agg_pubkey_alone() -> None:
    """`agg_pubkey` is BIP327's `Q`, fixed at construction, tweaks or not.

    `pubkey_get` is the current state instead, so the two answer
    differently once a tweak lands.
    """
    tweak = hashlib.sha256(b"btclib_secp256k1 musig tweak").digest()
    ec_cache = musig.KeyAggCache(PUBKEYS)
    before = ec_cache.agg_pubkey
    untweaked = ec_cache.pubkey_get()

    ec_tweaked = ec_cache.pubkey_ec_tweak_add(tweak)
    assert ec_cache.agg_pubkey == before
    assert ec_cache.pubkey_get() == ec_tweaked
    assert ec_tweaked != untweaked

    xonly_cache = musig.KeyAggCache(PUBKEYS)
    xonly_tweaked = xonly_cache.pubkey_xonly_tweak_add(tweak)
    assert xonly_cache.agg_pubkey == before
    assert xonly_tweaked != untweaked


def test_key_agg_cache_tweak_add_refuses_an_invalid_tweak() -> None:
    """A tweak that is the wrong length, or does not fit in 32 bytes."""
    cache = musig.KeyAggCache(PUBKEYS)
    with pytest.raises(ValueError, match="32 bytes"):
        cache.pubkey_ec_tweak_add(b"\x01" * 31)
    # 2**256 - 1, above the curve order: not a valid scalar
    with pytest.raises(ValueError, match="invalid tweak"):
        cache.pubkey_xonly_tweak_add(b"\xff" * 32)


def test_session_refuses_an_invalid_aggregate_nonce() -> None:
    """A wrong-length or unparsable aggregate nonce is refused at the parse."""
    cache = musig.KeyAggCache(PUBKEYS)
    with pytest.raises(ValueError, match="66 bytes"):
        musig.Session(bytes(65), MSG, cache)
    # 0x02 names no valid point at x = 0
    with pytest.raises(ValueError, match="invalid aggregate nonce"):
        musig.Session(b"\x02" + bytes(65), MSG, cache)


def test_session_refuses_a_message_of_the_wrong_length() -> None:
    """`nonce_process` signs a 32-byte message, `msg32` being its own name."""
    cache, secnonces, _session = two_of_two_session()
    aggnonce = musig.nonce_agg([secnonce.pubnonce for secnonce in secnonces])
    with pytest.raises(ValueError, match="message"):
        musig.Session(aggnonce, MSG + b"\x00", cache)


def test_partial_sig_verify_answers_false_for_a_wrong_signature() -> None:
    """A partial signature attributed to the wrong signer does not verify.

    Not required in a regular session, the module docstring's own words:
    what this checks is that a caller who does ask gets a verdict rather
    than an exception for octets that parse fine and simply are not the
    right answer.
    """
    cache, secnonces, session = two_of_two_session()
    sig0 = secnonces[0].partial_sign(PRVKEYS[0], cache, session)
    assert not session.partial_sig_verify(
        sig0, secnonces[1].pubnonce, PUBKEYS[1], cache
    )


def test_partial_sign_refuses_a_mismatched_private_key() -> None:
    """A secnonce signs only for the keypair `nonce_gen` built it for.

    libsecp256k1 checks the match through an ARG_CHECK and reports a
    bare 0 for it, which is conflated here with every other reason
    `partial_sign` can fail -- the module docstring's own point about a
    wrapper unable to tell them apart. What is asserted is that it is
    refused, and that the secret nonce is spent regardless, as it is for
    a signature that succeeds.
    """
    cache, secnonces, session = two_of_two_session()
    with pytest.raises(ValueError, match="do not match this secret nonce"):
        secnonces[0].partial_sign(PRVKEYS[1], cache, session)
    assert secnonce_memory(secnonces[0]) == b""
    # the mismatch is an ARG_CHECK, so it recorded an illegal argument on
    # this thread that nothing here read: drained so it is not raised by
    # a later, unrelated call to context.check(), as its own docstring
    # asks of a caller reaching an ARG_CHECK through anything but `lib`
    with pytest.raises(ValueError, match="secp256k1_fe_equal"):
        check()
    check()  # and now the thread is clean


def test_a_wiped_secret_nonce_refuses_to_sign() -> None:
    """Rather than signing with the zeros the wipe left."""
    cache, secnonces, session = two_of_two_session()
    secnonces[0].wipe()
    with pytest.raises(ValueError, match="wiped or already spent"):
        secnonces[0].partial_sign(PRVKEYS[0], cache, session)


def test_wipe_overwrites_the_secret_nonce() -> None:
    """The secret is in there until `wipe`, and gone after it."""
    secnonce = musig.nonce_gen(PUBKEYS[0], PRVKEYS[0])
    assert secnonce_memory(secnonce) != b""

    secnonce.wipe()
    assert secnonce_memory(secnonce) == b""


def test_partial_sign_wipes_the_secret_nonce_it_spends() -> None:
    """`partial_sign` wipes on the way out, whether it signs or is refused."""
    cache, secnonces, session = two_of_two_session()
    secnonces[0].partial_sign(PRVKEYS[0], cache, session)
    assert secnonce_memory(secnonces[0]) == b""


def test_the_with_block_wipes_whatever_ended_it() -> None:
    """A signature, and an exception, leave the same wiped secret nonce."""
    cache, secnonces, session = two_of_two_session()
    with secnonces[0] as secnonce:
        secnonce.partial_sign(PRVKEYS[0], cache, session)
    assert secnonce_memory(secnonces[0]) == b""

    raising = musig.nonce_gen(PUBKEYS[0], PRVKEYS[0])
    with pytest.raises(ValueError, match="what the block raised"), raising:
        raise ValueError("what the block raised")
    assert secnonce_memory(raising) == b""


def test_wiping_twice_is_not_an_error() -> None:
    """Signing consumes it, and wiping afterwards is not a mistake to report."""
    cache, secnonces, session = two_of_two_session()
    with secnonces[0] as secnonce:
        secnonce.partial_sign(PRVKEYS[0], cache, session)
    secnonces[0].wipe()
    assert secnonce_memory(secnonces[0]) == b""


def test_a_dropped_secret_nonce_leaves_the_memory_as_it_was() -> None:
    """Nothing wipes behind a caller who neither wipes nor uses `with`.

    SECURITY.md names this as the second buffer of the package whose
    zeroing is asked for rather than done, and this is that sentence as
    an assertion, matching `tests/test_signer.py`'s own for `ssa.Signer`.
    """
    secnonce = musig.nonce_gen(PUBKEYS[0], PRVKEYS[0])
    # kept alive here, and by nothing else once the secnonce is dropped
    held = secnonce._secnonce
    assert held is not None
    before = bytes(ffi.buffer(held))
    assert before != bytes(len(before))

    del secnonce
    gc.collect()  # refcounting has dropped it already; PyPy needs asking

    assert bytes(ffi.buffer(held)) == before


def test_nonce_gen_needs_only_a_public_key() -> None:
    """Every other argument is optional, and folds into the derivation."""
    secnonce = musig.nonce_gen(PUBKEYS[0])
    assert len(secnonce.pubnonce) == 66
    secnonce.wipe()


def test_nonce_gen_refuses_an_invalid_public_key() -> None:
    """The public key is parsed before any secret is generated."""
    with pytest.raises(ValueError, match="public key"):
        musig.nonce_gen(bytes(33))


# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@pytest.mark.parametrize("prvkey", [0, N])
def test_nonce_gen_refuses_a_private_key_out_of_range(prvkey: int) -> None:
    """The one way `secp256k1_musig_nonce_gen` can fail given valid octets.

    The public key, the message and the key aggregation cache are all
    already-proved objects by the time they reach it; the private key,
    given as octets rather than parsed, is the one argument libsecp256k1
    still checks for itself, `secp256k1_scalar_set_b32_seckey` rejecting
    zero and the group order the same way `keys.prvkey_verify` does.
    """
    with pytest.raises(ValueError, match="private key"):
        musig.nonce_gen(PUBKEYS[0], prvkey)


def test_nonce_gen_counter_needs_a_private_key_and_a_counter() -> None:
    """The alternative to `nonce_gen`, for a signer counting instead of asking.

    Unlike `nonce_gen`, the private key is mandatory here: the counter's
    uniqueness is a property of the key it counts for.
    """
    secnonce = musig.nonce_gen_counter(PRVKEYS[0], 0)
    assert len(secnonce.pubnonce) == 66
    secnonce.wipe()

    # a second call with the same key and counter is exactly what the
    # counter exists to prevent, and nothing here can catch it: this
    # package validates arguments, not the caller's bookkeeping. What is
    # checked is only the bound on the counter itself
    with pytest.raises(ValueError, match="nonrepeating_cnt"):
        musig.nonce_gen_counter(PRVKEYS[0], -1)
    with pytest.raises(ValueError, match="nonrepeating_cnt"):
        musig.nonce_gen_counter(PRVKEYS[0], 2**64)
    with pytest.raises(TypeError, match="nonrepeating_cnt"):
        musig.nonce_gen_counter(PRVKEYS[0], 1.0)  # type: ignore[arg-type]


def test_pubnonce_aggnonce_and_partial_sig_round_trip() -> None:
    """`parse` and `serialize` answer each other, for all three types."""
    cache, secnonces, session = two_of_two_session()
    pubnonce = musig.pubnonce_parse(secnonces[0].pubnonce)
    assert musig.pubnonce_serialize(pubnonce) == secnonces[0].pubnonce

    aggnonce_bytes = musig.nonce_agg([s.pubnonce for s in secnonces])
    aggnonce = musig.aggnonce_parse(aggnonce_bytes)
    assert musig.aggnonce_serialize(aggnonce) == aggnonce_bytes

    partial_sig_bytes = secnonces[0].partial_sign(PRVKEYS[0], cache, session)
    partial_sig = musig.partial_sig_parse(partial_sig_bytes)
    assert musig.partial_sig_serialize(partial_sig) == partial_sig_bytes


def test_a_call_made_through_lib_reports_through_context_check() -> None:
    """The raw path the README documents beside `musig`'s own wrapping.

    `musig.SecretNonce.partial_sign` answers its own `ValueError` for a
    reused secret nonce, having no illegal callback to read; a caller
    reaching `lib` directly instead gets a bare 0 and reads why with
    `context.check()`, which is what this reproduces.
    """
    cache, secnonces, session = two_of_two_session()
    secnonce = secnonces[0]._secnonce
    keypair = ffi.new("secp256k1_keypair *")
    assert lib.secp256k1_keypair_create(ctx, keypair, PRVKEYS[0])
    partial_sig = ffi.new("secp256k1_musig_partial_sig *")
    assert lib.secp256k1_musig_partial_sign(
        ctx, partial_sig, secnonce, keypair, cache._cache_(), session._session_()
    )
    secnonces[0]._secnonce = None  # the C call already zeroed it

    # signing again with the same (now zeroed) secnonce is refused, and
    # named: this is the failed magic check context.py's own docstring
    # names as the example
    assert not lib.secp256k1_musig_partial_sign(
        ctx, partial_sig, secnonce, keypair, cache._cache_(), session._session_()
    )
    with pytest.raises(ValueError, match="secnonce_magic"):
        check()

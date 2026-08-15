# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the ecdh, recovery, ellswift, and musig libsecp256k1 modules.

Wherever possible the results are cross-checked against the other
bindings (dsa, ssa, mult) instead of against vendored constants: the
ECDH secret is recomputed from the shared point, the recoverable
signature is compared with the deterministic ECDSA one, and the
MuSig2 aggregate signature is verified as a plain BIP340 signature.

MuSig2 has no wrapper module, by decision, its two-round protocol
belonging where the signing state lives: it is exercised through the raw
cffi bindings, and this test doubles as the usage example the README
points at.
"""

from __future__ import annotations

import hashlib

import pytest

from btclib_secp256k1 import (
    _secret,
    context,
    dsa,
    ecdh,
    ellswift,
    ffi,
    keys,
    lib,
    mult,
    recovery,
    silentpayments,
    ssa,
    xonly,
)
from btclib_secp256k1.context import ctx

msg = hashlib.sha256(b"btclib_secp256k1").digest()


def compress(pubkey_bytes: bytes) -> bytes:
    """Compress an uncompressed 65-byte public key."""
    return bytes([2 + (pubkey_bytes[64] & 1)]) + pubkey_bytes[1:33]


def test_ecdh() -> None:
    """Both parties reach one secret, and it is the hash of the point.

    Cross-checked three ways rather than against a constant: the two
    parties agree, the secret is the SHA256 of the compressed shared
    point recomputed here, and `keys.pubkey_tweak_mul` gives that same
    point -- which is why the hash of the ecdh call is not a parameter, a
    protocol wanting another derivation applying it to the point.
    """
    prvkey_a, prvkey_b = 3, 5
    pubkey_a, pubkey_b = mult.mult_bytes(prvkey_a), mult.mult_bytes(prvkey_b)

    secret = ecdh.shared_secret(pubkey_b, prvkey_a)
    # both parties compute the same secret
    assert secret == ecdh.shared_secret(pubkey_a, prvkey_b)
    # which is the SHA256 of the compressed shared point
    shared_point = mult.mult_bytes(prvkey_a * prvkey_b)
    assert secret == hashlib.sha256(compress(shared_point)).digest()
    # bytes and int private keys are interchangeable
    assert secret == ecdh.shared_secret(pubkey_b, prvkey_a.to_bytes(32, "big"))

    # the same point is what keys returns for an arbitrary private key,
    # which is why the hash function of the ecdh call is not exposed: a
    # protocol needing another derivation applies it to this
    assert secret == hashlib.sha256(keys.pubkey_tweak_mul(pubkey_b, prvkey_a)).digest()


def test_ecdh_invalid_inputs() -> None:
    """A zero key, a short key and an unparsable public key are refused."""
    pubkey_bytes = mult.mult_bytes(1)

    with pytest.raises(ValueError, match="private key"):
        ecdh.shared_secret(pubkey_bytes, 0)
    with pytest.raises(ValueError, match="32 bytes"):
        ecdh.shared_secret(pubkey_bytes, b"\x01" * 31)
    with pytest.raises(ValueError, match="public key"):
        ecdh.shared_secret(b"\x02" + b"\x00" * 32, 1)


def test_recovery() -> None:
    """A recoverable signature recovers the signer, and is the ECDSA one.

    The recovery id is 0 or 1 for a key of this curve, and the DER form
    of the recoverable signature equals what `dsa.sign` produces for the
    same message and key -- so the two entry points are one signature,
    not two. A nonce contribution gives a different signature that is
    still recoverable.
    """
    prvkey = 7
    pubkey_bytes = compress(mult.mult_bytes(prvkey))

    signature_bytes, recid = recovery.sign(msg, prvkey)
    assert len(signature_bytes) == 64
    assert recid in (0, 1)
    assert recovery.recover(msg, signature_bytes, recid) == pubkey_bytes

    # the recoverable signature is the deterministic ECDSA one
    der_bytes = recovery.to_der(signature_bytes, recid)
    assert der_bytes == dsa.sign(msg, prvkey)
    assert dsa.verify(msg, pubkey_bytes, der_bytes)

    # a custom nonce yields a different, still recoverable signature
    custom = recovery.sign(msg, prvkey, b"\x01" * 32)
    assert custom[0] != signature_bytes
    assert recovery.recover(msg, *custom) == pubkey_bytes

    # the recovered key comes back in either form, this being
    # keys.serialize and the same point either way
    uncompressed = recovery.recover(msg, signature_bytes, recid, compressed=False)
    assert uncompressed == mult.mult_bytes(prvkey)
    assert compress(uncompressed) == pubkey_bytes


def test_recovery_invalid_inputs() -> None:
    """Every argument the recovery module bounds is refused out of range.

    A zero private key, a message hash that is not 32 octets, a compact
    signature that is not 64, a recovery id outside 0..3, and a compact
    signature whose r cannot be parsed.
    """
    signature_bytes, recid = recovery.sign(msg, 7)

    with pytest.raises(ValueError, match="private key"):
        recovery.sign(msg, 0)
    with pytest.raises(ValueError, match="32 bytes"):
        recovery.sign(msg[1:], 7)
    with pytest.raises(ValueError, match="message hash"):
        recovery.recover(msg[1:], signature_bytes, recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.recover(msg, signature_bytes[1:], recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.to_der(signature_bytes[1:], recid)
    with pytest.raises(ValueError, match="recovery id"):
        recovery.recover(msg, signature_bytes, 4)
    with pytest.raises(ValueError, match="recovery id"):
        recovery.to_der(signature_bytes, -1)
    with pytest.raises(ValueError, match="compact signature"):
        # an out of range r (and s) cannot be parsed
        recovery.recover(msg, b"\xff" * 64, 0)
    with pytest.raises(ValueError, match="recovery failed"):
        # a zero r parses, but no point can be recovered from it
        recovery.recover(msg, b"\x00" * 64, 0)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        recovery.sign(msg, 7, b"\x01" * 33)


def test_ellswift() -> None:
    """An ElligatorSwift encoding decodes back, and the x-only ECDH agrees.

    The encoding is 64 octets and randomized, so a fresh one differs from
    the last; supplying the randomness makes it a function of that, which
    is what allows the assertion at all. The BIP324 secret is bound to the
    transcript rather than to the two keys: both parties reach one value
    naming their own side, and swapping the roles changes it.
    """
    prvkey_a, prvkey_b = 11, 13
    pubkey_a = compress(mult.mult_bytes(prvkey_a))

    ell_a = ellswift.create(prvkey_a, b"\x01" * 32)
    assert len(ell_a) == 64
    # the encoding decodes back to the public key
    assert ellswift.decode(ell_a) == pubkey_a
    # as does the one of an already computed public key
    assert ellswift.decode(ellswift.encode(pubkey_a)) == pubkey_a
    # the randomness can be supplied, and then the encoding is a function
    # of it: 32 bytes, like every other entropy argument here
    fixed = ellswift.encode(pubkey_a, b"\x02" * 32)
    assert fixed == ellswift.encode(pubkey_a, b"\x02" * 32)
    assert ellswift.decode(fixed) == pubkey_a
    # the encoding is randomized: a fresh one differs
    assert ellswift.create(prvkey_a) != ell_a
    # and the decoding comes back in either form, this being
    # keys.serialize and the same point either way
    assert ellswift.decode(ell_a, compressed=False) == mult.mult_bytes(prvkey_a)

    # x-only ECDH: both parties agree on the BIP324 shared secret
    ell_b = ellswift.create(prvkey_b)
    secret = ellswift.xdh(ell_a, ell_b, prvkey_a, 0)
    assert len(secret) == 32
    assert secret == ellswift.xdh(ell_a, ell_b, prvkey_b, 1)
    # the secret is bound to the transcript: swapping the roles changes it
    assert secret != ellswift.xdh(ell_b, ell_a, prvkey_b, 0)


def test_ellswift_invalid_inputs() -> None:
    """Every argument the ellswift module bounds is refused out of range.

    A zero private key, a key and an entropy argument that are not 32
    octets, a public key that does not parse, an encoding that is not 64
    octets, and a party that is neither 0 nor 1.
    """
    ell = ellswift.create(11)

    with pytest.raises(ValueError, match="private key"):
        ellswift.create(0)
    with pytest.raises(ValueError, match="32 bytes"):
        ellswift.create(b"\x01" * 31)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ellswift.create(11, b"\x01" * 33)
    with pytest.raises(ValueError, match="public key"):
        ellswift.encode(b"\x02" + b"\x00" * 32)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ellswift.encode(mult.mult_bytes(11), b"\x01" * 31)
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.decode(ell[1:])
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.xdh(ell[1:], ell, 11, 0)
    with pytest.raises(ValueError, match="party"):
        ellswift.xdh(ell, ell, 11, 2)
    with pytest.raises(ValueError, match="private key"):
        ellswift.xdh(ell, ell, 0, 0)


def test_musig() -> None:
    """Run a 2-of-2 MuSig2 signing session, then verify it with ssa."""
    prvkeys = [(1).to_bytes(32, "big"), (2).to_bytes(32, "big")]

    keypairs, pubkeys = [], []
    for prvkey in prvkeys:
        keypair = ffi.new("secp256k1_keypair *")
        assert lib.secp256k1_keypair_create(ctx, keypair, prvkey)
        pubkey = ffi.new("secp256k1_pubkey *")
        assert lib.secp256k1_keypair_pub(ctx, pubkey, keypair)
        keypairs.append(keypair)
        pubkeys.append(pubkey)

    # key aggregation
    keyagg_cache = ffi.new("secp256k1_musig_keyagg_cache *")
    agg_pubkey = ffi.new("secp256k1_xonly_pubkey *")
    assert lib.secp256k1_musig_pubkey_agg(
        ctx, agg_pubkey, keyagg_cache, ffi.new("secp256k1_pubkey *[]", pubkeys), 2
    )

    # nonce generation, first round
    secnonces, pubnonces = [], []
    for i, prvkey in enumerate(prvkeys):
        secnonce = ffi.new("secp256k1_musig_secnonce *")
        pubnonce = ffi.new("secp256k1_musig_pubnonce *")
        # the session randomness is zeroed by the call
        session_secrand = ffi.new("char[32]", bytes([i + 10]) * 32)
        assert lib.secp256k1_musig_nonce_gen(
            ctx,
            secnonce,
            pubnonce,
            session_secrand,
            prvkey,
            pubkeys[i],
            msg,
            keyagg_cache,
            ffi.NULL,
        )
        secnonces.append(secnonce)
        pubnonces.append(pubnonce)

    aggnonce = ffi.new("secp256k1_musig_aggnonce *")
    assert lib.secp256k1_musig_nonce_agg(
        ctx, aggnonce, ffi.new("secp256k1_musig_pubnonce *[]", pubnonces), 2
    )

    # partial signatures, second round
    session = ffi.new("secp256k1_musig_session *")
    assert lib.secp256k1_musig_nonce_process(ctx, session, aggnonce, msg, keyagg_cache)

    partial_sigs = []
    for i in range(2):
        partial_sig = ffi.new("secp256k1_musig_partial_sig *")
        assert lib.secp256k1_musig_partial_sign(
            ctx, partial_sig, secnonces[i], keypairs[i], keyagg_cache, session
        )
        assert lib.secp256k1_musig_partial_sig_verify(
            ctx, partial_sig, pubnonces[i], pubkeys[i], keyagg_cache, session
        )
        partial_sigs.append(partial_sig)

    sig = ffi.new("char[64]")
    assert lib.secp256k1_musig_partial_sig_agg(
        ctx,
        sig,
        session,
        ffi.new("secp256k1_musig_partial_sig *[]", partial_sigs),
        2,
    )

    # the aggregate signature is a plain BIP340 one, for the aggregate key
    xonly_bytes = ffi.new("char[32]")
    assert lib.secp256k1_xonly_pubkey_serialize(ctx, xonly_bytes, agg_pubkey)
    pubkey_bytes = ffi.unpack(xonly_bytes, 32)
    assert ssa.verify(msg, pubkey_bytes, ffi.unpack(sig, 64))

    # signing zeroed the secret nonces, so signing again with one of them
    # is refused: the whole point of the session, and the reason a call
    # made through lib is worth following with context.check(), which
    # turns the bare 0 into what libsecp256k1 has to say about it
    assert not lib.secp256k1_musig_partial_sign(
        ctx, partial_sigs[0], secnonces[0], keypairs[0], keyagg_cache, session
    )
    with pytest.raises(ValueError, match="secnonce_magic"):
        context.check()


def test_size_checks_refuse_both_sides() -> None:
    """Every size check of recovery and ellswift refuses both edges.

    The far edge of each, the one the tests above leave out: a check
    written `!= 32` or `!= 64` has two, and the first mutation session
    found every one of these surviving a `!=` turned into `<` or `>`.
    """
    prvkey = 7
    signature_bytes, recid = recovery.sign(msg, prvkey)
    ell = ellswift.create(prvkey)

    with pytest.raises(ValueError, match="message hash"):
        recovery.sign(msg + b"\x01", prvkey)
    with pytest.raises(ValueError, match="aux_rand32"):
        recovery.sign(msg, prvkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="message hash"):
        recovery.recover(msg + b"\x01", signature_bytes, recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.recover(msg, signature_bytes + b"\x01", recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.to_der(signature_bytes + b"\x01", recid)

    with pytest.raises(ValueError, match="aux_rand32"):
        ellswift.create(prvkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="aux_rand32"):
        ellswift.encode(mult.mult_bytes(prvkey), b"\x01" * 33)
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.decode(ell + b"\x01")
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.xdh(ell + b"\x01", ell, prvkey, 0)
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.xdh(ell, ell + b"\x01", prvkey, 0)
    with pytest.raises(ValueError, match="64 bytes"):
        ellswift.xdh(ell, ell[:-1], prvkey, 0)


def test_every_recovery_id_of_the_curve_is_accepted() -> None:
    """A recovery id of 2 or 3 is a valid argument, not only 0 and 1.

    `recovery.sign` answers 0 or 1 for a key of this curve, so those are
    the only two the tests above ever pass, and a bound written
    `recid not in (0, 1, 2, 3)` was therefore asserted on one half of its
    own domain: the first mutation session found it surviving with 2 or 3
    dropped from that tuple. What the API accepts is the whole SEC 1 range,
    a recovery id being two bits, so `to_der` has to take all four --
    reached here through the parse alone, `recover` being free to fail on a
    candidate that names no key.
    """
    signature_bytes, _ = recovery.sign(msg, 7)

    for recid in (0, 1, 2, 3):
        assert len(recovery.to_der(signature_bytes, recid)) > 0

    # `recover` bounds the recovery id separately, so it needs its own
    # two: 2 and 3 name the candidate whose x is r + n, which exists only
    # when r + n < p -- some 2^-127 of secp256k1 signatures, so for this
    # one the recovery fails. What the assertion is about is *which* way it
    # fails: "public key recovery failed" says the id was accepted and the
    # arithmetic answered, where "the recovery id must be" would say the
    # bound had refused it
    for recid in (2, 3):
        with pytest.raises(ValueError, match="public key recovery failed"):
            recovery.recover(msg, signature_bytes, recid)


# The silent payment this section pays and scans back: an input funded by
# the private key 7, to an address of the scan key 13 and the spend key
# 17. The outpoint is 36 zero bytes -- a serialization like any other
# here, BIP352 reading it as bytes and never as a transaction reference
SP_INPUT_PRVKEY = (7).to_bytes(32, "big")
SP_SCAN_PRVKEY = (13).to_bytes(32, "big")
SP_SPEND_PRVKEY = (17).to_bytes(32, "big")
SP_INPUT_PUBKEY = keys.pubkey_from_prvkey(SP_INPUT_PRVKEY)
SP_SCAN_PUBKEY = keys.pubkey_from_prvkey(SP_SCAN_PRVKEY)
SP_SPEND_PUBKEY = keys.pubkey_from_prvkey(SP_SPEND_PRVKEY)
SP_OUTPOINT = bytes(36)


def sp_summary() -> bytes:
    """Summarize the one-input transaction this section's payment funds."""
    return silentpayments.prevouts_summary(SP_OUTPOINT, pubkeys_bytes=[SP_INPUT_PUBKEY])


def test_a_silent_payment_is_found_by_the_key_it_was_paid_to() -> None:
    """Pay an address, scan the transaction, and spend what was found.

    The BIP352 vectors are what pin the values; this pins the round trip
    the three functions make together, and the one thing the vectors
    cannot say -- that the tweak returned is the tweak that spends the
    output. Adding it to the spend private key has to give the private
    key of the taproot output found, which is checked by signing with it.
    """
    outputs = silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)],
        SP_OUTPOINT,
        prvkeys=[SP_INPUT_PRVKEY],
    )
    found = silentpayments.scan_outputs(
        outputs, SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY
    )

    assert [pubkey for pubkey, _, _ in found] == outputs
    for pubkey, tweak, label in found:
        assert label is None
        output_prvkey = keys.prvkey_tweak_add(SP_SPEND_PRVKEY, tweak)
        # the output is x-only, so what has to match is the x of the
        # tweaked key: signing with it is BIP340's own answer to that
        assert ssa.verify(msg, pubkey, ssa.sign(msg, output_prvkey))


def test_a_labeled_silent_payment_is_found_only_with_its_label() -> None:
    """A labeled output is invisible to a scan whose cache lacks the label.

    Both halves are the point. The label reaching the scan is what makes
    the output findable, and the same scan without it finding nothing is
    what says the label was doing the work -- an unlabeled address would
    have matched anyway.
    """
    label, label_tweak = silentpayments.label(SP_SCAN_PRVKEY, 1)
    labeled_spend_pubkey = silentpayments.labeled_spend_pubkey(SP_SPEND_PUBKEY, label)
    outputs = silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, labeled_spend_pubkey)],
        SP_OUTPOINT,
        prvkeys=[SP_INPUT_PRVKEY],
    )

    found = silentpayments.scan_outputs(
        outputs,
        SP_SCAN_PRVKEY,
        sp_summary(),
        SP_SPEND_PUBKEY,
        labels={label: label_tweak},
    )
    assert [(pubkey, found_label) for pubkey, _, found_label in found] == [
        (outputs[0], label)
    ]

    # the tweak reported is the whole of what spends the output, the label
    # tweak included: one addition to the spend private key, not two. What
    # says the label is in there is the unlabeled payment to the same scan
    # key, whose tweak is this one less the label's -- both being the same
    # shared secret at the same k
    pubkey, tweak, _ = found[0]
    assert ssa.verify(
        msg, pubkey, ssa.sign(msg, keys.prvkey_tweak_add(SP_SPEND_PRVKEY, tweak))
    )
    unlabeled = silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)], SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY]
    )
    unlabeled_tweak = silentpayments.scan_outputs(
        unlabeled, SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY
    )[0][1]
    assert keys.prvkey_tweak_add(unlabeled_tweak, label_tweak) == tweak

    assert (
        silentpayments.scan_outputs(
            outputs, SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY
        )
        == []
    )
    # an empty cache is not the absence of one: it reaches libsecp256k1 as
    # a lookup function that never matches rather than as no function, and
    # has to answer the same
    assert (
        silentpayments.scan_outputs(
            outputs, SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY, labels={}
        )
        == []
    )


def test_the_outputs_follow_the_recipient_order() -> None:
    """The n-th output is the n-th recipient's, whatever the order given.

    What the BIP352 vectors pin is the set of outputs, the assignment of
    a k within a group of recipients sharing a scan key not being
    determined by them. This is the other half: libsecp256k1 documents
    the outputs as ordered by the index of the recipient they belong to,
    and it reorders the array it is handed rather than the objects in it,
    so a wrong index would show up as an answer permuted with the input.

    The two recipients have *different* scan keys, which is what makes
    the assertion about the ordering alone: sharing one would put them in
    a group whose k assignment is libsecp256k1's, so reversing the list
    would change the output values as well as their places -- which is
    what this test asserted first, and what it fails on.
    """
    recipients = [
        (SP_SCAN_PUBKEY, SP_SPEND_PUBKEY),
        (keys.pubkey_from_prvkey(19), keys.pubkey_from_prvkey(23)),
    ]
    outputs = silentpayments.create_outputs(
        recipients, SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY]
    )
    reversed_outputs = silentpayments.create_outputs(
        recipients[::-1], SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY]
    )

    assert len(set(outputs)) == 2, "the two recipients share an output"
    assert reversed_outputs == outputs[::-1]


def test_a_taproot_input_pays_as_its_even_y_key() -> None:
    """The two sides agree on a taproot input, which is where parity is dropped.

    A taproot input contributes the even-y point of its x-only key, so
    the sender passes the private key as a taproot one and the recipient
    the 32 bytes: `taproot_prvkeys` negating where the y is odd is what
    makes the two the same point, and the private key here is chosen to
    be one that needs it.
    """
    # 6, not 3: the negation is only exercised by a key whose y is odd
    prvkey = (6).to_bytes(32, "big")
    xonly_pubkey, parity = xonly.from_pubkey(keys.pubkey_from_prvkey(prvkey))
    assert parity == 1, "this key no longer exercises the negation"

    outputs = silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)], SP_OUTPOINT, taproot_prvkeys=[prvkey]
    )
    summary = silentpayments.prevouts_summary(
        SP_OUTPOINT, taproot_pubkeys_bytes=[xonly_pubkey]
    )
    found = silentpayments.scan_outputs(
        outputs, SP_SCAN_PRVKEY, summary, SP_SPEND_PUBKEY
    )

    assert [pubkey for pubkey, _, _ in found] == outputs


def test_the_prevouts_summary_carries_no_secret() -> None:
    """The summary is public data, and the same for every scan key.

    It holds the sum of the input public keys and the hash of the
    outpoint, so two recipients scanning one transaction build the same
    one -- which is why it is a separate function rather than an argument
    of the scan.
    """
    assert sp_summary() == sp_summary()
    assert len(sp_summary()) == silentpayments.SUMMARY_SIZE


def test_a_label_is_a_point_and_round_trips_through_its_33_bytes() -> None:
    """The 33 bytes of a label parse back into the label they came from.

    `labeled_spend_pubkey` and `parse_label` are what take one, and the
    parse is exercised through both: the same 33 bytes have to give the
    same labeled key, and a label is a point rather than an opaque blob
    -- the sum below is what says so.
    """
    label, _ = silentpayments.label(SP_SCAN_PRVKEY, 0)
    assert len(label) == silentpayments.LABEL_SIZE

    labeled = silentpayments.labeled_spend_pubkey(SP_SPEND_PUBKEY, label)
    assert labeled == keys.pubkey_combine([SP_SPEND_PUBKEY, label])
    assert silentpayments.labeled_spend_pubkey(
        SP_SPEND_PUBKEY, label, compressed=False
    ) == keys.pubkey_combine([SP_SPEND_PUBKEY, label], compressed=False)

    # and the 33 bytes parse back into the label the recipient made,
    # which is what lets a cache of them be used without going round
    # through the serialization at every address
    assert (
        keys.serialize(
            silentpayments._labeled_spend_pubkey_(
                keys.parse(SP_SPEND_PUBKEY), silentpayments.parse_label(label)
            )
        )
        == labeled
    )


def test_a_label_of_a_scan_key_is_the_scan_key_and_m() -> None:
    """A different m, or a different scan key, is a different label."""
    label, tweak = silentpayments.label(SP_SCAN_PRVKEY, 0)

    assert silentpayments.label(SP_SCAN_PRVKEY, 0) == (label, tweak)
    assert silentpayments.label(SP_SCAN_PRVKEY, 1) != (label, tweak)
    assert silentpayments.label(SP_SPEND_PRVKEY, 0) != (label, tweak)
    # the tweak is the label's own private key, m = 2**32 - 1 included
    assert keys.pubkey_from_prvkey(tweak) == label
    biggest, biggest_tweak = silentpayments.label(SP_SCAN_PRVKEY, 2**32 - 1)
    assert keys.pubkey_from_prvkey(biggest_tweak) == biggest


def test_silent_payment_creation_refuses_an_empty_recipient_list() -> None:
    """No recipient is nothing to pay, which is refused before the call."""
    with pytest.raises(ValueError, match="at least one recipient"):
        silentpayments.create_outputs([], SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY])


def test_silent_payment_creation_refuses_a_transaction_with_no_keys() -> None:
    """No private key is no shared secret, and the two lists are both empty."""
    with pytest.raises(ValueError, match="at least one private key"):
        silentpayments.create_outputs([(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)], SP_OUTPOINT)


def test_silent_payment_creation_refuses_an_invalid_private_key() -> None:
    """A taproot private key libsecp256k1 rejects is named as one."""
    with pytest.raises(ValueError, match="invalid private key"):
        silentpayments.create_outputs(
            [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)], SP_OUTPOINT, taproot_prvkeys=[0]
        )


@pytest.mark.parametrize(
    "recipient, message",
    [
        ((b"\x02" + bytes(32), SP_SPEND_PUBKEY), "invalid scan public key"),
        ((SP_SCAN_PUBKEY, b"\x02" + bytes(32)), "invalid spend public key"),
    ],
)
def test_silent_payment_creation_names_which_key_it_refused(
    recipient: tuple[bytes, bytes], message: str
) -> None:
    """Scan and spend are two arguments, and the exception says which.

    `keys.parse` would answer both with "invalid public key", which for a
    recipient built out of two keys is the half of the answer that does
    not help.

    Args:
        recipient: the pair to pay, one half of it unparsable.
        message: what the exception has to name.
    """
    with pytest.raises(ValueError, match=message):
        silentpayments.create_outputs(
            [recipient], SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY]
        )


def test_a_label_m_outside_four_bytes_is_refused() -> None:
    """Refuse an m outside the uint32 the label index is.

    Left to cffi the answer is `OverflowError`, which is neither how this
    package reports an argument out of domain nor a message naming the
    argument.

    `2**32 + 1` is here because the two ends of the bound are not enough,
    which a mutation session said: with `<` mutated to `!=` the check
    reads `0 <= m != 2**32`, and both ends still raise -- `-1` fails the
    first comparison and `2**32` fails the second. A value *above* the
    bound is the one input that tells the two apart, so it is the one
    that kills that mutant.
    """
    for m in (-1, 2**32, 2**32 + 1):
        with pytest.raises(
            ValueError, match=r"the label m must be in \[0, 4294967295\]"
        ):
            silentpayments.label(SP_SCAN_PRVKEY, m)


def test_a_label_of_an_invalid_scan_key_is_refused() -> None:
    """A scan key outside [1, n-1] has no label, and libsecp256k1 says so."""
    with pytest.raises(ValueError, match="invalid scan private key"):
        silentpayments.label(0, 0)


def test_a_labeled_spend_pubkey_summing_to_infinity_is_refused() -> None:
    """The point at infinity has no serialization, and is reachable here.

    Only from a label that is not one BIP352 made: a label is a point,
    and the negation of the spend public key parses as one, so a caller
    holding both can ask for the sum that does not exist. The label
    `label` returns cannot do it -- it is a hash away from the key.
    """
    negated = keys.pubkey_negate(SP_SPEND_PUBKEY)

    with pytest.raises(ValueError, match="invalid labeled spend public key"):
        silentpayments.labeled_spend_pubkey(SP_SPEND_PUBKEY, negated)


def test_an_unparsable_label_is_refused() -> None:
    """33 bytes that are not a point are not a label."""
    with pytest.raises(ValueError, match="invalid label"):
        silentpayments.labeled_spend_pubkey(SP_SPEND_PUBKEY, b"\x02" + bytes(32))


def test_a_prevouts_summary_of_no_input_is_refused() -> None:
    """No input public key is no sum, and both lists are empty."""
    with pytest.raises(ValueError, match="at least one public key"):
        silentpayments.prevouts_summary(SP_OUTPOINT)


def test_a_prevouts_summary_of_an_unparsable_taproot_key_is_refused() -> None:
    """An x that is not on the curve is not a taproot input key."""
    with pytest.raises(ValueError, match="invalid taproot public key"):
        silentpayments.prevouts_summary(SP_OUTPOINT, taproot_pubkeys_bytes=[bytes(32)])


def test_scanning_refuses_an_empty_output_list() -> None:
    """A transaction with no taproot output pays no silent payment.

    libsecp256k1 requires at least one -- `n_tx_outputs > 0` is an
    ARG_CHECK of its own -- and what a violated precondition gets a
    caller is a bare zero return, which this wrapper can only report as
    the scan having failed. So it is refused here instead, by the
    argument's own name.
    """
    with pytest.raises(ValueError, match="at least one transaction output"):
        silentpayments.scan_outputs([], SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY)


def test_scanning_refuses_an_unparsable_output() -> None:
    """An output that is not an x-only public key is named as one."""
    with pytest.raises(ValueError, match="invalid transaction output"):
        silentpayments.scan_outputs(
            [bytes(32)], SP_SCAN_PRVKEY, sp_summary(), SP_SPEND_PUBKEY
        )


def test_scanning_refuses_a_summary_of_the_wrong_length() -> None:
    """The summary is opaque, so its length is all that can be checked."""
    with pytest.raises(ValueError, match="prevouts summary must be"):
        silentpayments.scan_outputs(
            [SP_INPUT_PUBKEY[1:]],
            SP_SCAN_PRVKEY,
            sp_summary()[:-1],
            SP_SPEND_PUBKEY,
        )


def test_scanning_refuses_an_invalid_scan_key() -> None:
    """A scan key outside [1, n-1] is what libsecp256k1 refuses the scan for."""
    with pytest.raises(ValueError, match="silent payment scanning failed"):
        silentpayments.scan_outputs(
            [SP_INPUT_PUBKEY[1:]], 0, sp_summary(), SP_SPEND_PUBKEY
        )


@pytest.mark.parametrize(
    "labels, message",
    [
        ({bytes(33): bytes(31)}, "label tweak must be 32 bytes"),
        ({bytes(32): bytes(32)}, "label must be 33 bytes"),
    ],
)
def test_scanning_refuses_a_malformed_label_cache(
    labels: dict[bytes, bytes], message: str
) -> None:
    """Both halves of a cache entry are checked, and before the scan starts.

    The tweak has to be copied into a buffer this package owns before the
    callback can hand a pointer to it back, so a wrong length is caught
    there rather than inside a lookup that has nowhere to raise.

    Args:
        labels: a cache with one malformed entry.
        message: what the exception has to name.
    """
    with pytest.raises(ValueError, match=message):
        silentpayments.scan_outputs(
            [SP_INPUT_PUBKEY[1:]],
            SP_SCAN_PRVKEY,
            sp_summary(),
            SP_SPEND_PUBKEY,
            labels=labels,
        )


def spy_on_wipe(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record every buffer `silentpayments` wipes, and wipe it for real.

    The buffers holding a secret in these wrappers are locals, gone by the
    time a caller could look at one, so a spy is the only way to hold what
    was wiped and check it. What it holds is the buffer itself, wiped: the
    assertions below read it after the call.

    The spy goes onto `silentpayments` and the real one is read from
    `_secret`, which is not interchangeable: the module does
    `from ._secret import wipe`, so it holds a reference of its own and
    patching `_secret.wipe` would not reach it.

    Args:
        monkeypatch: the fixture, whose undo is what keeps this local to
            one test.

    Returns:
        The list the spy appends to, in the order the wrapper wipes.
    """
    wiped: list[object] = []

    def recording_wipe(buffer: object) -> None:
        wiped.append(buffer)
        _secret.wipe(buffer)

    monkeypatch.setattr(silentpayments, "wipe", recording_wipe)
    return wiped


def zeroed(buffer: object) -> bool:
    """Whether a cffi buffer holds nothing but zeros."""
    memory = ffi.buffer(buffer)
    return bytes(memory) == bytes(len(memory))


def test_the_sender_wipes_every_private_key_it_copied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both kinds of key are wiped, one buffer each, and on the way out.

    A taproot key becomes a `secp256k1_keypair` and any other a 32-octet
    buffer; both are memory this package owns and both carry the secret,
    so both are taken back. The count is what a loop that ran no
    iterations would fail -- which is what a mutation session turned this
    wipe into, and nothing noticed.

    Args:
        monkeypatch: the fixture the spy is installed through.
    """
    wiped = spy_on_wipe(monkeypatch)

    silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)],
        SP_OUTPOINT,
        taproot_prvkeys=[SP_INPUT_PRVKEY],
        prvkeys=[SP_SPEND_PRVKEY],
    )

    assert len(wiped) == 2, "one buffer per private key given, and no more"
    assert all(zeroed(buffer) for buffer in wiped)


def test_the_sender_wipes_the_keys_it_had_when_a_later_one_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key that cannot be made does not leave the ones before it behind.

    Which is why the two lists are built inside the `try` rather than
    before it: the second key here is invalid, so `_keypair` raises with
    the first already made, and the `finally` has to be in force for it.

    Args:
        monkeypatch: the fixture the spy is installed through.
    """
    wiped = spy_on_wipe(monkeypatch)

    with pytest.raises(ValueError, match="invalid private key"):
        silentpayments.create_outputs(
            [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)],
            SP_OUTPOINT,
            taproot_prvkeys=[SP_INPUT_PRVKEY, 0],
        )

    assert len(wiped) == 1, "the key made before the refusal"
    assert all(zeroed(buffer) for buffer in wiped)


def test_scanning_wipes_the_tweaks_and_the_label_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every found output and every cached label tweak is taken back.

    The found outputs are wiped whether libsecp256k1 wrote to them or
    not -- the array is as long as the outputs one and it says through
    `n_found` how much of it it used -- so the count is one per
    transaction output plus one per label in the cache.

    Args:
        monkeypatch: the fixture the spy is installed through.
    """
    label, label_tweak = silentpayments.label(SP_SCAN_PRVKEY, 1)
    labeled = silentpayments.labeled_spend_pubkey(SP_SPEND_PUBKEY, label)
    outputs = silentpayments.create_outputs(
        [(SP_SCAN_PUBKEY, labeled), (SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)],
        SP_OUTPOINT,
        prvkeys=[SP_INPUT_PRVKEY],
    )
    summary = sp_summary()
    wiped = spy_on_wipe(monkeypatch)

    found = silentpayments.scan_outputs(
        outputs, SP_SCAN_PRVKEY, summary, SP_SPEND_PUBKEY, labels={label: label_tweak}
    )

    assert len(found) == 2, "both outputs are this recipient's"
    assert len(wiped) == len(outputs) + 1, "every found output slot, and the one label"
    assert all(zeroed(buffer) for buffer in wiped)
    # the tweaks reached the caller before the buffers were zeroed
    assert all(tweak != bytes(32) for _, tweak, _ in found)


def test_scanning_wipes_the_tweaks_it_had_when_a_later_label_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cache entry that cannot be made does not leave the ones before it.

    The recipient's side of
    `test_the_sender_wipes_the_keys_it_had_when_a_later_one_is_refused`,
    and the reason is the same one: the cache is filled inside the `try`,
    so a tweak copied before the refusal is wiped on the way out rather
    than dropped where it was. Built before the `try` -- or by a
    comprehension, which drops what it had along with the exception --
    this counted one buffer, the output slot, and the tweak was released
    in the clear.

    Args:
        monkeypatch: the fixture the spy is installed through.
    """
    label, label_tweak = silentpayments.label(SP_SCAN_PRVKEY, 1)
    summary = sp_summary()
    wiped = spy_on_wipe(monkeypatch)

    with pytest.raises(ValueError, match="label tweak must be 32 bytes"):
        silentpayments.scan_outputs(
            [SP_INPUT_PUBKEY[1:]],
            SP_SCAN_PRVKEY,
            summary,
            SP_SPEND_PUBKEY,
            # insertion order is what the cache is filled in, so the
            # refusal comes after the tweak that has to be taken back
            labels={label: label_tweak, bytes(silentpayments.LABEL_SIZE): bytes(31)},
        )

    assert len(wiped) == 2, "the one output slot, and the tweak made before the refusal"
    assert all(zeroed(buffer) for buffer in wiped)

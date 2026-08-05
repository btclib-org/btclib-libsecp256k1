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

from btclib_libsecp256k1 import (
    context,
    dsa,
    ecdh,
    ellswift,
    ffi,
    keys,
    lib,
    mult,
    recovery,
    ssa,
)
from btclib_libsecp256k1.context import ctx

msg = hashlib.sha256(b"btclib_libsecp256k1").digest()


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
    pubkey_a, pubkey_b = mult.mult_(prvkey_a), mult.mult_(prvkey_b)

    secret = ecdh.shared_secret(pubkey_b, prvkey_a)
    # both parties compute the same secret
    assert secret == ecdh.shared_secret(pubkey_a, prvkey_b)
    # which is the SHA256 of the compressed shared point
    shared_point = mult.mult_(prvkey_a * prvkey_b)
    assert secret == hashlib.sha256(compress(shared_point)).digest()
    # bytes and int private keys are interchangeable
    assert secret == ecdh.shared_secret(pubkey_b, prvkey_a.to_bytes(32, "big"))

    # the same point is what keys returns for an arbitrary private key,
    # which is why the hash function of the ecdh call is not exposed: a
    # protocol needing another derivation applies it to this
    assert secret == hashlib.sha256(keys.pubkey_tweak_mul(pubkey_b, prvkey_a)).digest()


def test_ecdh_invalid_inputs() -> None:
    """A zero key, a short key and an unparsable public key are refused."""
    pubkey_bytes = mult.mult_(1)

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
    pubkey_bytes = compress(mult.mult_(prvkey))

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
    with pytest.raises(ValueError, match="ndata must be 32 bytes"):
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
    pubkey_a = compress(mult.mult_(prvkey_a))

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
    with pytest.raises(ValueError, match="rnd32 must be 32 bytes"):
        ellswift.encode(mult.mult_(11), b"\x01" * 31)
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
    with pytest.raises(ValueError, match="ndata"):
        recovery.sign(msg, prvkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="message hash"):
        recovery.recover(msg + b"\x01", signature_bytes, recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.recover(msg, signature_bytes + b"\x01", recid)
    with pytest.raises(ValueError, match="64 bytes"):
        recovery.to_der(signature_bytes + b"\x01", recid)

    with pytest.raises(ValueError, match="aux_rand32"):
        ellswift.create(prvkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="rnd32"):
        ellswift.encode(mult.mult_(prvkey), b"\x01" * 33)
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

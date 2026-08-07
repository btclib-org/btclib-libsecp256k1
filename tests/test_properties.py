# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Invariants of the bindings, over many inputs rather than a few.

The rest of the suite pins results down against published vectors and a
handful of small keys. What that leaves out is not a line or a branch,
all of which are covered, but a wrong result on an input nobody wrote
down: with the private keys 1, 3, 5, 7, 11 and 13, no public key has an
x coordinate starting with a zero byte, and no signature is one of the
few whose DER encoding is 69 bytes long.

So the inputs here are derived, not chosen: a chain of SHA256, which
gives variety without randomness. A failure is reproducible at the exact
iteration, and nothing has to be installed to generate it.

The properties are the bindings' own, never a second implementation of
secp256k1: a round trip returning what it started from, a scalar
operation agreeing with the point operation it corresponds to, two
parties agreeing on a shared secret. Where an independent reference does
exist without one, hashlib, it is used.

Breadth is what the sweep is for. The cases too rare to be reached by it
reliably are pinned at the end, with the property each exhibits asserted
rather than assumed.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Iterator

from btclib_libsecp256k1 import (
    dsa,
    ecdh,
    ellswift,
    hashes,
    keys,
    mult,
    recovery,
    ssa,
    xonly,
)

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# enough for the sweep to vary what a fixed key cannot: parity of y,
# length of a DER encoding, leading zero bytes of a scalar. Eight
# invariants over this many inputs take a fraction of a second, which is
# what lets it run in every wheel test environment as well
COUNT = 128


def derived(tag: bytes, count: int = COUNT) -> Iterator[bytes]:
    """Yield 32-byte values from a SHA256 chain seeded by the tag.

    Valid private keys, all of them: a scalar out of [1, n-1] is beyond
    astronomically unlikely here, and would be reported by the very
    bindings under test rather than silently skipped.
    """
    value = hashlib.sha256(b"btclib_libsecp256k1 properties" + tag).digest()
    for _ in range(count):
        value = hashlib.sha256(value).digest()
        yield value


def compress(pubkey_bytes: bytes) -> bytes:
    """Compress an uncompressed 65-byte public key."""
    return bytes([2 + (pubkey_bytes[64] & 1)]) + pubkey_bytes[1:33]


def test_serialization_round_trips() -> None:
    """Either form parses and comes back, and negation is an involution.

    `mult` is checked to agree with the serialization it is derived from,
    and negating the private key is checked to flip the y while leaving
    the x alone -- which is the point-level meaning of the scalar
    operation, asserted rather than assumed. What
    `keys.pubkey_from_prvkey` serializes in C is checked against the
    compression composed here, over a sweep in which both parities occur:
    a fixed key exercises one of them.
    """
    for prvkey in derived(b"serialization"):
        uncompressed = mult.mult_(prvkey)
        compressed = compress(uncompressed)

        # either form parses, and serializes back to either form
        assert keys.serialize(keys.parse(uncompressed)) == compressed
        assert keys.serialize(keys.parse(compressed), False) == uncompressed
        # and both are what pubkey_from_prvkey answers, whose compressed
        # form libsecp256k1 writes where this file composes it
        assert keys.pubkey_from_prvkey(prvkey) == compressed
        assert keys.pubkey_from_prvkey(prvkey, False) == uncompressed
        # mult agrees with the serialization it is derived from
        assert mult.mult(prvkey) == (
            int.from_bytes(uncompressed[1:33], "big"),
            int.from_bytes(uncompressed[33:], "big"),
        )

        # negation is an involution, on both sides
        assert keys.prvkey_negate(keys.prvkey_negate(prvkey)) == prvkey
        assert keys.pubkey_negate(keys.pubkey_negate(compressed)) == compressed
        # and negating the private key negates the point, i.e. flips y
        negated = mult.mult_(keys.prvkey_negate(prvkey))
        assert negated[1:33] == uncompressed[1:33]
        assert negated[64] & 1 != uncompressed[64] & 1


def test_scalar_algebra_matches_point_algebra() -> None:
    """(d + t)G is dG + tG, and (d * t)G is t(dG), over the whole sweep.

    The scalar operation and the point operation are the bindings' own,
    so what is compared is one against the other and never against a
    second implementation of the curve. Addition is checked to commute,
    and combining two points to be adding their scalars.
    """
    for prvkey, tweak in zip(derived(b"scalar"), derived(b"tweak"), strict=True):
        pubkey = compress(mult.mult_(prvkey))

        # (d + t)G == dG + tG, and (d * t)G == t(dG)
        assert mult.mult_(keys.prvkey_tweak_add(prvkey, tweak)) == mult.mult_(
            keys.prvkey_tweak_add(tweak, prvkey)
        )
        assert compress(
            mult.mult_(keys.prvkey_tweak_add(prvkey, tweak))
        ) == keys.pubkey_tweak_add(pubkey, tweak)
        assert compress(
            mult.mult_(keys.prvkey_tweak_mul(prvkey, tweak))
        ) == keys.pubkey_tweak_mul(pubkey, tweak)

        # combining points is adding scalars
        assert keys.pubkey_combine([
            pubkey,
            compress(mult.mult_(tweak)),
        ]) == keys.pubkey_tweak_add(pubkey, tweak)


def test_ecdsa_signature_forms() -> None:
    """RFC6979 signing is deterministic, low-s, and converts both ways.

    Over the sweep rather than the handful of small keys, which is what
    reaches a DER length the fixed vectors never produce. A private key as
    octets and as an int is the same key; a nonce contribution changes the
    signature and the result still verifies.
    """
    for prvkey, entropy in zip(derived(b"ecdsa"), derived(b"ndata"), strict=True):
        pubkey = compress(mult.mult_(prvkey))
        msg = hashlib.sha256(prvkey).digest()

        sig = dsa.sign(msg, prvkey)
        # RFC6979 signing is deterministic, and bytes or int is the same key
        assert sig == dsa.sign(msg, int.from_bytes(prvkey, "big"))
        assert dsa.verify(msg, pubkey, sig)
        # signatures are produced in the lower-s form
        assert dsa.is_low_s(sig)
        assert dsa.normalize(sig) == sig
        # the two encodings convert into each other, whatever the length
        # of the DER one turns out to be
        assert dsa.to_der(dsa.to_compact(sig)) == sig
        assert len(dsa.to_compact(sig)) == 64

        # a nonce contribution changes the signature, which still verifies
        contributed = dsa.sign(msg, prvkey, entropy)
        assert contributed != sig
        assert dsa.verify(msg, pubkey, contributed)


def test_recovery_recovers_the_signer() -> None:
    """A recoverable signature recovers the signer, and no other key.

    Its DER form equals what `dsa.sign` produces, so the two entry points
    are one signature. The other recovery id is asserted to give a
    different key when it gives one at all -- it need not, which is why
    the ValueError is suppressed rather than expected.
    """
    for prvkey in derived(b"recovery"):
        pubkey = compress(mult.mult_(prvkey))
        msg = hashlib.sha256(prvkey).digest()

        signature, recid = recovery.sign(msg, prvkey)
        assert recovery.recover(msg, signature, recid) == pubkey
        # the recoverable signature is the deterministic ECDSA one
        assert recovery.to_der(signature, recid) == dsa.sign(msg, prvkey)
        with contextlib.suppress(ValueError):
            # the other recovery id recovers a different key, when it
            # recovers one at all
            assert recovery.recover(msg, signature, (recid + 1) % 2) != pubkey


def test_schnorr_and_taproot_tweaking() -> None:
    """BIP340 signing is deterministic, and a taproot tweak is consistent.

    A signature verifies against the x-only key whatever the parity the
    compressed form carries, and `sign_custom` agrees with `sign` on a
    32-octet message. The tweaked key checks out against its commitment,
    and the tweaked private key is asserted to be the one that signs for
    it -- which is what a key path spending needs and what no single call
    can confirm.
    """
    for prvkey, tweak in zip(derived(b"schnorr"), derived(b"taptweak"), strict=True):
        pubkey = compress(mult.mult_(prvkey))
        msg = hashlib.sha256(prvkey).digest()
        aux_rand32 = hashlib.sha256(msg).digest()

        sig = ssa.sign(msg, prvkey, aux_rand32)
        # BIP340 signing is deterministic given the auxiliary randomness
        assert sig == ssa.sign(msg, prvkey, aux_rand32)
        # and verifies against the x-only public key, whatever the
        # parity of the y coordinate the compressed form carries
        assert ssa.verify(msg, pubkey[1:], sig)
        # the same signature for a 32-byte message
        assert ssa.sign_custom(msg, prvkey, aux_rand32) == sig

        # the x-only form is the x coordinate, and the parity is y's
        xonly_bytes, parity = xonly.from_pubkey(pubkey)
        assert xonly_bytes == pubkey[1:]
        assert parity == pubkey[0] - 2

        # the tweaked key checks out against the commitment, and the
        # tweaked private key is the one that signs for it
        tweaked, tweaked_parity = xonly.tweak_add(xonly_bytes, tweak)
        assert xonly.tweak_add_check(tweaked, tweaked_parity, xonly_bytes, tweak)
        tweaked_prvkey = xonly.prvkey_tweak_add(prvkey, tweak)
        assert ssa.verify(msg, tweaked, ssa.sign(msg, tweaked_prvkey))


def test_ecdh_and_ellswift_agree() -> None:
    """Both parties reach one ECDH secret, and BIP324's is symmetric.

    The secret is checked against the SHA256 of the shared point that
    `keys` returns, hashlib being the independent reference. An
    ElligatorSwift encoding decodes to the key it encodes, from a private
    key and from an already computed public one, and the x-only ECDH gives
    one value to the two parties naming their own side.
    """
    for prvkey_a, prvkey_b in zip(derived(b"ecdh a"), derived(b"ecdh b"), strict=True):
        pubkey_a = compress(mult.mult_(prvkey_a))
        pubkey_b = compress(mult.mult_(prvkey_b))

        # both parties reach the same secret, which is the SHA256 of the
        # shared point keys returns
        secret = ecdh.shared_secret(pubkey_b, prvkey_a)
        assert secret == ecdh.shared_secret(pubkey_a, prvkey_b)
        assert (
            secret == hashlib.sha256(keys.pubkey_tweak_mul(pubkey_b, prvkey_a)).digest()
        )

        # an ElligatorSwift encoding decodes to the key it encodes
        ell_a = ellswift.create(prvkey_a)
        assert ellswift.decode(ell_a) == pubkey_a
        assert ellswift.decode(ellswift.encode(pubkey_a)) == pubkey_a
        # and the BIP324 x-only ECDH is symmetric in the two parties
        ell_b = ellswift.create(prvkey_b)
        assert ellswift.xdh(ell_a, ell_b, prvkey_a, 0) == ellswift.xdh(
            ell_a, ell_b, prvkey_b, 1
        )


def test_public_key_ordering() -> None:
    """Ordering is the one of the compressed serialization, pairwise too.

    Python sorting the same octets is the independent reference, and every
    pair is checked against `<` on those octets, so the comparison is held
    to the order rather than only the sort to the comparison.
    """
    prvkeys = list(derived(b"ordering", 8))
    pubkeys = [compress(mult.mult_(prvkey)) for prvkey in prvkeys]

    # the ordering is the one of the compressed serialization, which
    # sorting those same bytes is an independent way to obtain
    assert keys.pubkey_sort(pubkeys) == sorted(pubkeys)
    for i, first in enumerate(pubkeys):
        for second in pubkeys[i + 1 :]:
            assert (keys.pubkey_cmp(first, second) < 0) == (first < second)


def test_tagged_hashing() -> None:
    """The tagged hash matches its definition, computed with hashlib.

    Over the sweep and three tags, the empty one included: an
    implementation of SHA256 that has nothing to do with the one inside
    libsecp256k1.
    """
    for msg in derived(b"tagged"):
        for tag in (b"", b"TapLeaf", b"BIP0340/challenge"):
            tag_hash = hashlib.sha256(tag).digest()
            assert (
                hashes.tagged_sha256(tag, msg)
                == hashlib.sha256(tag_hash + tag_hash + msg).digest()
            )


def test_scalar_range_ends() -> None:
    """Both ends of the scalar range are usable keys, and negate to each other.

    1 and n-1 verify, sign and verify under ECDSA and BIP340. They are the
    two values the sweep cannot reach, being a chain of hashes.
    """
    msg = hashlib.sha256(b"edge").digest()
    for scalar in (1, N - 1):
        assert keys.prvkey_verify(scalar)
        pubkey = compress(mult.mult_(scalar))
        assert dsa.verify(msg, pubkey, dsa.sign(msg, scalar))
        assert ssa.verify(msg, pubkey[1:], ssa.sign(msg, scalar))
    # and they are each other's negation
    assert keys.prvkey_negate(1) == (N - 1).to_bytes(32, "big")


def test_pinned_zero_leading_x() -> None:
    """A public key whose x starts with a zero octet still round trips.

    About one key in 256, so not something the sweep can be relied on to
    produce: it is pinned by value, taken from the same chain. What it
    exercises is every place a leading zero could be dropped -- both
    serializations, the x-only form, and the coordinates.
    """
    # value 223 of derived(b""), the first of that chain whose public key
    # has an x coordinate starting with a zero byte: about 1 in 256, so
    # not something COUNT iterations can be relied on to produce
    prvkey = bytes.fromhex(
        "ee69f731efff2c96989416d78ac759f38e5668927f2ffdb4d782a84e36ae48b6"
    )
    uncompressed = mult.mult_(prvkey)
    assert uncompressed[1] == 0

    assert keys.serialize(keys.parse(uncompressed)) == compress(uncompressed)
    assert keys.serialize(keys.parse(compress(uncompressed)), False) == uncompressed
    assert xonly.from_pubkey(uncompressed)[0] == uncompressed[1:33]
    assert mult.mult(prvkey)[0] == int.from_bytes(uncompressed[1:33], "big")


def test_pinned_short_der_signature() -> None:
    """A 69-octet DER signature converts, normalizes and recovers.

    Both r and s short, which is about one signature in 200: the rest of
    the suite only ever produces 70 and 71 octets, so a length assumption
    anywhere would pass everything and fail here. Pinned by value from the
    same chain.
    """
    # value 220 of the same chain, signing the message derived from it:
    # r and s both short, for a DER encoding of 69 bytes. The rest of the
    # suite only ever produces 70 and 71; this is about 1 in 200
    prvkey = bytes.fromhex(
        "439138d04caec9e702723a29afc585ce8b7cbc57f844297eb11df08b1d16788e"
    )
    msg = bytes.fromhex(
        "4f7044d25bce345b37a424c23102ebe8987f513b600c71e3bc9e7f987c9b31a6"
    )
    sig = dsa.sign(msg, prvkey)
    assert len(sig) == 69

    assert dsa.verify(msg, compress(mult.mult_(prvkey)), sig)
    assert dsa.to_der(dsa.to_compact(sig)) == sig
    assert dsa.normalize(sig) == sig
    signature, recid = recovery.sign(msg, prvkey)
    assert recovery.to_der(signature, recid) == sig

# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the keys and xonly modules, and for the ECDSA signature forms.

The scalar and point operations are cross-checked against the mult
bindings, computing the expected result modulo the group order; the
x-only tweaking is cross-checked against the plain public key tweaking,
which is a distinct libsecp256k1 code path; the taproot key path is
checked end to end, signing with the tweaked private key and verifying
against the tweaked x-only public key.
"""

from __future__ import annotations

import hashlib

import pytest

from btclib_libsecp256k1 import dsa, keys, mult, ssa, xonly

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

msg = hashlib.sha256(b"btclib_libsecp256k1").digest()


def compress(pubkey_bytes: bytes) -> bytes:
    """Compress an uncompressed 65-byte public key."""

    return bytes([2 + (pubkey_bytes[64] & 1)]) + pubkey_bytes[1:33]


def test_prvkey_verify() -> None:
    """Accept 1 and n-1, refuse 0, n and a value above the order."""
    assert keys.prvkey_verify(1)
    assert keys.prvkey_verify(N - 1)
    # zero and the group order are out of the [1, n-1] range
    assert not keys.prvkey_verify(0)
    assert not keys.prvkey_verify(N)
    assert not keys.prvkey_verify(b"\xff" * 32)


def test_prvkey_algebra() -> None:
    """Scalar algebra on a private key matches the arithmetic mod n.

    Negation, addition and multiplication are each compared with the
    integer answer computed here, and negation is checked to be its own
    inverse. The sum wraps at the group order, and a sum that reaches zero
    is refused: zero is no private key, so there is no result to hand back.
    """
    a, b = 3, 5

    assert keys.prvkey_negate(a) == (N - a).to_bytes(32, "big")
    assert keys.prvkey_negate(keys.prvkey_negate(a)) == (a.to_bytes(32, "big"))
    assert keys.prvkey_tweak_add(a, b) == (a + b).to_bytes(32, "big")
    assert keys.prvkey_tweak_mul(a, b) == (a * b).to_bytes(32, "big")

    # the sum wraps around the group order
    assert keys.prvkey_tweak_add(N - 1, 3) == (2).to_bytes(32, "big")
    # a sum which is zero has no valid private key
    with pytest.raises(ValueError, match="private key or tweak"):
        keys.prvkey_tweak_add(a, N - a)


def test_pubkey_algebra() -> None:
    """Tweaking a public key matches tweaking the private key under it.

    Add, multiply and negate, each against `mult.mult_` of the tweaked
    scalar, with negation checked to be its own inverse. Combining keys
    matches adding their scalars and does not depend on the order they are
    given in; one key combines to itself. A sum landing on the point at
    infinity is refused, that point having no public key.
    """
    a, b = 3, 5
    pubkey_a, pubkey_b = mult.mult_(a), mult.mult_(b)

    # tweaking a public key matches tweaking its private key
    assert keys.pubkey_tweak_add(pubkey_a, b) == (compress(mult.mult_(a + b)))
    assert keys.pubkey_tweak_mul(pubkey_a, b) == (compress(mult.mult_(a * b)))
    assert keys.pubkey_negate(pubkey_a) == (compress(mult.mult_(N - a)))
    assert keys.pubkey_negate(keys.pubkey_negate(pubkey_a)) == (compress(pubkey_a))

    # adding public keys matches adding their private keys
    combined = keys.pubkey_combine([pubkey_a, pubkey_b])
    assert combined == compress(mult.mult_(a + b))
    assert combined == keys.pubkey_combine([pubkey_b, pubkey_a])
    # a single key is combined with itself only
    assert keys.pubkey_combine([pubkey_a]) == compress(pubkey_a)

    # the point at infinity is not a valid public key
    with pytest.raises(ValueError, match="public key sum"):
        keys.pubkey_combine([pubkey_a, keys.pubkey_negate(pubkey_a)])


def test_pubkey_serialization() -> None:
    """Both serialized forms parse, and either converts to the other.

    The uncompressed form is 65 octets opening with 0x04, the compressed
    33 whose first octet carries the parity of the y being dropped.
    """
    pubkey_bytes = mult.mult_(7)

    # both forms parse, and either can be serialized from the other
    compressed = keys.serialize(keys.parse(pubkey_bytes))
    assert compressed == compress(pubkey_bytes)
    assert keys.serialize(keys.parse(compressed), False) == pubkey_bytes
    assert keys.pubkey_negate(compressed, False)[0] == 0x04


def test_pubkey_order() -> None:
    """Sorting is by compressed serialization, whatever form is given.

    Python sorting the same octets is the independent reference: what
    libsecp256k1 orders by is that serialization, so an ordering it
    produces is checkable without reimplementing the comparison. `cmp` is
    checked to agree with the order pairwise and to answer zero for one
    key against itself in the other form; sorting no key is no key rather
    than an error, and a key that does not parse is refused.
    """
    uncompressed = [mult.mult_(k) for k in (5, 2, 9, 1)]
    compressed = [compress(pubkey_bytes) for pubkey_bytes in uncompressed]
    # what libsecp256k1 orders by is the compressed serialization, so
    # python sorting the same bytes is an independent reference
    expected = sorted(compressed)

    assert keys.pubkey_sort(compressed) == expected
    # whichever form the keys are given and returned in
    assert keys.pubkey_sort(uncompressed) == expected
    assert [
        compress(pubkey_bytes)
        for pubkey_bytes in keys.pubkey_sort(compressed, compressed=False)
    ] == expected
    # sorting no key at all is no key at all, not an error
    assert keys.pubkey_sort([]) == []

    for i in range(len(expected) - 1):
        assert keys.pubkey_cmp(expected[i], expected[i + 1]) < 0
        assert keys.pubkey_cmp(expected[i + 1], expected[i]) > 0
    # one key equals itself, in either form
    assert keys.pubkey_cmp(compressed[0], uncompressed[0]) == 0

    with pytest.raises(ValueError, match="public key"):
        keys.pubkey_sort([compressed[0], b"\x02" + b"\x00" * 32])
    with pytest.raises(ValueError, match="public key"):
        keys.pubkey_cmp(compressed[0], b"")


def test_keys_invalid_inputs() -> None:
    """Every argument the keys module bounds is refused out of range.

    A private key that is not 32 octets or is zero, a tweak that is not,
    a public key that does not parse, an empty list to combine, and the
    two products that reach zero or infinity -- neither of which has a key
    to answer with.
    """
    pubkey_bytes = mult.mult_(7)

    with pytest.raises(ValueError, match="private key"):
        keys.prvkey_negate(b"\x01" * 31)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        keys.prvkey_tweak_add(7, b"\x01" * 33)
    with pytest.raises(ValueError, match="private key"):
        keys.prvkey_negate(0)
    with pytest.raises(ValueError, match="public key"):
        keys.pubkey_tweak_add(b"\x02" + b"\x00" * 32, 3)
    with pytest.raises(ValueError, match="tweak"):
        keys.pubkey_tweak_mul(pubkey_bytes, 0)
    with pytest.raises(ValueError, match="at least one public key"):
        keys.pubkey_combine([])
    # a zero tweak makes the product zero, which is no private key
    with pytest.raises(ValueError, match="private key or tweak"):
        keys.prvkey_tweak_mul(7, 0)
    # tweaking by the negation of the private key lands on the point at
    # infinity, which has no serialization
    with pytest.raises(ValueError, match="tweak or resulting public key"):
        keys.pubkey_tweak_add(mult.mult_(7), N - 7)


def test_xonly_from_pubkey() -> None:
    """An x-only key is the x of the public key, with the parity beside it.

    Checked over three keys, in both serialized forms: the parity is the
    one the uncompressed form carries, and it is what a caller needs to
    lift the x back to the point it came from.
    """
    for prvkey in (1, 2, 3):
        pubkey_bytes = mult.mult_(prvkey)
        xonly_bytes, parity = xonly.from_pubkey(pubkey_bytes)
        assert xonly_bytes == pubkey_bytes[1:33]
        assert parity == pubkey_bytes[64] & 1
        # the compressed form is accepted too
        assert xonly.from_pubkey(compress(pubkey_bytes)) == (
            xonly_bytes,
            parity,
        )


def test_xonly_tweak_add() -> None:
    """BIP341 tweaking of an x-only key, against the plain key path.

    The same result is reached by lifting the key to its even y point and
    tweaking that through `keys.pubkey_tweak_add`, which is what the x-only
    call does internally. A full public key is refused rather than lifted:
    the key used here has odd y, so accepting one would tweak a point the
    caller did not pass, and `from_pubkey` is where that lift is asked for.
    `tweak_add_check` then verifies the commitment without recomputing it,
    and fails on a different tweak, key or parity.
    """
    prvkey, tweak = 11, hashlib.sha256(b"taproot tweak").digest()
    xonly_bytes, _ = xonly.from_pubkey(mult.mult_(prvkey))

    tweaked_bytes, parity = xonly.tweak_add(xonly_bytes, tweak)

    # the same result is reached tweaking the even y lift of the key
    # through the plain public key code path
    lifted = keys.pubkey_tweak_add(b"\x02" + xonly_bytes, tweak)
    assert (tweaked_bytes, parity) == xonly.from_pubkey(lifted)

    # a full public key is not accepted: the public key of 11 has odd y,
    # so tweaking it would tweak a point the caller did not pass, and
    # from_pubkey is where that lift is asked for
    assert mult.mult_(prvkey)[64] & 1
    for form in (mult.mult_(prvkey), compress(mult.mult_(prvkey))):
        with pytest.raises(ValueError, match="x-only public key must be 32 bytes"):
            xonly.tweak_add(form, tweak)

    # the commitment can be checked without recomputing it
    assert xonly.tweak_add_check(tweaked_bytes, parity, xonly_bytes, tweak)
    # a different tweak, key, or parity does not check out
    assert not xonly.tweak_add_check(tweaked_bytes, parity, xonly_bytes, b"\x01" * 32)
    assert not xonly.tweak_add_check(
        tweaked_bytes, parity, xonly.from_pubkey(mult.mult_(12))[0], tweak
    )
    assert not xonly.tweak_add_check(tweaked_bytes, 1 - parity, xonly_bytes, tweak)


def test_taproot_key_path() -> None:
    """Sign a taproot key path spending with a tweaked private key."""

    prvkey, tweak = 11, hashlib.sha256(b"taproot tweak").digest()
    internal_bytes, _ = xonly.from_pubkey(mult.mult_(prvkey))
    output_bytes, _ = xonly.tweak_add(internal_bytes, tweak)

    tweaked_prvkey = xonly.prvkey_tweak_add(prvkey, tweak)
    # the tweaked private key is the one of the tweaked x-only key
    assert xonly.from_pubkey(mult.mult_(tweaked_prvkey))[0] == (output_bytes)
    # hence it signs for the taproot output key
    signature_bytes = ssa.sign(msg, tweaked_prvkey)
    assert ssa.verify(msg, output_bytes, signature_bytes)
    # while the internal key does not
    assert not ssa.verify(msg, internal_bytes, signature_bytes)


def test_xonly_invalid_inputs() -> None:
    """Every argument the xonly module bounds is refused out of range.

    Thirty-two octets that are not an x coordinate, a key that is not 32
    octets, a tweak that is not, a parity outside 0..1, a zero private
    key, a public key that does not parse -- and the two tweaks by the
    negation of the scalar, which land on the point at infinity and have
    no x-only form to answer with.
    """
    xonly_bytes, parity = xonly.from_pubkey(mult.mult_(11))

    with pytest.raises(ValueError, match="invalid x-only public key"):
        # 32 bytes which are not a valid x coordinate
        xonly.tweak_add(b"\xff" * 32, b"\x01" * 32)
    with pytest.raises(ValueError, match="x-only public key must be 32 bytes"):
        xonly.tweak_add(b"\x02" + b"\x00" * 32, b"\x01" * 32)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        xonly.tweak_add(xonly_bytes, b"\x01" * 31)
    with pytest.raises(ValueError, match="tweaked x-only public key"):
        xonly.tweak_add_check(xonly_bytes[1:], parity, xonly_bytes, b"\x01" * 32)
    with pytest.raises(ValueError, match="parity"):
        xonly.tweak_add_check(xonly_bytes, 2, xonly_bytes, b"\x01" * 32)
    with pytest.raises(ValueError, match="private key"):
        xonly.prvkey_tweak_add(0, b"\x01" * 32)
    with pytest.raises(ValueError, match="public key"):
        xonly.from_pubkey(b"\x02" + b"\x00" * 32)
    # tweaking by the negation of the private key of the even y point
    # lands on the point at infinity, which has no x-only form
    with pytest.raises(ValueError, match="tweak or resulting public key"):
        xonly.tweak_add(xonly.from_pubkey(mult.mult_(1))[0], N - 1)
    with pytest.raises(ValueError, match="tweak or resulting private key"):
        xonly.prvkey_tweak_add(1, N - 1)


def test_dsa_signature_forms() -> None:
    """The compact form is r and s, and the conversion round trips.

    Both halves are checked to be in 1..n-1, as two assertions rather than
    one conjunction so that a failure says which half. A compact signature
    that is not 64 octets and one whose r is out of range are both
    refused, and the DER rebuilt from the compact form still verifies.
    """
    prvkey = 7
    pubkey_bytes = compress(mult.mult_(prvkey))
    der_bytes = dsa.sign(msg, prvkey)

    compact_bytes = dsa.to_compact(der_bytes)
    assert len(compact_bytes) == 64
    # the compact form is the concatenation of r and s
    r, s = (
        int.from_bytes(compact_bytes[:32], "big"),
        int.from_bytes(compact_bytes[32:], "big"),
    )
    # two assertions, not one conjunction: a failure then says which half
    assert 0 < r < N
    assert 0 < s < N
    # and the conversion round trips
    assert dsa.to_der(compact_bytes) == der_bytes

    with pytest.raises(ValueError, match="compact signature"):
        dsa.to_der(compact_bytes[1:])
    with pytest.raises(ValueError, match="compact signature"):
        # an out of range r cannot be parsed
        dsa.to_der(b"\xff" * 32 + compact_bytes[32:])
    assert dsa.verify(msg, pubkey_bytes, dsa.to_der(compact_bytes))


def test_dsa_low_s() -> None:
    """A signature is made low-s, and a malleated one normalizes back.

    Negating s gives the other signature of the same message under the
    same key, which is what the low-s rule exists to rule out: it is
    reported as not low-s and does not verify, while `normalize` returns
    the original byte for byte and that verifies.
    """
    prvkey = 7
    pubkey_bytes = compress(mult.mult_(prvkey))
    der_bytes = dsa.sign(msg, prvkey)

    # signatures are created in the normalized lower-s form
    assert dsa.is_low_s(der_bytes)
    assert dsa.normalize(der_bytes) == der_bytes

    # negating s yields the malleated signature of the same message
    compact_bytes = dsa.to_compact(der_bytes)
    s = int.from_bytes(compact_bytes[32:], "big")
    malleated_bytes = dsa.to_der(compact_bytes[:32] + (N - s).to_bytes(32, "big"))

    assert not dsa.is_low_s(malleated_bytes)
    # which does not verify, being a higher-s one
    assert not dsa.verify(msg, pubkey_bytes, malleated_bytes)
    # but normalizes back to the original signature
    assert dsa.normalize(malleated_bytes) == der_bytes
    assert dsa.verify(msg, pubkey_bytes, dsa.normalize(malleated_bytes))


def test_size_checks_refuse_both_sides() -> None:
    """Both x-only size checks refuse a value too short as well as too long.

    The tests above pass a 33-octet key to each, which is the compressed
    form and the mistake a caller actually makes; what they leave out is
    the other edge, and the first mutation session found both checks
    surviving a `!=` turned into `>`.
    """
    xonly_bytes, parity = xonly.from_pubkey(mult.mult_(11))

    # _parse, reached through both entry points
    with pytest.raises(ValueError, match="x-only public key must be 32 bytes"):
        xonly.tweak_add(xonly_bytes[:-1], b"\x01" * 32)

    # and the tweaked key of the commitment check, one octet too many
    with pytest.raises(ValueError, match="tweaked x-only public key"):
        xonly.tweak_add_check(xonly_bytes + b"\x01", parity, xonly_bytes, b"\x01" * 32)

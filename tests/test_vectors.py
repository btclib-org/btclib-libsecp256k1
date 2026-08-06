# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests against independent, publicly documented test vectors.

- BIP340: bip340_test_vectors.csv, vendored from
  https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
- ECDSA RFC6979: (k, r, s) vectors published in
  https://bitcointalk.org/index.php?topic=285142.msg3300992
  as vendored by trezor-firmware (crypto/tests/test_check.c,
  test_rfc6979) and bitcoinjs-lib (test/fixtures/ecdsa.json);
  each vector is also self-checked here asserting r == x(k*G)
- deterministic ECDSA and DER encodings from trezor-firmware
  (crypto/tests/test_check.c, test_ecdsa_sign_digest_deterministic
  and test_ecdsa_der)
- ecdsa_sig.json and ecdsa_custom_nonce_sig.json, the ECDSA vectors
  used by btclib, vendored from
  https://github.com/rustyrussell/secp256k1-py (tests/data);
  note: the rfc6979.json vectors used by btclib are NOT imported,
  as they only cover NIST curves (per RFC 6979 appendix A.2),
  not secp256k1
- the recovery id 2 and 3 fixture, which is published nowhere and is
  constructed here instead, against arithmetic this file does itself.
  Its derivation is documented where it is built
"""

from __future__ import annotations

import csv
import hashlib
import json
import pathlib

import pytest

from btclib_libsecp256k1 import dsa, mult, recovery, ssa

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# and its field prime and generator: the recovery below is computed here
# as well as by the bindings, which is what holds one to the other
P = 2**256 - 2**32 - 977
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int] | None


def der_decode(sig: bytes) -> tuple[int, int]:
    """Parse a canonical DER ECDSA signature, returning (r, s)."""
    assert sig[0] == 0x30, "not a DER sequence"
    assert sig[1] == len(sig) - 2, "wrong DER length byte"
    ints = []
    cursor = 2
    for _ in range(2):
        assert sig[cursor] == 0x02, "not a DER integer"
        length = sig[cursor + 1]
        payload = sig[cursor + 2 : cursor + 2 + length]
        assert len(payload) == length, "truncated DER integer"
        assert payload[0] < 0x80, "negative DER integer"
        if payload[0] == 0x00:
            assert length > 1, "zero-length DER integer"
            assert payload[1] >= 0x80, "non-minimal DER integer"
        ints.append(int.from_bytes(payload, "big"))
        cursor += 2 + length
    assert cursor == len(sig), "trailing garbage in DER"
    return ints[0], ints[1]


def point_add(point_1: Point, point_2: Point) -> Point:
    """Add two points of secp256k1, None being the point at infinity."""
    if point_1 is None:
        return point_2
    if point_2 is None:
        return point_1
    if point_1[0] == point_2[0] and (point_1[1] + point_2[1]) % P == 0:
        return None
    if point_1 == point_2:
        slope = 3 * point_1[0] * point_1[0] * pow(2 * point_1[1], -1, P) % P
    else:
        slope = (point_2[1] - point_1[1]) * pow(point_2[0] - point_1[0], -1, P) % P
    x = (slope * slope - point_1[0] - point_2[0]) % P
    return x, (slope * (point_1[0] - x) - point_1[1]) % P


def point_mul(scalar: int, point: Point) -> Point:
    """Multiply a point of secp256k1 by a scalar, double and add."""
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def compressed(point: Point) -> bytes:
    """Serialize a point of secp256k1 in its 33-byte compressed form."""
    assert point is not None, "the point at infinity has no serialization"
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def bip340_vectors() -> list[dict[str, str]]:
    """Read the BIP340 vector csv, vendored from bitcoin/bips."""
    path = pathlib.Path(__file__).parent / "bip340_test_vectors.csv"
    with path.open(newline="") as csv_file:
        return list(csv.DictReader(csv_file))


@pytest.mark.parametrize(
    "vector", bip340_vectors(), ids=lambda v: f"bip340-{v['index']}"
)
def test_bip340_vector(vector: dict[str, str]) -> None:
    """Verify one BIP340 vector, and reproduce its signature where it has one.

    The verification verdict is the vector's own. A vector carrying a
    secret key is also signed and the signature compared byte for byte,
    which the fixed aux_rand makes possible. Which function signs it is
    the length of the message: `ssa.sign` is BIP340's 32-byte signing, and
    `ssa.sign_custom` is the arbitrary-length one, so the four vectors
    added in 2022 -- messages of 0, 1, 17 and 100 octets -- are the only
    published values `sign_custom` can be held against. A structurally
    invalid input raises where the vector says false, so the exception is
    read as that verdict rather than as an error.
    """
    msg = bytes.fromhex(vector["message"])
    pubkey = bytes.fromhex(vector["public key"])
    sig = bytes.fromhex(vector["signature"])
    expected = vector["verification result"] == "TRUE"

    if vector["secret key"]:
        seckey = bytes.fromhex(vector["secret key"])
        aux_rand = bytes.fromhex(vector["aux_rand"])
        assert ssa.sign_custom(msg, seckey, aux_rand) == sig
        # sign_custom answers a 32-byte message with the signature sign
        # returns, which is what makes the two comparable at all
        if len(msg) == 32:
            assert ssa.sign(msg, seckey, aux_rand) == sig

    try:
        result = bool(ssa.verify(msg, pubkey, sig))
    except ValueError:
        # structurally invalid inputs raise instead of returning false
        result = False
    assert result == expected, vector["comment"]


# A signature whose nonce point has an x coordinate above the group
# order, which is what a recovery id of 2 or 3 says. No search produces
# one: x(kG) lands in [n, p) with probability about 2**-128, and finding
# a k that puts it there is the discrete logarithm problem. So the point
# comes first and the signature is built around it, which needs no k at
# all -- recovery is r**-1 (sR - eG), an equation in R rather than in its
# logarithm, and the key it answers with is defined by that equation
# rather than by a signer. Nobody holds the private key of this
# signature, and nothing here needs to.
#
# x is the smallest one above the order that is on the curve, and s is an
# arbitrary low-s scalar, low so that the DER conversion of the same
# signature is one dsa.verify accepts
HIGH_X_NONCE = N + 2
HIGH_X_S = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
HIGH_X_MSG = hashlib.sha256(b"btclib_libsecp256k1 recid 2 and 3").digest()


@pytest.mark.parametrize("recid", [2, 3])
def test_recovery_of_a_high_x_nonce(recid: int) -> None:
    """Recover a key from a signature whose nonce point x exceeds the order.

    recovery.py accepts `recid in range(4)` and the suite only ever fed
    it 0 and 1, so half of the accepted domain reached libsecp256k1 from
    no test. What the high bit of the recovery id says is that the x
    coordinate of the nonce point was reduced modulo the order on the way
    into r, so recovery has to add the order back before decompressing
    it; getting that wrong recovers a different key, or none.

    The recovered key is compared against the recovery equation computed
    here in python, not against something these bindings produced.
    """
    # n itself is on the curve, and would make r zero; n + 1 is not
    assert pow((pow(N + 1, 3, P) + 7) % P, (P - 1) // 2, P) == P - 1
    y_squared = (pow(HIGH_X_NONCE, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    assert pow(y, 2, P) == y_squared, "n + 2 is not on the curve"

    # the low bit of the recovery id is the parity of that y
    if (y % 2 == 0) != (recid == 2):
        y = P - y
    r = HIGH_X_NONCE - N
    e = int.from_bytes(HIGH_X_MSG, "big") % N
    expected = compressed(
        point_mul(
            pow(r, -1, N),
            point_add(point_mul(HIGH_X_S, (HIGH_X_NONCE, y)), point_mul(N - e, G)),
        )
    )

    signature = r.to_bytes(32, "big") + HIGH_X_S.to_bytes(32, "big")
    pubkey = recovery.recover(HIGH_X_MSG, signature, recid)
    assert pubkey == expected

    # and it is a key this signature verifies under, which is the whole
    # point of recovering one
    assert dsa.verify(HIGH_X_MSG, pubkey, recovery.to_der(signature, recid))
    # the same signature read as a low recovery id answers another key,
    # so the high bit is doing something rather than being ignored
    assert recovery.recover(HIGH_X_MSG, signature, recid - 2) != pubkey


def test_high_s_is_carried_through_recovery_unchanged() -> None:
    """recovery.recover and recovery.to_der leave a high-s signature alone.

    `to_der` documents that it does not normalize s, and nothing held it
    to that. Negating s modulo the order is the malleability ECDSA has:
    the result is a second valid signature of the same message under the
    same key, and it flips the parity of the nonce point, so it is the
    other recovery id that recovers the key from it.
    """
    msg = hashlib.sha256(b"btclib_libsecp256k1 high s").digest()
    prvkey = 7
    signature, recid = recovery.sign(msg, prvkey)
    pubkey = recovery.recover(msg, signature, recid)
    s = int.from_bytes(signature[32:], "big")
    assert s <= N // 2, "libsecp256k1 signs low-s"

    high_s = signature[:32] + (N - s).to_bytes(32, "big")
    assert recovery.recover(msg, high_s, recid ^ 1) == pubkey
    assert recovery.recover(msg, high_s, recid) != pubkey

    der = recovery.to_der(high_s, recid ^ 1)
    assert not dsa.is_low_s(der)
    # which is why dsa.verify refuses it, and normalizing recovers the
    # signature dsa.sign would have produced
    assert not dsa.verify(msg, pubkey, der)
    assert dsa.verify(msg, pubkey, dsa.normalize(der))
    assert dsa.normalize(der) == dsa.sign(msg, prvkey)


# (secret key, message, k, r, s)
RFC6979_ECDSA_VECTORS = [
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "Satoshi Nakamoto",
        "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15",
        "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
        "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "All those moments will be lost in time, like tears in rain. Time to die...",
        "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3",
        "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b",
        "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
    ),
    (
        "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
        "Alan Turing",
        "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1",
        "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c",
        "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
    ),
    (
        "0000000000000000000000000000000000000000000000000000000000000001",
        "Everything should be made as simple as possible, but not simpler.",
        "ec633bd56a5774a0940cb97e27a9e4e51dc94af737596a0c5cbb3d30332d92a5",
        "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
        "6f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262",
    ),
    (
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        (
            "Equations are more important to me, because politics is for the "
            "present, but an equation is something for eternity."
        ),
        "9dc74cbfd383980fb4ae5d2680acddac9dac956dca65a28c80ac9c847c2374e4",
        "54c4a33c6423d689378f160a7ff8b61330444abb58fb470f96ea16d99d4a2fed",
        "07082304410efa6b2943111b6a4e0aaa7b7db55a07e9861d1fb3cb1f421044a5",
    ),
    (
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        (
            "Not only is the Universe stranger than we think, it is stranger "
            "than we can think."
        ),
        "fd27071f01648ebbdd3e1cfbae48facc9fa97edc43bbbc9a7fdc28eae13296f5",
        "ff466a9f1b7b273e2f4c3ffe032eb2e814121ed18ef84665d0f515360dab3dd0",
        "6fc95f5132e5ecfdc8e5e6e616cc77151455d46ed48f5589b7db7771a332b283",
    ),
    (
        "69ec59eaa1f4f2e36b639716b7c30ca86d9a5375c7b38d8918bd9c0ebc80ba64",
        (
            "Computer science is no more about computers than astronomy is "
            "about telescopes."
        ),
        "6bb4a594ad57c1aa22dbe991a9d8501daf4688bf50a4892ef21bd7c711afda97",
        "7186363571d65e084e7f02b0b77c3ec44fb1b257dee26274c38c928986fea45d",
        "0de0b38e06807e46bda1f1e293f4f6323e854c86d58abdd00c46c16441085df6",
    ),
]


@pytest.mark.parametrize(
    "seckey_hex, msg_text, k_hex, r_hex, s_hex",
    RFC6979_ECDSA_VECTORS,
    ids=lambda v: v[:16] if isinstance(v, str) else None,
)
def test_rfc6979_ecdsa_vector(
    seckey_hex: str, msg_text: str, k_hex: str, r_hex: str, s_hex: str
) -> None:
    """Reproduce an RFC6979 signature, with the vector checked against itself.

    The vector publishes the nonce as well as r and s, so `r == x(k*G)` is
    asserted first: what that buys is knowing the vector is internally
    consistent before it is used to judge anything. libsecp256k1 always
    produces the low-s form, so the expected s is the smaller of s and
    n-s.
    """
    msg32 = hashlib.sha256(msg_text.encode()).digest()
    r = int(r_hex, 16)
    s = int(s_hex, 16)

    # vector self-consistency: r is the x coordinate of k*G
    assert mult.mult(bytes.fromhex(k_hex))[0] == r

    # libsecp256k1 always produces low-s signatures
    der = dsa.sign(msg32, bytes.fromhex(seckey_hex))
    assert der_decode(der) == (r, min(s, N - s))

    pubkey = mult.mult_(bytes.fromhex(seckey_hex))
    assert dsa.verify(msg32, pubkey, der)


# (secret key, digest, 64-byte compact signature r||s)
TREZOR_ECDSA_VECTORS = [
    (
        "312155017c70a204106e034520e0cdf17b3e54516e2ece38e38e38e38e38e38e",
        "ffffffffffffffffffffffffffffffff20202020202020202020202020202020",
        (
            "e3d70248ea2fc771fc8d5e62d76b9cfd5402c96990333549eaadce1ae9f737eb"
            "5cfbdc7d1e0ec18cc9b57bbb18f0a57dc929ec3c4dfac9073c581705015f6a8a"
        ),
    ),
    (
        "312155017c70a204106e034520e0cdf17b3e54516e2ece38e38e38e38e38e38e",
        "2020202020202020202020202020202020202020202020202020202020202020",
        (
            "40666188895430715552a7e4c6b53851f37a93030fb94e043850921242db78e8"
            "75aa2ac9fd7e5a19402973e60e64382cdc29a09ebf6cb37e92f23be5b9251aee"
        ),
    ),
]


@pytest.mark.parametrize("seckey_hex, digest_hex, sig_hex", TREZOR_ECDSA_VECTORS)
def test_trezor_ecdsa_vector(seckey_hex: str, digest_hex: str, sig_hex: str) -> None:
    """Reproduce a trezor ECDSA vector, given as a compact r||s.

    Two keys whose repeating tail is what makes them worth having: the
    vectors were chosen upstream to exercise the scalar arithmetic rather
    than to look random. The low-s form applies as above.
    """
    digest = bytes.fromhex(digest_hex)
    sig = bytes.fromhex(sig_hex)
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")

    der = dsa.sign(digest, bytes.fromhex(seckey_hex))
    assert der_decode(der) == (r, min(s, N - s))

    pubkey = mult.mult_(bytes.fromhex(seckey_hex))
    assert dsa.verify(digest, pubkey, der)


# encodings accepted by secp256k1_ecdsa_signature_parse_der: they parse
# fine and merely fail verification; note that the parser is lenient on
# two fronts (last three entries): integers with the high bit set are
# read as unsigned, and out-of-range values are zeroed instead of
# rejected
PARSED_DER = [
    (
        "30450221009a0b7be0d4ed3146ee262b42202841834698bb3ee39c24e7437df208b8"
        "b7077102202b79ab1e7736219387dffe8d615bbdba87e11477104b867ef47afed1a5"
        "ede781"
    ),
    (
        "30440220666666666666666666666666666666666666666666666666666666666666"
        "66660220777777777777777777777777777777777777777777777777777777777777"
        "7777"
    ),
    (
        "30450220666666666666666666666666666666666666666666666666666666666666"
        "6666022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeee"
    ),
    (
        "3045022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeee02207777777777777777777777777777777777777777777777777777777777"
        "777777"
    ),
    "3006020166020177",
    "3007020166020200ee",
    "3007020200ee020177",
    "3008020200ee020200ff",
    # r with the high bit set, read as a large unsigned integer
    (
        "304402207f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1"
        "f0220800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    ),
    # s not below the group order, zeroed by the parser
    (
        "3046022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        "eeeeee022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffff"
    ),
]

# rejected by secp256k1_ecdsa_signature_parse_der
REJECTED_DER = [
    "",
    "3008020200ee020200ff00",  # trailing garbage
    # non-minimal zero padding
    (
        "30440220007f0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1"
        "e022000800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
    ),
]


def json_vectors(name: str) -> list[dict[str, str]]:
    """Read a json vector file vendored from the secp256k1-py test suite."""
    path = pathlib.Path(__file__).parent / name
    with path.open(encoding="ascii") as json_file:
        vectors: list[dict[str, str]] = json.load(json_file)["vectors"]
    return vectors


def test_secp256k1py_ecdsa_vectors() -> None:
    """Reproduce every secp256k1-py ECDSA vector byte for byte.

    The vendored signature carries a trailing SIGHASH_ALL octet, which is
    a fact about the transaction it came from rather than part of the DER,
    so it is stripped before the comparison.
    """
    for vector in json_vectors("ecdsa_sig.json"):
        msg32 = bytes.fromhex(vector["msg"])
        prvkey = bytes.fromhex(vector["privkey"])
        # the vendored signature carries a trailing SIGHASH_ALL byte
        der = bytes.fromhex(vector["sig"])[:-1]

        assert dsa.sign(msg32, prvkey) == der
        pubkey = mult.mult_(prvkey)
        assert dsa.verify(msg32, pubkey, der)


def test_secp256k1py_custom_nonce_vectors() -> None:
    """Verify the custom-nonce vectors, and anchor each on its own nonce.

    The nonce field is the literal k, and the bindings expose the default
    RFC6979 derivation only, so these signatures cannot be reproduced.
    They are verified instead, with `r == x(k*G)` and the low-s rule
    asserted so that the vector is held to something of its own rather
    than only to a verification this package performs.
    """
    # the nonce field is the literal k: the bindings only expose the
    # default RFC6979 nonce, so signing cannot be reproduced; the
    # signature is verified instead, and anchored asserting r == x(k*G)
    for vector in json_vectors("ecdsa_custom_nonce_sig.json"):
        msg32 = bytes.fromhex(vector["msg"])
        prvkey = bytes.fromhex(vector["privkey"])
        k = bytes.fromhex(vector["nonce"])
        der = bytes.fromhex(vector["sig"])

        r, s = der_decode(der)
        assert s <= N // 2, "not a low-s signature"
        assert r == mult.mult(k)[0] % N
        pubkey = mult.mult_(prvkey)
        assert dsa.verify(msg32, pubkey, der)


def test_der_parsing() -> None:
    """Tell a signature that parses from one that does not.

    Both lists are encodings, and what separates them is whose question
    they answer: the first parse and then fail to verify, which is a
    verdict about the signature, and the second are refused as DER, which
    is a verdict about the octets. Reporting either as the other is what
    the two lists exist to catch.
    """
    msg32 = b"\x01" * 32
    pubkey = mult.mult_(1)
    for der_hex in PARSED_DER:
        # parses fine, does not verify
        assert not dsa.verify(msg32, pubkey, bytes.fromhex(der_hex))
    for der_hex in REJECTED_DER:
        with pytest.raises(ValueError, match="DER"):
            dsa.verify(msg32, pubkey, bytes.fromhex(der_hex))

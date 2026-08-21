# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests against independent, publicly documented test vectors.

- BIP340: bip340_test_vectors.csv, vendored from
  https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
- BIP324: bip324_ellswift_decode_test_vectors.csv and
  bip324_packet_encoding_test_vectors.csv, vendored from
  https://github.com/bitcoin/bips/tree/master/bip-0324; the second is
  the packet encoding suite, of which the ellswift/private key inputs
  and the shared secret are what these bindings compute
- BIP327: bip327_key_agg_vectors.json, bip327_nonce_agg_vectors.json,
  bip327_sign_verify_vectors.json and bip327_sig_agg_vectors.json,
  vendored from
  https://github.com/bitcoin/bips/tree/master/bip-0327/vectors
- BIP352: bip352_send_and_receive_test_vectors.json, vendored from
  https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json;
  both directions of every case are driven, the eligibility of an input
  being read off the keys the file itself publishes rather than off its
  scripts -- see `bip352_eligible`
- ECDSA RFC6979: (k, r, s) vectors published in
  https://bitcointalk.org/index.php?topic=285142.msg3300992
  as vendored by trezor-firmware (crypto/tests/test_check.c,
  test_rfc6979) and bitcoinjs-lib (test/fixtures/ecdsa.json);
  each vector is also self-checked here asserting r == x(k*G)
- deterministic ECDSA and DER encodings from trezor-firmware
  (crypto/tests/test_check.c, test_ecdsa_sign_digest_deterministic
  and test_ecdsa_der)
- low-r grinding, from the two implementations of the scheme this
  package copies: bitcoin/bitcoin src/test/key_tests.cpp, both the
  fixed signatures of `key_test1` and the property `key_signature_tests`
  asserts over 256 messages, and rust-bitcoin/rust-secp256k1 src/lib.rs
  `test_low_r`, whose vector is the one that takes more than one attempt
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
from typing import Any

import pytest

from btclib_secp256k1 import (
    dsa,
    ellswift,
    keys,
    musig,
    recovery,
    silentpayments,
    ssa,
    xonly,
)

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


def test_point_add_at_infinity() -> None:
    """The two cases the vectors below never reach, driven directly.

    `point_mul` is the only caller here, and it never hands `point_add`
    a second operand of None nor two points that cancel: it doubles and
    adds a generator by scalars that are group elements. So the identity
    on the right and the inverse are the arithmetic this file compares
    the bindings against, and are exercised by nothing that compares
    anything -- which is the shape a test of the reference itself exists
    for, the reference being wrong in a way no vector would report.
    """
    assert point_add(G, None) == G
    assert point_add(None, G) == G
    assert point_add(None, None) is None
    # -G is G mirrored across the x axis, and G + (-G) is the point at
    # infinity: the one sum of two affine points that has no affine value
    assert point_add(G, (G[0], P - G[1])) is None
    # a point and itself is doubling and not cancellation, which is the
    # distinction the first coordinate alone cannot make
    assert point_add(G, G) == point_mul(2, G)


def bip340_vectors() -> list[dict[str, str]]:
    """Read the BIP340 vector csv, vendored from bitcoin/bips."""
    path = pathlib.Path(__file__).parent / "bip340_test_vectors.csv"
    with path.open(newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


@pytest.mark.parametrize(
    "vector", bip340_vectors(), ids=lambda v: f"bip340-{v['index']}"
)
def test_bip340_vector(vector: dict[str, str]) -> None:
    """Verify one BIP340 vector, and reproduce its signature where it has one.

    The verification verdict is the vector's own. A vector carrying a
    secret key is also signed and the signature compared byte for byte,
    which the fixed aux_rand makes possible, and the public key of that
    secret key is checked against the vector's -- the published anchor
    for `keys.pubkey_from_prvkey`, whose compressed answer carries that
    x and a parity octet BIP340 drops. Which function signs it is
    the length of the message: `ssa.sign` is BIP340's 32-byte signing, and
    `ssa.sign_custom` is the arbitrary-length one, so the four vectors
    added in 2022 -- messages of 0, 1, 17 and 100 octets -- are the only
    published values `sign_custom` can be held against. `ssa.Signer` is
    those same two calls with the keypair hoisted out of them, so it is
    signed here as well, against the vector rather than against them. A
    structurally invalid input raises where the vector says false, so
    the exception is read as that verdict rather than as an error.
    """
    msg = bytes.fromhex(vector["message"])
    pubkey = bytes.fromhex(vector["public key"])
    sig = bytes.fromhex(vector["signature"])
    expected = vector["verification result"] == "TRUE"

    if vector["secret key"]:
        seckey = bytes.fromhex(vector["secret key"])
        aux_rand = bytes.fromhex(vector["aux_rand"])
        # the vector's public key is x(dG), which is the compressed
        # serialization of the same point without its first octet
        assert keys.pubkey_from_prvkey(seckey)[1:] == pubkey
        assert ssa.sign_custom(msg, seckey, aux_rand) == sig
        # sign_custom answers a 32-byte message with the signature sign
        # returns, which is what makes the two comparable at all
        if len(msg) == 32:
            assert ssa.sign(msg, seckey, aux_rand) == sig
        # and a signer is those same two calls with the keypair built
        # once, so the published value is what holds it too rather than
        # an agreement between two functions of this package
        with ssa.Signer(seckey) as signer:
            assert signer.sign_custom(msg, aux_rand) == sig
            if len(msg) == 32:
                assert signer.sign(msg, aux_rand) == sig

    try:
        result = bool(ssa.verify(msg, pubkey, sig))
    except ValueError:
        # structurally invalid inputs raise instead of returning false
        result = False
    assert result == expected, vector["comment"]


def bip324_vectors(name: str) -> list[dict[str, str]]:
    """Read one of the BIP324 vector csv files, vendored from bitcoin/bips."""
    path = pathlib.Path(__file__).parent / f"bip324_{name}_test_vectors.csv"
    with path.open(newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


@pytest.mark.parametrize(
    "vector",
    bip324_vectors("ellswift_decode"),
    ids=lambda v: f"ellswift-decode-{v['comment']}",
)
def test_bip324_ellswift_decode_vector(vector: dict[str, str]) -> None:
    """Decode one ElligatorSwift encoding to the x coordinate BIP324 gives.

    The suite's own ellswift tests encode and decode and agree with
    themselves, which says nothing about the map being the one BIP324
    defines. These are the published pairs, the degenerate cases among
    them: u or t zero, u**3 + t**2 + 7 zero, x2 or x3 chosen rather than
    x1.

    Only x is compared. BIP324 defines the map into a field element, so
    the y libsecp256k1 recovers with it -- the prefix of the compressed
    key this returns, which is 02 for some vectors and 03 for others --
    is a fact about the library rather than about the vector.
    """
    decoded = ellswift.decode(bytes.fromhex(vector["ellswift"]))
    assert decoded[1:].hex() == vector["x"]
    assert decoded[0] in (2, 3)


@pytest.mark.parametrize(
    "vector",
    bip324_vectors("packet_encoding"),
    ids=lambda v: f"ellswift-xdh-{v['in_idx']}",
)
def test_bip324_ellswift_xdh_vector(vector: dict[str, str]) -> None:
    """Reproduce the BIP324 shared secret of one packet encoding vector.

    `ellswift.xdh` is the whole reason the ellswift module is wrapped,
    and nothing independent checked it: the suite gave both parties the
    same secret, which two wrong implementations of one function also
    do.

    The vectors come from the packet encoding suite, whose later columns
    are the ciphers BIP324 builds on top and are no business of these
    bindings; `mid_shared_secret` is where this package's part ends. The
    two encodings go in the order BIP324 hashes them, initiator first,
    which is what `party` says: 0 when the private key is the
    initiator's, 1 when it is the responder's.
    """
    prvkey = bytes.fromhex(vector["in_priv_ours"])
    ours = bytes.fromhex(vector["in_ellswift_ours"])
    theirs = bytes.fromhex(vector["in_ellswift_theirs"])
    initiating = vector["in_initiating"] == "1"

    ell_a, ell_b, party = (ours, theirs, 0) if initiating else (theirs, ours, 1)
    assert (
        ellswift.xdh(ell_a, ell_b, prvkey, party).hex() == vector["mid_shared_secret"]
    )

    # the same vector pins the decoding of both encodings, which is the
    # x each party ends up multiplying
    assert ellswift.decode(ours)[1:].hex() == vector["mid_x_ours"]
    assert ellswift.decode(theirs)[1:].hex() == vector["mid_x_theirs"]


def bip327_vectors(name: str) -> dict[str, Any]:
    """Read one of the BIP327 vector json files, vendored from bitcoin/bips."""
    path = pathlib.Path(__file__).parent / f"bip327_{name}_vectors.json"
    with path.open(encoding="utf-8") as json_file:
        loaded: dict[str, Any] = json.load(json_file)
        return loaded


def musig_keyagg(
    pubkeys_hex: list[str], tweaks: list[tuple[bytes, bool]]
) -> musig.KeyAggCache | None:
    """Aggregate keys and apply the tweaks, None where a step is refused.

    Returns the key aggregation, which is what every later call reads.
    A vector's own error cases do not say which step failed -- an
    unparsable key or an out-of-range tweak are one refusal in the
    reference implementation -- so neither is told apart here either.
    """
    try:
        cache = musig.KeyAggCache([bytes.fromhex(pubkey) for pubkey in pubkeys_hex])
        for tweak, is_xonly in tweaks:
            if is_xonly:
                cache.pubkey_xonly_tweak_add(tweak)
            else:
                cache.pubkey_ec_tweak_add(tweak)
    except ValueError:
        return None
    return cache


def musig_xonly(cache: musig.KeyAggCache) -> str:
    """Serialize the aggregate key of a cache, as BIP327 writes it."""
    pubkey_bytes = cache.pubkey_get(compressed=False)
    return xonly.from_pubkey(pubkey_bytes)[0].hex().upper()


def musig_tweaks(
    vectors: dict[str, Any], case: dict[str, Any]
) -> list[tuple[bytes, bool]]:
    """Pair each tweak of a case with the flag saying how it is applied."""
    return [
        (bytes.fromhex(vectors["tweaks"][index]), is_xonly)
        for index, is_xonly in zip(
            case.get("tweak_indices", []), case.get("is_xonly", []), strict=True
        )
    ]


KEY_AGG = bip327_vectors("key_agg")
NONCE_AGG = bip327_vectors("nonce_agg")
SIGN_VERIFY = bip327_vectors("sign_verify")
SIG_AGG = bip327_vectors("sig_agg")

# libsecp256k1 signs the 32-byte message BIP340 does, and nothing else:
# secp256k1_musig_nonce_process takes a msg32. Two of the sign/verify
# vectors are an empty message and a 38-byte one, which BIP327 allows and
# no entry point here can be handed at all
SIGNABLE = [
    case
    for case in SIGN_VERIFY["valid_test_cases"]
    if len(bytes.fromhex(SIGN_VERIFY["msgs"][case["msg_index"]])) == 32
]


@pytest.mark.parametrize(
    "case", KEY_AGG["valid_test_cases"], ids=lambda c: c["expected"][:8]
)
def test_bip327_key_agg_vector(case: dict[str, Any]) -> None:
    """Aggregate the keys of one BIP327 vector into the key it publishes.

    `tests/test_musig.py` verifies an aggregate signature against an
    aggregate key `musig.KeyAggCache` computed, which is a round trip: a
    wrong-but-self-consistent aggregation passes it. This is the
    aggregation itself, against the published value -- the coefficients,
    the ordering, and the second-key special case among them.
    """
    cache = musig_keyagg(
        [KEY_AGG["pubkeys"][i] for i in case["key_indices"]],
        musig_tweaks(KEY_AGG, case),
    )
    assert cache is not None
    assert musig_xonly(cache) == case["expected"]


@pytest.mark.parametrize(
    "case", KEY_AGG["error_test_cases"], ids=lambda c: c["comment"]
)
def test_bip327_key_agg_error_vector(case: dict[str, Any]) -> None:
    """Refuse a key aggregation BIP327 says has to fail.

    Where it fails is not the vector's business: an unparsable key stops
    at the parse, an out-of-range tweak at the tweak, and the reference
    implementation reports both as one error. What is pinned is that
    nothing comes out the other end.
    """
    assert (
        musig_keyagg(
            [KEY_AGG["pubkeys"][i] for i in case["key_indices"]],
            musig_tweaks(KEY_AGG, case),
        )
        is None
    )


@pytest.mark.parametrize(
    "case", NONCE_AGG["valid_test_cases"], ids=lambda c: c["expected"][:8]
)
def test_bip327_nonce_agg_vector(case: dict[str, Any]) -> None:
    """Aggregate public nonces into the 66 bytes BIP327 publishes."""
    pubnonces = [bytes.fromhex(NONCE_AGG["pnonces"][i]) for i in case["pnonce_indices"]]
    assert musig.nonce_agg(pubnonces).hex().upper() == case["expected"]


@pytest.mark.parametrize(
    "case", NONCE_AGG["error_test_cases"], ids=lambda c: c["comment"]
)
def test_bip327_nonce_agg_error_vector(case: dict[str, Any]) -> None:
    """Refuse a public nonce BIP327 says is invalid, at the parse."""
    pubnonces = [bytes.fromhex(NONCE_AGG["pnonces"][i]) for i in case["pnonce_indices"]]
    with pytest.raises(ValueError, match="public nonce"):
        musig.nonce_agg(pubnonces)


@pytest.mark.parametrize("case", SIGNABLE, ids=lambda c: c["expected"][:8])
def test_bip327_partial_sig_verify_vector(case: dict[str, Any]) -> None:
    """Verify the partial signature BIP327 publishes for one signer.

    The signing direction cannot be driven from these vectors:
    libsecp256k1 has no parser for a serialized secret nonce, by design
    -- a secnonce that can be loaded is a secnonce that can be reused --
    so the `sk` and `secnonces` of this file have no entry point. What is
    checkable is the verification, which reads the same equation from the
    other side: a partial signature verifies against its signer's public
    nonce and public key only if the coefficients, the aggregate nonce
    and the challenge are the ones BIP327 defines.
    """
    pubkeys = [SIGN_VERIFY["pubkeys"][i] for i in case["key_indices"]]
    cache = musig_keyagg(pubkeys, [])
    assert cache is not None

    aggnonce_bytes = bytes.fromhex(SIGN_VERIFY["aggnonces"][case["aggnonce_index"]])
    msg = bytes.fromhex(SIGN_VERIFY["msgs"][case["msg_index"]])
    session = musig.Session(aggnonce_bytes, msg, cache)

    signer = case["signer_index"]
    pubnonce_bytes = bytes.fromhex(
        SIGN_VERIFY["pnonces"][case["nonce_indices"][signer]]
    )
    partial_sig_bytes = bytes.fromhex(case["expected"])
    assert session.partial_sig_verify(
        partial_sig_bytes, pubnonce_bytes, bytes.fromhex(pubkeys[signer]), cache
    )


@pytest.mark.parametrize(
    "case", SIGN_VERIFY["verify_fail_test_cases"], ids=lambda c: c["comment"]
)
def test_bip327_partial_sig_verify_fail_vector(case: dict[str, Any]) -> None:
    """Refuse a partial signature BIP327 says does not verify."""
    pubkeys = [SIGN_VERIFY["pubkeys"][i] for i in case["key_indices"]]
    cache = musig_keyagg(pubkeys, [])
    assert cache is not None

    pubnonces = [
        bytes.fromhex(SIGN_VERIFY["pnonces"][i]) for i in case["nonce_indices"]
    ]
    aggnonce = musig.nonce_agg(pubnonces)
    msg = bytes.fromhex(SIGN_VERIFY["msgs"][case["msg_index"]])
    session = musig.Session(aggnonce, msg, cache)

    signer = case["signer_index"]
    # a signature out of range is refused by the parse; one in range and
    # wrong, by the verification
    try:
        verified = session.partial_sig_verify(
            bytes.fromhex(case["sig"]),
            pubnonces[signer],
            bytes.fromhex(pubkeys[signer]),
            cache,
        )
    except ValueError:
        return
    assert not verified


@pytest.mark.parametrize(
    "case", SIG_AGG["valid_test_cases"], ids=lambda c: c["expected"][:8]
)
def test_bip327_sig_agg_vector(case: dict[str, Any]) -> None:
    """Aggregate partial signatures into the BIP340 signature BIP327 publishes.

    The tweaked cases are the taproot ones, and they are why this is
    worth pinning separately from the round trip: the tweak enters the
    aggregate signature through the session, and an aggregation that got
    it wrong would still produce something self-consistent.
    """
    cache = musig_keyagg(
        [SIG_AGG["pubkeys"][i] for i in case["key_indices"]],
        musig_tweaks(SIG_AGG, case),
    )
    assert cache is not None

    aggnonce_bytes = bytes.fromhex(case["aggnonce"])
    msg = bytes.fromhex(SIG_AGG["msg"])
    session = musig.Session(aggnonce_bytes, msg, cache)

    partial_sigs = [bytes.fromhex(SIG_AGG["psigs"][i]) for i in case["psig_indices"]]
    signature = session.partial_sig_agg(partial_sigs)
    assert signature.hex().upper() == case["expected"]
    # and it is a BIP340 signature of the aggregate key, tweaks included
    assert ssa.verify(msg, bytes.fromhex(musig_xonly(cache)), signature)


@pytest.mark.parametrize(
    "case", SIG_AGG["error_test_cases"], ids=lambda c: c["comment"]
)
def test_bip327_sig_agg_error_vector(case: dict[str, Any]) -> None:
    """Refuse a partial signature BIP327 says cannot be aggregated.

    Every error case of this vector is a signature that fails to parse,
    which `tests/README.md` records; a session is not built to check it,
    the parse failure being independent of which one it would have been.
    """
    refused = 0
    for i in case["psig_indices"]:
        try:
            musig.partial_sig_parse(bytes.fromhex(SIG_AGG["psigs"][i]))
        except ValueError:
            refused += 1
    assert refused > 0


def bip352_vectors() -> list[dict[str, Any]]:
    """Load the BIP352 send and receive vectors."""
    path = pathlib.Path(__file__).parent / "bip352_send_and_receive_test_vectors.json"
    with path.open(encoding="utf-8") as json_file:
        cases: list[dict[str, Any]] = json.load(json_file)
    return cases


BIP352 = bip352_vectors()


def bip352_outpoint(vin: list[dict[str, Any]]) -> bytes:
    """Choose the lexicographically smallest outpoint of a vector's inputs.

    libsecp256k1 takes it already chosen, BIP352 stating the choice over
    the transaction rather than over the keys, so it is made here: each
    outpoint is the txid in internal byte order and the little endian
    vout, and the smallest of them is the smallest as bytes -- which case
    4 of these vectors is the one that distinguishes from the smallest
    vout.
    """
    outpoints: list[bytes] = [
        bytes.fromhex(vin_entry["txid"])[::-1]
        + int(vin_entry["vout"]).to_bytes(4, "little")
        for vin_entry in vin
    ]
    return min(outpoints)


def bip352_is_taproot(vin_entry: dict[str, Any]) -> bool:
    """Whether an input's prevout is P2TR: OP_1 OP_PUSHBYTES_32 <32 bytes>.

    Which side of `create_outputs` and `prevouts_summary` a key goes to,
    and the one script question these vectors cannot be driven without:
    BIP352 reads a taproot input as the even-y point of its x-only key
    and any other as the full key, so the two are separate arguments and
    the caller says which is which.
    """
    script = bytes.fromhex(vin_entry["prevout"]["scriptPubKey"]["hex"])
    return len(script) == 34 and script[0] == 0x51 and script[1] == 0x20


def bip352_eligible(
    vin: list[dict[str, Any]], input_pub_keys: list[str]
) -> list[tuple[dict[str, Any], str]]:
    """Pair each Silent Payments eligible input with its public key.

    BIP352's eligibility rules are rules about scripts -- a bare
    multisig, an uncompressed key and a NUMS-point script path are each
    excluded by one of them -- and scripts are what these bindings
    deliberately do not read. So the rules are not reimplemented here:
    the vectors publish the extracted keys of exactly the eligible
    inputs, in input order, and this walks the two in step. A taproot
    input is recognized by its prevout carrying the key; any other by
    pushing it in the scriptSig or the witness.

    Matching by containment alone would be wrong, and case 22 is why: its
    third input is a bare multisig whose redeem script names the key of
    the *first* input, so a key already claimed would be claimed twice.
    Consuming them in order is what refuses it.

    Args:
        vin: the inputs, as the vector gives them.
        input_pub_keys: the published 33-byte keys, hex, in input order.

    Returns:
        One pair per eligible input: the input, and its key as hex.
    """
    remaining = list(input_pub_keys)
    eligible = []
    for vin_entry in vin:
        if not remaining:
            break
        candidate = remaining[0]
        if bip352_is_taproot(vin_entry):
            xonly = vin_entry["prevout"]["scriptPubKey"]["hex"][4:]
            matched = candidate[2:] == xonly
        else:
            pushed = vin_entry["scriptSig"] + vin_entry["txinwitness"]
            matched = candidate in pushed
        if matched:
            eligible.append((vin_entry, remaining.pop(0)))
    return eligible


def bip352_recipients(given: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    """Pair up the keys to pay, one pair per output the vector asks for."""
    return [
        (bytes.fromhex(r["scan_pub_key"]), bytes.fromhex(r["spend_pub_key"]))
        for r in given["recipients"]
        for _ in range(r.get("count", 1))
    ]


@pytest.mark.parametrize("case", BIP352, ids=[case["comment"] for case in BIP352])
def test_bip352_sending_vector(case: dict[str, Any]) -> None:
    """Create the outputs BIP352 publishes for a transaction and its recipients.

    The published `outputs` is a list of *alternative* output sets, and
    not orderings of one: where several recipients share a scan public
    key, which of them gets k = 0, which k = 1 and so on is not
    determined, and each assignment gives different output keys. Cases 15
    and 17 are the ones where those sets genuinely differ -- 17 lists
    twelve of them -- so what is asserted is that the set produced is one
    of the sets accepted, whichever assignment libsecp256k1 made.
    Comparing with the first entry alone would fail there while being
    right about everything else, which is how this was found.

    Order within the set is not compared for the same reason. It is not
    unspecified -- libsecp256k1 returns one output per recipient in the
    order the recipients were given -- it is simply not what these
    vectors pin, and `test_the_outputs_follow_the_recipient_order` in
    tests/test_modules.py is what holds it.

    A single empty set is the sender making nothing, which here is a
    `ValueError` rather than an empty list: there is no silent payment
    with no input to derive it from.

    Args:
        case: one vector, both directions of it.
    """
    for send in case["sending"]:
        given, expected = send["given"], send["expected"]
        taproot_prvkeys: list[bytes] = []
        prvkeys: list[bytes] = []
        for vin_entry, _ in bip352_eligible(given["vin"], expected["input_pub_keys"]):
            prvkey = bytes.fromhex(vin_entry["private_key"])
            keys_of_its_kind = (
                taproot_prvkeys if bip352_is_taproot(vin_entry) else prvkeys
            )
            keys_of_its_kind.append(prvkey)

        recipients = bip352_recipients(given)
        outpoint = bip352_outpoint(given["vin"])
        if expected["outputs"] == [[]]:
            with pytest.raises(ValueError, match=r"silent payment|private key"):
                silentpayments.create_outputs(
                    recipients,
                    outpoint,
                    taproot_prvkeys=taproot_prvkeys,
                    prvkeys=prvkeys,
                )
            continue

        outputs = silentpayments.create_outputs(
            recipients, outpoint, taproot_prvkeys=taproot_prvkeys, prvkeys=prvkeys
        )
        accepted = [sorted(output_set) for output_set in expected["outputs"]]
        assert sorted(output.hex() for output in outputs) in accepted


@pytest.mark.parametrize("case", BIP352, ids=[case["comment"] for case in BIP352])
def test_bip352_receiving_vector(case: dict[str, Any]) -> None:
    """Find the outputs BIP352 publishes as this recipient's, and their tweaks.

    The input public keys are the ones the sending half of the same
    vector publishes, the transaction being the same one: extracting them
    from the scripts again would be the script reader this package has
    no business carrying.

    A transaction whose eligible inputs sum to the point at infinity, or
    which has none, is BIP352's "not a Silent Payments transaction": the
    recipient skips it, and here that is `prevouts_summary` refusing it
    rather than a scan that finds nothing.

    Args:
        case: one vector, both directions of it.
    """
    input_pub_keys = case["sending"][0]["expected"]["input_pub_keys"]
    for recv in case["receiving"]:
        given, expected = recv["given"], recv["expected"]
        taproot_pubkeys: list[bytes] = []
        pubkeys: list[bytes] = []
        for vin_entry, pubkey_hex in bip352_eligible(given["vin"], input_pub_keys):
            pubkey = bytes.fromhex(pubkey_hex)
            if bip352_is_taproot(vin_entry):
                taproot_pubkeys.append(pubkey[1:])
            else:
                pubkeys.append(pubkey)

        scan_prvkey = bytes.fromhex(given["key_material"]["scan_priv_key"])
        spend_prvkey = bytes.fromhex(given["key_material"]["spend_priv_key"])
        spend_pubkey = keys.pubkey_from_prvkey(spend_prvkey)
        labels = dict(silentpayments.label(scan_prvkey, m) for m in given["labels"])

        outpoint = bip352_outpoint(given["vin"])
        # a published null shared secret is BIP352's "not a Silent
        # Payments transaction", and says so about the transaction rather
        # than about this recipient: there are no eligible inputs, or
        # they sum to the point at infinity. The recipient skips it, and
        # here that is prevouts_summary refusing to make one at all --
        # which is not the same as the scan below finding nothing, the
        # case whose shared secret exists and matches no output of it
        if expected["shared_secret"] is None:
            assert expected["outputs"] == []
            with pytest.raises(ValueError, match=r"public key|silent payments"):
                silentpayments.prevouts_summary(
                    outpoint,
                    taproot_pubkeys_bytes=taproot_pubkeys,
                    pubkeys_bytes=pubkeys,
                )
            continue

        summary = silentpayments.prevouts_summary(
            outpoint, taproot_pubkeys_bytes=taproot_pubkeys, pubkeys_bytes=pubkeys
        )
        found = silentpayments.scan_outputs(
            [bytes.fromhex(output) for output in given["outputs"]],
            scan_prvkey,
            summary,
            spend_pubkey,
            labels=labels or None,
        )
        # the K_max case publishes how many outputs are found rather than
        # which: 2324 outputs pay one scan key, and BIP352 stops at 2323
        if "outputs" not in expected:
            assert len(found) == expected["n_outputs"]
            continue

        assert sorted(pubkey.hex() for pubkey, _, _ in found) == sorted(
            output["pub_key"] for output in expected["outputs"]
        )
        assert sorted(tweak.hex() for _, tweak, _ in found) == sorted(
            output["priv_key_tweak"] for output in expected["outputs"]
        )
        # a label is found only because its tweak was in the cache handed
        # in, so an output reported with one is that lookup having worked
        assert all(label in labels for _, _, label in found if label is not None)


@pytest.mark.parametrize(
    "case",
    [case for case in BIP352 if any(r["given"]["labels"] for r in case["receiving"])],
    ids=[
        case["comment"]
        for case in BIP352
        if any(r["given"]["labels"] for r in case["receiving"])
    ],
)
def test_bip352_labeled_spend_pubkey_vector(case: dict[str, Any]) -> None:
    """Reproduce a labeled address the senders of a vector were paying to.

    The published recipient keys are the sender's view of an address, and
    the sender cannot tell a labeled spend public key from an unlabeled
    one. That is what makes them a check on this side: for each labeled
    receiving case, the label it uses is the one whose labeled spend
    public key is among the keys its senders were given.

    Args:
        case: one vector, whose receiving half uses at least one label.
    """
    published = {
        r["spend_pub_key"]
        for send in case["sending"]
        for r in send["given"]["recipients"]
    }
    for recv in case["receiving"]:
        given = recv["given"]
        if not given["labels"]:
            continue
        scan_prvkey = bytes.fromhex(given["key_material"]["scan_priv_key"])
        spend_prvkey = bytes.fromhex(given["key_material"]["spend_priv_key"])
        spend_pubkey = keys.pubkey_from_prvkey(spend_prvkey)
        labeled = {
            silentpayments.labeled_spend_pubkey(
                spend_pubkey, silentpayments.label(scan_prvkey, m)[0]
            ).hex()
            for m in given["labels"]
        }
        assert labeled & published, "no label reproduces a published recipient key"


def test_the_bip352_vectors_were_read_at_all() -> None:
    """Guard the three tests above against a file that parsed to nothing.

    Every one of them is a loop over a vector's own contents, so an empty
    case list, or cases with empty halves, is a pass that asserted
    nothing. No count is stated: what is required is that both directions
    of every case carry something to drive.
    """
    assert BIP352
    for case in BIP352:
        assert case["sending"], case["comment"]
        assert case["receiving"], case["comment"]


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
HIGH_X_MSG = hashlib.sha256(b"btclib_secp256k1 recid 2 and 3").digest()


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
    msg = hashlib.sha256(b"btclib_secp256k1 high s").digest()
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

    The published k is also what `dsa.nonce_rfc6979` has to answer, which
    is the only assertion here that holds that entry point to something
    other than this package: `tests/test_nonces.py` compares it with the
    signature it made, and this compares it with the value RFC6979
    publishes.
    """
    msg32 = hashlib.sha256(msg_text.encode()).digest()
    r = int(r_hex, 16)
    s = int(s_hex, 16)

    # the derivation itself, against the published nonce rather than
    # against a signature of ours
    assert dsa.nonce_rfc6979(msg32, bytes.fromhex(seckey_hex)) == bytes.fromhex(k_hex)

    # vector self-consistency: r is the x coordinate of k*G
    assert (
        int.from_bytes(
            keys.pubkey_from_prvkey(bytes.fromhex(k_hex), compressed=False)[1:33], "big"
        )
        == r
    )

    # libsecp256k1 always produces low-s signatures
    der = dsa.sign(msg32, bytes.fromhex(seckey_hex))
    assert der_decode(der) == (r, min(s, N - s))

    pubkey = keys.pubkey_from_prvkey(bytes.fromhex(seckey_hex), compressed=False)
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

    pubkey = keys.pubkey_from_prvkey(bytes.fromhex(seckey_hex), compressed=False)
    assert dsa.verify(digest, pubkey, der)


# Bitcoin Core's src/test/key_tests.cpp, key_test1: the scalars of the
# WIFs strSecret1 and strSecret2, signing Hash("Very deterministic
# message") through CKey::Sign, which grinds unless told otherwise. Core
# asserts the same octets for the compressed and the uncompressed
# spelling of each key, so the scalar is all there is to carry over --
# and it is the scalar this package takes anyway, a private key having
# no compression flag on this side of the boundary
CORE_PRVKEY1 = "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747"
CORE_PRVKEY2 = "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117"
CORE_DETERMINISTIC_VECTORS = [
    (
        CORE_PRVKEY1,
        (
            "304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe5"
            "9d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd"
            "4582f6"
        ),
    ),
    (
        CORE_PRVKEY2,
        (
            "3044022052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9d"
            "c1cd5022061d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771"
            "b5944d"
        ),
    ),
]

# rust-bitcoin/rust-secp256k1, src/lib.rs, test_low_r: the same counter
# scheme in an implementation that shares no line of code with Core's,
# and a case that needs five attempts to reach a low r -- so the counter
# is in the answer here, where Core's own vectors are settled by the
# first attempt
RUST_LOW_R_MSG = "887d04bb1cf1b1554f1b268dfe62d13064ca67ae45348d50d1392ce2d13418ac"
RUST_LOW_R_PRVKEY = "57f0148f94d13095cfda539d0da0d1541304b678d8b36e243980aab4e1b7cead"
RUST_LOW_R_SIG = (
    "047dd4d049db02b430d24c41c7925b2725bcd5a85393513bdec04b4dc363632b"
    "1054d0180094122b380f4cfa391e6296244da773173e78fc745c1b9c79f7b713"
)


def hash256(msg: bytes) -> bytes:
    """Return Bitcoin Core's Hash(), which is the SHA256 of the SHA256."""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


@pytest.mark.parametrize("prvkey_hex, der_hex", CORE_DETERMINISTIC_VECTORS)
def test_bitcoin_core_deterministic_vector(prvkey_hex: str, der_hex: str) -> None:
    """Reproduce the deterministic signatures of Core's `key_test1`.

    Both are low-r at the first attempt, which is the half of grinding a
    fixed vector pins without looking as though it pins anything: asking
    for it has to change nothing, and a loop that ground one attempt too
    many, or that read the wrong octet of the compact form, would answer
    something else here.
    """
    msg = hash256(b"Very deterministic message")
    prvkey = bytes.fromhex(prvkey_hex)

    assert dsa.sign(msg, prvkey).hex() == der_hex
    assert dsa.sign(msg, prvkey, grind=True).hex() == der_hex
    assert dsa.verify(msg, keys.pubkey_from_prvkey(prvkey), bytes.fromhex(der_hex))
    # and Core's vector is what `is_low_r` is held to as well: these
    # octets are low-r because Core says so, not because this package
    # produced them
    assert dsa.is_low_r(bytes.fromhex(der_hex))


def test_rust_secp256k1_low_r_vector() -> None:
    """Reproduce rust-secp256k1's `test_low_r`, which grinds five times.

    The vector that says the counter is written the way both other
    implementations write it: little endian, in the first 4 of 32 octets,
    starting at 1 for the attempt after the deterministic one. Any other
    reading of those octets diverges by the second attempt, and this one
    needs five -- the first is the signature asserted below to be the one
    with the high r.
    """
    msg = bytes.fromhex(RUST_LOW_R_MSG)
    prvkey = bytes.fromhex(RUST_LOW_R_PRVKEY)

    assert dsa.sign(msg, prvkey, compact=True, grind=True).hex() == RUST_LOW_R_SIG
    # what grinding was for: the deterministic signature of this key and
    # message is the high-r one, so the vector above is not it -- which
    # is the False `is_low_r` has no vector of its own for
    assert dsa.sign(msg, prvkey, compact=True)[0] >= 0x80
    assert not dsa.is_low_r(dsa.sign(msg, prvkey))
    assert dsa.is_low_r(dsa.to_der(bytes.fromhex(RUST_LOW_R_SIG)))
    assert dsa.verify(
        msg,
        keys.pubkey_from_prvkey(prvkey),
        bytes.fromhex(RUST_LOW_R_SIG),
        compact=True,
    )


def test_bitcoin_core_low_r_property() -> None:
    """Reproduce `key_signature_tests` of Core's src/test/key_tests.cpp.

    Core's own property, over its own inputs: 256 messages signed with
    grinding, none of them encoding to more than 70 octets and none with
    an r of more than 32, at least one shorter than 70 -- and, before
    that, the other half of the same test, that specifying the entropy
    without grinding does reach a high r within 20 tries. That last one
    is what makes the rest mean something: it is the same 32 octets the
    grinding counter writes, so it says the loop has something to find
    rather than a predicate that is always true.
    """
    prvkey = bytes.fromhex(CORE_PRVKEY1)

    # a high r within 20 tries, the counter as Core's test_case writes it
    high_r = [
        dsa.sign(
            hash256(b"A message to be signed"),
            prvkey,
            attempt.to_bytes(4, "little") + bytes(28),
        )
        for attempt in range(1, 21)
    ]
    assert any(der[3:5] == b"\x21\x00" for der in high_r)
    # Core's own reading of those octets is the length of r, and
    # `is_low_r` has to answer the same way about every one of them
    assert all(dsa.is_low_r(der) == (der[3] <= 32) for der in high_r)

    lengths = set()
    for i in range(256):
        der = dsa.sign(
            hash256(b"A message to be signed" + str(i).encode()), prvkey, grind=True
        )
        # der[3] is the length of r, which grinding holds to 32 octets:
        # the leading zero DER spends on a high one is what it is for
        assert der[3] <= 32
        assert dsa.is_low_r(der)
        lengths.add(len(der))
    assert max(lengths) <= 70
    assert min(lengths) < 70


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
        pubkey = keys.pubkey_from_prvkey(prvkey, compressed=False)
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
        assert (
            r
            == int.from_bytes(keys.pubkey_from_prvkey(k, compressed=False)[1:33], "big")
            % N
        )
        pubkey = keys.pubkey_from_prvkey(prvkey, compressed=False)
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
    pubkey = keys.pubkey_from_prvkey(1, compressed=False)
    for der_hex in PARSED_DER:
        # parses fine, does not verify
        assert not dsa.verify(msg32, pubkey, bytes.fromhex(der_hex))
    for der_hex in REJECTED_DER:
        with pytest.raises(ValueError, match="DER"):
            dsa.verify(msg32, pubkey, bytes.fromhex(der_hex))

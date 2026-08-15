# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every private half answers what its public half answers.

`_foo_` means one thing across these bindings, and the package docstring
states it: the wrapper takes the parsed object in place of the octets,
and the public half is that same call with a `parse` in front of it, a
`serialize` behind it, or both. That is an equality, so it is written as
one here, pair by pair and -- where the object is a public key -- over
both serializations of it, which is what keeps the two halves from
drifting into two implementations of the same thing.

`test_every_private_half_is_paired` holds the tables to the modules' own
contents, so a private half added and not paired here is visible as an
absence rather than as a test nobody wrote.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from btclib_secp256k1 import (
    dsa,
    ecdh,
    ellswift,
    ffi,
    keys,
    mult,
    recovery,
    silentpayments,
    ssa,
    xonly,
)

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

PRVKEY = 7
TWEAK = 11
SCAN_PRVKEY = 13
MSG = hashlib.sha256(b"btclib_secp256k1").digest()
# the randomness of an ElligatorSwift encoding, pinned: fresh randomness
# is what the encoding takes by default, and two of those never agree
RND32 = bytes(32)

PUBKEY_LONG = mult.mult_bytes(PRVKEY)
PUBKEY = keys.pubkey_from_prvkey(PRVKEY)
OTHER = keys.pubkey_from_prvkey(3)
XONLY, PARITY = xonly.from_pubkey(PUBKEY)
DER = dsa.sign(MSG, PRVKEY)
# the same signature with s negated, which is the malleation the lower-s
# rule rules out: `normalize` is what puts it back
HIGH_S = dsa.to_der(
    dsa.to_compact(DER)[:32]
    + (N - int.from_bytes(dsa.to_compact(DER)[32:], "big")).to_bytes(32, "big")
)
SSA_SIG = ssa.sign(MSG, PRVKEY, bytes(32))
TWEAKED, TWEAKED_PARITY = xonly.tweak_add(XONLY, TWEAK)
RECOVERABLE, RECID = recovery.sign(MSG, PRVKEY)
ELL = ellswift.create(PRVKEY, RND32)
LABEL, LABEL_TWEAK = silentpayments.label(SCAN_PRVKEY, 0)

# the Silent Payments transaction the two sides of that module are held
# to: one recipient, one input, and the outputs the sender creates
SP_OUTPOINT = bytes(36)
SP_SCAN_PUBKEY = keys.pubkey_from_prvkey(SCAN_PRVKEY)
SP_SPEND_PUBKEY = keys.pubkey_from_prvkey(PRVKEY)
SP_INPUT_PRVKEY = 3
SP_INPUT_PUBKEY = keys.pubkey_from_prvkey(SP_INPUT_PRVKEY)
SP_OUTPUTS = silentpayments.create_outputs(
    [(SP_SCAN_PUBKEY, SP_SPEND_PUBKEY)], SP_OUTPOINT, prvkeys=[SP_INPUT_PRVKEY]
)
SP_SUMMARY = silentpayments.prevouts_summary(
    SP_OUTPOINT, pubkeys_bytes=[SP_INPUT_PUBKEY]
)


def label_through_the_private_half() -> tuple[bytes, bytes]:
    """Create a label through `_label_`, and serialize what it answered.

    Returns:
        The 33-byte label and its 32-byte tweak, which is the pair
        `silentpayments.label` answers with.
    """
    label_obj, tweak = silentpayments._label_(SCAN_PRVKEY, 0)
    return silentpayments.serialize_label(label_obj), tweak


def scan_through_the_private_half() -> list[tuple[bytes, bytes, bytes | None]]:
    """Scan the transaction with every argument already parsed.

    Returns:
        What `silentpayments.scan_outputs` answers for the same
        transaction, which is a list of triples of octets either way.
    """
    return silentpayments._scan_outputs_(
        [xonly.parse(output) for output in SP_OUTPUTS],
        SCAN_PRVKEY,
        silentpayments._prevouts_summary_(
            SP_OUTPOINT, pubkeys=[keys.parse(SP_INPUT_PUBKEY)]
        ),
        keys.parse(SP_SPEND_PUBKEY),
    )


# every pair whose object is a public key: the private half's name, the
# public half as a call of the serialized key alone, and the private one
# as a call of the parsed key. The arguments that are not the key are
# closed over, being the same on both sides by construction. Two of the
# private halves answer with the key they mutated, and a cffi object is
# equal to no other, so those are compared through `keys.serialize` --
# which is what their public halves do with the same object
PAIRS: list[tuple[str, Callable[[bytes], Any], Callable[[Any], Any]]] = [
    (
        "keys._pubkey_negate_",
        keys.pubkey_negate,
        lambda pubkey: keys.serialize(keys._pubkey_negate_(pubkey)),
    ),
    (
        "keys._pubkey_tweak_add_",
        lambda pubkey_bytes: keys.pubkey_tweak_add(pubkey_bytes, TWEAK),
        lambda pubkey: keys.serialize(keys._pubkey_tweak_add_(pubkey, TWEAK)),
    ),
    (
        "keys._pubkey_tweak_mul_",
        lambda pubkey_bytes: keys.pubkey_tweak_mul(pubkey_bytes, TWEAK),
        lambda pubkey: keys.serialize(keys._pubkey_tweak_mul_(pubkey, TWEAK)),
    ),
    (
        "keys._pubkey_cmp_",
        lambda pubkey_bytes: keys.pubkey_cmp(pubkey_bytes, OTHER),
        lambda pubkey: keys._pubkey_cmp_(pubkey, keys.parse(OTHER)),
    ),
    ("xonly._from_pubkey_", xonly.from_pubkey, xonly._from_pubkey_),
    (
        "ecdh._shared_secret_",
        lambda pubkey_bytes: ecdh.shared_secret(pubkey_bytes, PRVKEY),
        lambda pubkey: ecdh._shared_secret_(pubkey, PRVKEY),
    ),
    (
        "dsa._verify_",
        lambda pubkey_bytes: dsa.verify(MSG, pubkey_bytes, DER),
        lambda pubkey: dsa._verify_(MSG, pubkey, dsa.parse_der(DER)),
    ),
    (
        "ellswift._encode_",
        lambda pubkey_bytes: ellswift.encode(pubkey_bytes, RND32),
        lambda pubkey: ellswift._encode_(pubkey, RND32),
    ),
]

# and every other pair, whose object is produced rather than taken, or is
# a signature, a label or a summary rather than a key: each is written as
# the pair of calls it is, so there are no two serializations of an
# argument to drive them with and the equality is over the answer alone
EQUALITIES: list[tuple[str, Callable[[], Any], Callable[[], Any]]] = [
    (
        "keys._pubkey_from_prvkey_",
        lambda: keys.pubkey_from_prvkey(PRVKEY),
        lambda: keys.serialize(keys._pubkey_from_prvkey_(PRVKEY)),
    ),
    (
        "keys._pubkey_combine_",
        lambda: keys.pubkey_combine([PUBKEY, OTHER]),
        lambda: keys.serialize(
            keys._pubkey_combine_([keys.parse(PUBKEY), keys.parse(OTHER)])
        ),
    ),
    (
        "keys._pubkey_sort_",
        lambda: keys.pubkey_sort([PUBKEY, OTHER]),
        lambda: [
            keys.serialize(pubkey)
            for pubkey in keys._pubkey_sort_([keys.parse(PUBKEY), keys.parse(OTHER)])
        ],
    ),
    (
        "dsa._sign_",
        lambda: dsa.sign(MSG, PRVKEY),
        lambda: dsa.serialize_der(dsa._sign_(MSG, PRVKEY)),
    ),
    (
        "dsa._normalize_",
        lambda: dsa.normalize(HIGH_S),
        lambda: dsa.serialize_der(dsa._normalize_(dsa.parse_der(HIGH_S))),
    ),
    (
        "dsa._is_low_s_",
        lambda: dsa.is_low_s(HIGH_S),
        lambda: dsa._is_low_s_(dsa.parse_der(HIGH_S)),
    ),
    (
        "recovery._sign_",
        lambda: recovery.sign(MSG, PRVKEY),
        lambda: recovery.serialize_compact(recovery._sign_(MSG, PRVKEY)),
    ),
    (
        "recovery._recover_",
        lambda: recovery.recover(MSG, RECOVERABLE, RECID),
        lambda: keys.serialize(
            recovery._recover_(MSG, recovery.parse_compact(RECOVERABLE, RECID))
        ),
    ),
    (
        "recovery._to_der_",
        lambda: recovery.to_der(RECOVERABLE, RECID),
        lambda: recovery._to_der_(recovery.parse_compact(RECOVERABLE, RECID)),
    ),
    (
        "ellswift._decode_",
        lambda: ellswift.decode(ELL),
        lambda: keys.serialize(ellswift._decode_(ELL)),
    ),
    (
        "silentpayments._label_",
        lambda: silentpayments.label(SCAN_PRVKEY, 0),
        label_through_the_private_half,
    ),
    (
        "silentpayments._labeled_spend_pubkey_",
        lambda: silentpayments.labeled_spend_pubkey(PUBKEY, LABEL),
        lambda: keys.serialize(
            silentpayments._labeled_spend_pubkey_(
                keys.parse(PUBKEY), silentpayments.parse_label(LABEL)
            )
        ),
    ),
    (
        "silentpayments._create_outputs_",
        lambda: SP_OUTPUTS,
        lambda: [
            xonly.serialize(output)
            for output in silentpayments._create_outputs_(
                [(keys.parse(SP_SCAN_PUBKEY), keys.parse(SP_SPEND_PUBKEY))],
                SP_OUTPOINT,
                prvkeys=[SP_INPUT_PRVKEY],
            )
        ],
    ),
    (
        "silentpayments._prevouts_summary_",
        lambda: SP_SUMMARY,
        lambda: bytes(
            ffi.buffer(
                silentpayments._prevouts_summary_(
                    SP_OUTPOINT, pubkeys=[keys.parse(SP_INPUT_PUBKEY)]
                )
            )
        ),
    ),
    (
        "silentpayments._scan_outputs_",
        lambda: silentpayments.scan_outputs(
            SP_OUTPUTS, SCAN_PRVKEY, SP_SUMMARY, SP_SPEND_PUBKEY
        ),
        scan_through_the_private_half,
    ),
]


@pytest.mark.parametrize("pubkey_bytes", [PUBKEY, PUBKEY_LONG], ids=["33", "65"])
@pytest.mark.parametrize("name,public,private", PAIRS, ids=[pair[0] for pair in PAIRS])
def test_the_private_half_is_the_public_one_without_the_parse(
    name: str,
    public: Callable[[bytes], Any],
    private: Callable[[Any], Any],
    pubkey_bytes: bytes,
) -> None:
    """`public(key_bytes)` is `private(parse(key_bytes))`, in both forms.

    Both serializations, because the parse is what tells them apart: the
    compressed one costs a field square root the uncompressed one does
    not, which is the whole reason for the pair, and the parsed key it
    ends at is the same point either way.

    Args:
        name: the private half, for the test id.
        public: the public half, as a call of the serialized key.
        private: the private half, as a call of the parsed key.
        pubkey_bytes: the key, compressed or not.
    """
    assert public(pubkey_bytes) == private(keys.parse(pubkey_bytes))


@pytest.mark.parametrize(
    "name,public,private", EQUALITIES, ids=[pair[0] for pair in EQUALITIES]
)
def test_the_private_half_answers_what_the_public_one_answers(
    name: str, public: Callable[[], Any], private: Callable[[], Any]
) -> None:
    """`public(...)` is the private half with the serialization around it.

    The same equality read the other way round: where the halves above
    take a key, these produce one, or take an object that is not a key at
    all -- a signature, a label, the summary of a transaction's inputs.
    What the public half adds is the parse in front, the serialize
    behind, or both; a caller that hands the object straight to another
    wrapper never pays for either.

    Args:
        name: the private half, for the test id.
        public: the public half, as a call of its own arguments.
        private: the private half, with what serializes its answer.
    """
    assert public() == private()


def test_the_schnorr_pair_parses_the_x_only_key() -> None:
    """`ssa.verify` is `ssa._verify_` behind `xonly.parse`.

    The one pair whose parsed key is not `keys.parse`'s: BIP340 verifies
    against the x coordinate, so what a caller holds is what
    `xonly.parse` returns, and proving those octets the x of a point is
    the call the verification would make again.
    """
    assert ssa.verify(MSG, XONLY, SSA_SIG)
    assert ssa._verify_(MSG, xonly.parse(XONLY), SSA_SIG)
    # and a signature that does not verify is False through both, rather
    # than an equality that holds because everything is True
    tampered = bytes([SSA_SIG[0] ^ 1]) + SSA_SIG[1:]
    assert not ssa.verify(MSG, XONLY, tampered)
    assert not ssa._verify_(MSG, xonly.parse(XONLY), tampered)


def test_the_taproot_pair_starts_from_the_point_the_x_belongs_to() -> None:
    """`xonly._tweak_add_` is `xonly.tweak_add` of the key's own x.

    The other pair whose parsed key is not the one its public half makes:
    `tweak_add` takes the x and lifts it, `_tweak_add_` takes the point
    that x belongs to, which is what a caller that validated a full
    public key is already holding.

    The odd-y key is the case worth writing down: BIP341's internal key
    is x-only, so the point is tweaked as its negation and answers the
    output key of the x it shares with it -- which is the same 32 bytes
    the even-y key gives, and the assertion below is that equality.
    """
    for pubkey_bytes in (PUBKEY, PUBKEY_LONG, keys.pubkey_negate(PUBKEY)):
        x_only, _ = xonly.from_pubkey(pubkey_bytes)
        assert x_only == XONLY
        assert xonly._tweak_add_(keys.parse(pubkey_bytes), TWEAK) == xonly.tweak_add(
            x_only, TWEAK
        )


def test_every_serialization_of_a_key_is_the_same_x_only_key() -> None:
    """32, 33 and 65 octets are one BIP340 key, and answer alike.

    The parity is a property of the serialization and not of the key:
    `lift_x` is the even-y point whatever form the x arrived in, and a
    signer whose point has odd y signs with n - d for that reason. So the
    negated key is not another key, and every entry point that takes one
    has to answer for all four spellings the same way.
    """
    negated = keys.pubkey_negate(PUBKEY)
    forms = (XONLY, PUBKEY, PUBKEY_LONG, negated, keys.pubkey_negate(PUBKEY, False))
    for pubkey_bytes in forms:
        assert xonly.from_pubkey(pubkey_bytes)[0] == XONLY
        assert xonly.tweak_add(pubkey_bytes, TWEAK) == xonly.tweak_add(XONLY, TWEAK)
        assert ssa.verify(MSG, pubkey_bytes, SSA_SIG)
        assert xonly.tweak_add_check(TWEAKED, TWEAKED_PARITY, pubkey_bytes, TWEAK)

    # and the parity is answered for what it is: which form was handed in
    assert xonly.from_pubkey(XONLY)[1] == 0
    assert xonly.from_pubkey(PUBKEY)[1] == 0
    assert xonly.from_pubkey(negated)[1] == 1


def test_reserialize_is_the_two_calls_it_replaces() -> None:
    """`keys.reserialize` is `serialize(parse(key))`, both forms both ways.

    And the refusal is `parse`'s, which is what makes it a validation: a
    caller proving a key at its own boundary has this and nothing to do
    with a parsed object.
    """
    for pubkey_bytes in (PUBKEY, PUBKEY_LONG):
        for compressed in (True, False):
            assert keys.reserialize(pubkey_bytes, compressed) == keys.serialize(
                keys.parse(pubkey_bytes), compressed
            )
    # the round trip in both directions, which is the conversion nothing
    # else here offers
    assert keys.reserialize(PUBKEY, compressed=False) == PUBKEY_LONG
    assert keys.reserialize(PUBKEY_LONG) == PUBKEY

    with pytest.raises(ValueError, match="invalid public key"):
        keys.reserialize(b"\x02" + bytes(32))


def test_a_chain_hands_out_the_point_it_holds() -> None:
    """`PubkeyTweakChain.pubkey` is the key without a tweak added.

    What `Signer.pubkey` is to a signer: the object is already there, so
    the answer is a serialization rather than a walk of the path again.
    Before the first tweak it is the key the chain was built from, which
    makes it that key's `reserialize`; `_pubkey_` is the same answer for
    a caller handing the point to a private half.
    """
    chain = keys.PubkeyTweakChain(PUBKEY)
    assert chain.pubkey() == PUBKEY
    assert chain.pubkey(compressed=False) == PUBKEY_LONG

    step = chain.tweak_add(TWEAK)
    assert chain.pubkey() == step
    assert keys.serialize(chain._pubkey_()) == step
    # and it is the point itself, not a copy of its bytes: the next tweak
    # is added to what the accessor answered
    assert xonly._from_pubkey_(chain._pubkey_()) == xonly.from_pubkey(step)


def test_a_parsed_key_verifies_more_than_once() -> None:
    """The motivating case: one parse, several signatures.

    Verification does not consume or change the key it is given -- the
    C call takes it const -- so a caller checking a batch of signatures
    against one key pays for the parse once. Checked by verifying three
    signatures of three messages through the same parsed key, and then
    asserting the key still serializes to the bytes it was parsed from.
    """
    pubkey = keys.parse(PUBKEY)
    for index in range(3):
        msg = hashlib.sha256(index.to_bytes(4, "big")).digest()
        assert dsa._verify_(msg, pubkey, dsa.parse_der(dsa.sign(msg, PRVKEY)))
        assert not dsa._verify_(msg, pubkey, dsa.parse_der(DER))
    assert keys.serialize(pubkey) == PUBKEY


def test_a_parsed_signature_is_asked_and_verified_without_a_second_parse() -> None:
    """The same motivating case for a signature: one parse, two questions.

    `is_low_s` and `verify` each parse the DER they are given, so a
    caller enforcing the lower-s rule and then verifying parses twice
    where the private halves take the object once.
    """
    signature = dsa.parse_der(DER)
    assert dsa._is_low_s_(signature)
    assert dsa._verify_(MSG, keys.parse(PUBKEY), signature)
    # and the two serializations are one object read twice, rather than
    # a conversion through the other
    assert dsa.serialize_der(signature) == DER
    assert dsa.serialize_compact(signature) == dsa.to_compact(DER)
    assert dsa.serialize_der(dsa.parse_compact(dsa.to_compact(DER))) == DER


def test_a_private_half_still_checks_everything_but_the_object() -> None:
    """What the underscores drop is the parse, and nothing else.

    Each remaining argument is refused exactly as the public half refuses
    it: a message hash that is not 32 octets, a signature that is not 64,
    a private key that is not a scalar, a tweak that is not 32 octets. A
    bare pointer's length is what no C return code can report, so a
    private half that skipped these would be reading past the end of a
    short value.
    """
    pubkey = keys.parse(PUBKEY)

    with pytest.raises(ValueError, match="message hash"):
        dsa._verify_(MSG[1:], pubkey, dsa.parse_der(DER))
    with pytest.raises(ValueError, match="DER"):
        dsa.parse_der(b"\x00" * 10)
    with pytest.raises(ValueError, match="signature must be 64 bytes"):
        ssa._verify_(MSG, xonly.parse(XONLY), SSA_SIG[1:])
    with pytest.raises(ValueError, match="private key"):
        ecdh._shared_secret_(pubkey, 0)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        keys._pubkey_tweak_add_(pubkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        keys._pubkey_tweak_mul_(pubkey, b"\x01" * 33)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        xonly._tweak_add_(pubkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="message hash"):
        recovery._recover_(MSG[1:], recovery.parse_compact(RECOVERABLE, RECID))

    # and the two verdicts libsecp256k1 gives on a tweak, through the
    # private halves: the sum that is the point at infinity, and the zero
    # multiplier
    with pytest.raises(ValueError, match="tweak or resulting public key"):
        keys._pubkey_tweak_add_(keys.parse(mult.mult_bytes(7)), N - 7)
    with pytest.raises(ValueError, match="invalid tweak"):
        keys._pubkey_tweak_mul_(pubkey, 0)


def test_every_private_half_is_paired() -> None:
    """Every `_foo_` of the boundary is in one of the tables above.

    The convention is a claim about every function spelled that way, so
    the tables are checked against what the modules carry rather than
    trusted to have been kept up to date.

    `ssa._verify_` and `xonly._tweak_add_` are paired in tests of their
    own rather than in a table: the parsed key of the first is
    `xonly.parse`'s and not `keys.parse`'s, and the second takes the
    point whose x its public half is given, so neither equality is the
    one parametrized above.
    """
    modules = {
        "dsa": dsa,
        "ecdh": ecdh,
        "ellswift": ellswift,
        "keys": keys,
        "mult": mult,
        "recovery": recovery,
        "silentpayments": silentpayments,
        "ssa": ssa,
        "xonly": xonly,
    }
    paired = (
        {name for name, *_ in PAIRS}
        | {name for name, *_ in EQUALITIES}
        | {"ssa._verify_", "xonly._tweak_add_"}
    )
    private_halves = {
        f"{module_name}.{name}"
        for module_name, module in modules.items()
        for name in dir(module)
        if name.startswith("_")
        and name.endswith("_")
        and not name.startswith("__")
        and callable(getattr(module, name))
        and getattr(getattr(module, name), "__module__", "")
        == f"btclib_secp256k1.{module_name}"
    }

    assert private_halves - paired == set()
    # and the tables name nothing the modules do not have
    assert paired - private_halves == set()

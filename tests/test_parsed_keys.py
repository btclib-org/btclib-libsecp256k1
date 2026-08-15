# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every inner half answers what its outer half answers.

A trailing underscore means one thing across these bindings, and
`keys.parse` states it: the wrapper takes the parsed public key in place
of the bytes, and the outer half is that same call with a `parse` in
front of it. That is an equality, so it is written as one here, pair by
pair and over both serializations of the key -- which is what keeps the
two halves from drifting into two implementations of the same thing.

`test_every_inner_half_is_paired` holds the table to the modules' own
contents, so an inner half added and not paired here is visible as an
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

PUBKEY_LONG = mult.mult_(PRVKEY)
PUBKEY = keys.pubkey_from_prvkey(PRVKEY)
OTHER = keys.pubkey_from_prvkey(3)
XONLY, PARITY = xonly.from_pubkey(PUBKEY)
DER = dsa.sign(MSG, PRVKEY)
SSA_SIG = ssa.sign(MSG, PRVKEY, bytes(32))
RECOVERABLE, RECID = recovery.sign(MSG, PRVKEY)
ELL = ellswift.create(PRVKEY, RND32)
LABEL, LABEL_TWEAK = silentpayments.label(SCAN_PRVKEY, 0)


def label_through_the_inner_half() -> tuple[bytes, bytes]:
    """Create a label through `label_`, and serialize what it answered.

    Returns:
        The 33-byte label and its 32-byte tweak, which is the pair
        `silentpayments.label` answers with.
    """
    label_obj, tweak = silentpayments.label_(SCAN_PRVKEY, 0)
    return silentpayments.serialize_label(label_obj), tweak


# every pair of the convention: the name of the outer half, that half as
# a call of the serialized key alone, and the inner half as a call of the
# parsed one. The arguments that are not the key are closed over, being
# the same on both sides by construction. Two of the inner halves answer
# with the key they mutated, and a cffi object is equal to no other, so
# those are compared through `keys.serialize` -- which is what their
# outer halves do with the same object
PAIRS: list[tuple[str, Callable[[bytes], Any], Callable[[Any], Any]]] = [
    (
        "keys.pubkey_negate",
        keys.pubkey_negate,
        lambda pubkey: keys.serialize(keys.pubkey_negate_(pubkey)),
    ),
    (
        "keys.pubkey_tweak_add",
        lambda pubkey_bytes: keys.pubkey_tweak_add(pubkey_bytes, TWEAK),
        lambda pubkey: keys.serialize(keys.pubkey_tweak_add_(pubkey, TWEAK)),
    ),
    (
        "keys.pubkey_tweak_mul",
        lambda pubkey_bytes: keys.pubkey_tweak_mul(pubkey_bytes, TWEAK),
        lambda pubkey: keys.serialize(keys.pubkey_tweak_mul_(pubkey, TWEAK)),
    ),
    (
        "keys.pubkey_cmp",
        lambda pubkey_bytes: keys.pubkey_cmp(pubkey_bytes, OTHER),
        lambda pubkey: keys.pubkey_cmp_(pubkey, keys.parse(OTHER)),
    ),
    ("xonly.from_pubkey", xonly.from_pubkey, xonly.from_pubkey_),
    (
        "ecdh.shared_secret",
        lambda pubkey_bytes: ecdh.shared_secret(pubkey_bytes, PRVKEY),
        lambda pubkey: ecdh.shared_secret_(pubkey, PRVKEY),
    ),
    (
        "dsa.verify",
        lambda pubkey_bytes: dsa.verify(MSG, pubkey_bytes, DER),
        lambda pubkey: dsa.verify_(MSG, pubkey, DER),
    ),
    (
        "ellswift.encode",
        lambda pubkey_bytes: ellswift.encode(pubkey_bytes, RND32),
        lambda pubkey: ellswift.encode_(pubkey, RND32),
    ),
]

# and the halves on the other side of the boundary: the ones that answer
# with the key instead of with its bytes, whose outer half is the same
# call with a `serialize` behind it rather than a `parse` in front. Each
# is written as the pair of calls it is, the key being what they produce
# rather than what they take -- so there are no two serializations of an
# argument to drive them with, and the equality is over the answer alone
PRODUCERS: list[tuple[str, Callable[[], Any], Callable[[], Any]]] = [
    (
        "keys.pubkey_from_prvkey",
        lambda: keys.pubkey_from_prvkey(PRVKEY),
        lambda: keys.serialize(keys.pubkey_from_prvkey_(PRVKEY)),
    ),
    (
        "keys.pubkey_combine",
        lambda: keys.pubkey_combine([PUBKEY, OTHER]),
        lambda: keys.serialize(
            keys.pubkey_combine_([keys.parse(PUBKEY), keys.parse(OTHER)])
        ),
    ),
    (
        "keys.pubkey_sort",
        lambda: keys.pubkey_sort([PUBKEY, OTHER]),
        lambda: [
            keys.serialize(pubkey)
            for pubkey in keys.pubkey_sort_([keys.parse(PUBKEY), keys.parse(OTHER)])
        ],
    ),
    (
        "recovery.recover",
        lambda: recovery.recover(MSG, RECOVERABLE, RECID),
        lambda: keys.serialize(recovery.recover_(MSG, RECOVERABLE, RECID)),
    ),
    (
        "ellswift.decode",
        lambda: ellswift.decode(ELL),
        lambda: keys.serialize(ellswift.decode_(ELL)),
    ),
    (
        "silentpayments.label",
        lambda: silentpayments.label(SCAN_PRVKEY, 0),
        label_through_the_inner_half,
    ),
    (
        "silentpayments.labeled_spend_pubkey",
        lambda: silentpayments.labeled_spend_pubkey(PUBKEY, LABEL),
        lambda: keys.serialize(
            silentpayments.labeled_spend_pubkey_(
                keys.parse(PUBKEY), silentpayments.parse_label(LABEL)
            )
        ),
    ),
]


@pytest.mark.parametrize("pubkey_bytes", [PUBKEY, PUBKEY_LONG], ids=["33", "65"])
@pytest.mark.parametrize("name,outer,inner", PAIRS, ids=[pair[0] for pair in PAIRS])
def test_the_inner_half_is_the_outer_one_without_the_parse(
    name: str,
    outer: Callable[[bytes], Any],
    inner: Callable[[Any], Any],
    pubkey_bytes: bytes,
) -> None:
    """`outer(key_bytes)` is `inner(parse(key_bytes))`, in both forms.

    Both serializations, because the parse is what tells them apart: the
    compressed one costs a field square root the uncompressed one does
    not, which is the whole reason for the pair, and the parsed key it
    ends at is the same point either way.

    Args:
        name: the outer half, for the test id.
        outer: it, as a call of the serialized key.
        inner: the inner half, as a call of the parsed key.
        pubkey_bytes: the key, compressed or not.
    """
    assert outer(pubkey_bytes) == inner(keys.parse(pubkey_bytes))


@pytest.mark.parametrize(
    "name,outer,inner", PRODUCERS, ids=[producer[0] for producer in PRODUCERS]
)
def test_the_producing_half_is_the_outer_one_without_the_serialize(
    name: str, outer: Callable[[], Any], inner: Callable[[], Any]
) -> None:
    """`outer(...)` is `serialize(inner(...))`, key for key.

    The same equality read the other way round: where the halves above
    take the key, these produce it, so what the outer half adds is the
    serialization behind the call rather than the parse in front of it.
    A caller who hands the key straight to another wrapper -- which is
    what these are for -- never pays for either.

    Args:
        name: the outer half, for the test id.
        outer: it, as a call of its own arguments.
        inner: the inner half, with what serializes its answer.
    """
    assert outer() == inner()


def test_the_schnorr_pair_parses_the_x_only_key() -> None:
    """`ssa.verify` is `ssa.verify_` behind `xonly.parse`.

    The one pair whose parsed key is not `keys.parse`'s: BIP340 verifies
    against the 32-byte x-only key, so what a caller holds is what
    `xonly.parse` returns, and proving those 32 bytes to be the x
    coordinate of a point is the call the verification would make again.
    """
    assert ssa.verify(MSG, XONLY, SSA_SIG)
    assert ssa.verify_(MSG, xonly.parse(XONLY), SSA_SIG)
    # and a signature that does not verify is False through both, rather
    # than an equality that holds because everything is True
    tampered = bytes([SSA_SIG[0] ^ 1]) + SSA_SIG[1:]
    assert not ssa.verify(MSG, XONLY, tampered)
    assert not ssa.verify_(MSG, xonly.parse(XONLY), tampered)


def test_the_taproot_pair_starts_from_the_point_the_x_belongs_to() -> None:
    """`xonly.tweak_add_` is `xonly.tweak_add` of the key's own x.

    The other pair whose parsed key is not the one its outer half makes:
    `tweak_add` takes 32 bytes and lifts them, `tweak_add_` takes the
    point those bytes are the x of, which is what a caller that validated
    a full public key is already holding.

    The odd-y key is the case worth writing down: BIP341's internal key
    is x-only, so the point is tweaked as its negation and answers the
    output key of the x it shares with it -- which is the same 32 bytes
    the even-y key gives, and the assertion below is that equality.
    """
    for pubkey_bytes in (PUBKEY, PUBKEY_LONG, keys.pubkey_negate(PUBKEY)):
        x_only, _ = xonly.from_pubkey(pubkey_bytes)
        assert x_only == XONLY
        assert xonly.tweak_add_(keys.parse(pubkey_bytes), TWEAK) == xonly.tweak_add(
            x_only, TWEAK
        )


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
        assert dsa.verify_(msg, pubkey, dsa.sign(msg, PRVKEY))
        assert not dsa.verify_(msg, pubkey, DER)
    assert keys.serialize(pubkey) == PUBKEY


def test_an_inner_half_still_checks_everything_but_the_key() -> None:
    """What the underscore drops is the parse, and nothing else.

    Each remaining argument is refused exactly as the outer half refuses
    it: a message hash that is not 32 octets, a DER signature that is
    malformed, a signature that is not 64, a private key that is not a
    scalar, a tweak that is not 32 octets. A bare pointer's length is
    what no C return code can report, so an inner half that skipped these
    would be reading past the end of a short value.
    """
    pubkey = keys.parse(PUBKEY)

    with pytest.raises(ValueError, match="message hash"):
        dsa.verify_(MSG[1:], pubkey, DER)
    with pytest.raises(ValueError, match="DER"):
        dsa.verify_(MSG, pubkey, b"\x00" * 10)
    with pytest.raises(ValueError, match="signature must be 64 bytes"):
        ssa.verify_(MSG, xonly.parse(XONLY), SSA_SIG[1:])
    with pytest.raises(ValueError, match="private key"):
        ecdh.shared_secret_(pubkey, 0)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        keys.pubkey_tweak_add_(pubkey, b"\x01" * 31)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        keys.pubkey_tweak_mul_(pubkey, b"\x01" * 33)
    with pytest.raises(ValueError, match="tweak must be 32 bytes"):
        xonly.tweak_add_(pubkey, b"\x01" * 31)

    # and the two verdicts libsecp256k1 gives on a tweak, through the
    # inner halves: the sum that is the point at infinity, and the zero
    # multiplier
    with pytest.raises(ValueError, match="tweak or resulting public key"):
        keys.pubkey_tweak_add_(keys.parse(mult.mult_(7)), N - 7)
    with pytest.raises(ValueError, match="invalid tweak"):
        keys.pubkey_tweak_mul_(pubkey, 0)


def test_every_inner_half_is_paired() -> None:
    """Every trailing underscore of the boundary is in the table above.

    The convention is a claim about every function spelled that way, so
    the table is checked against what the modules export rather than
    trusted to have been kept up to date. `mult.mult_` is the one
    exception and is named as one: its underscore is older and means the
    other thing, the serialized point against the pair of coordinates
    `mult` answers with, and there is no key to hand it already parsed.

    `ssa.verify_` and `xonly.tweak_add_` are paired in tests of their own
    rather than in the table: the parsed key of the first is
    `xonly.parse`'s and not `keys.parse`'s, and the second takes the point
    whose x its outer half is given, so neither equality is the one
    parametrized above.
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
        {f"{name}_" for name, *_ in PAIRS}
        | {f"{name}_" for name, *_ in PRODUCERS}
        | {"ssa.verify_", "xonly.tweak_add_"}
    )
    inner_halves = {
        f"{module_name}.{name}"
        for module_name, module in modules.items()
        for name in dir(module)
        if name.endswith("_")
        and not name.startswith("_")
        and callable(getattr(module, name))
        and getattr(getattr(module, name), "__module__", "")
        == f"btclib_secp256k1.{module_name}"
    }

    assert inner_halves - paired == {"mult.mult_"}
    # and the table names nothing the modules do not have
    assert paired - inner_halves == set()

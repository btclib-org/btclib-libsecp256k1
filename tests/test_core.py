# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Core tests: signing round-trips, input validation, and safe aborts.

The safe-abort test drives libsecp256k1 with deliberately illegal
arguments: it passes only because the vendored default callbacks are
replaced by do-nothing stubs, instead of the abort()ing upstream ones
that would take the hosting Python process down with them.
"""

import array
import hashlib
import secrets

import pytest

from btclib_secp256k1 import (
    _scalar,
    context,
    dsa,
    ellswift,
    ffi,
    hashes,
    keys,
    lib,
    recovery,
    silentpayments,
    ssa,
    xonly,
)

prvkey = 1
# the field order of secp256k1, for the curve equation below
P = 2**256 - 2**32 - 977
pubkey_bytes = b"\x02y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98"
# the x-only form BIP340 verifies against; the key has even y, so it is
# the same point the compressed form above encodes
xonly_bytes = pubkey_bytes[1:]


def test_sign_and_verify() -> None:
    """Round-trip ECDSA and BIP340, and check what each call refuses.

    A private key is interchangeable as an int and as 32 octets. A nonce
    contribution changes the deterministic ECDSA signature and the result
    still verifies; being entropy it is 32 octets or nothing, so a shorter
    value is refused rather than padded. BIP340 verification takes the
    x-only key and only it, a full public key being the caller's to
    convert through `xonly`.
    """
    msg = b"\xa0\xdce\xff\xcay\x98s\xcb\xea\n\xc2t\x01[\x95&P]\xaa\xae\xd3\x85\x15T%\xf73w\x04\x88>"

    dsa_sig = dsa.sign(msg, prvkey)
    assert dsa.verify(msg, pubkey_bytes, dsa_sig)
    assert dsa_sig == dsa.sign(msg, prvkey.to_bytes(32, "big"))

    # a nonce contribution changes the deterministic signature, which
    # still verifies; being entropy, it is 32 bytes or nothing, and a
    # shorter value is rejected instead of being padded into one
    custom_sig = dsa.sign(msg, prvkey, b"\x01" * 32)
    assert custom_sig != dsa_sig
    assert dsa.verify(msg, pubkey_bytes, custom_sig)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        dsa.sign(msg, prvkey, b"\x01")

    ssa_sig = ssa.sign(msg, prvkey)
    # BIP340 verifies against an x coordinate, so every serialization of
    # the point names the same key -- the public key of this scalar has
    # odd y, and verifies as itself
    assert ssa.verify(msg, xonly_bytes, ssa_sig)
    assert ssa.verify(msg, pubkey_bytes, ssa_sig)
    assert ssa.verify(msg, keys.reserialize(pubkey_bytes), ssa_sig)


def test_ssa_sign_custom() -> None:
    """Sign a BIP340 message of any length, which only sign_custom takes.

    For 32 octets the two entry points agree byte for byte, `sign` being
    `sign_custom` with the default nonce function and nothing else set.
    Past that: a longer message verifies, the same signature does not
    verify against that message truncated, the empty message is a length
    like any other, and `sign` refuses what is not 32 octets. The three
    refusals are a zero private key and an aux_rand32 one octet too long
    and one too short.
    """
    msg = b"\x02" * 32
    aux_rand32 = b"\x11" * 32

    # for a 32-byte message the two are the same signature: sign is
    # sign_custom with the default nonce function and nothing else set
    assert ssa.sign_custom(msg, prvkey, aux_rand32) == ssa.sign(msg, prvkey, aux_rand32)

    # a message of any other length is what only sign_custom accepts,
    # BIP340 not being restricted to 32 bytes
    long_msg = b"Satoshi Nakamoto" * 7
    long_sig = ssa.sign_custom(long_msg, prvkey, aux_rand32)
    assert ssa.verify(long_msg, xonly_bytes, long_sig)
    # the same signature does not verify against a truncated message
    assert not ssa.verify(long_msg[:-1], xonly_bytes, long_sig)
    with pytest.raises(ValueError, match="message hash"):
        ssa.sign(long_msg, prvkey)

    # the empty message is a length like any other
    assert ssa.verify(b"", xonly_bytes, ssa.sign_custom(b"", prvkey))

    with pytest.raises(ValueError, match="private key"):
        ssa.sign_custom(long_msg, 0)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ssa.sign_custom(long_msg, prvkey, b"\x01" * 33)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ssa.sign_custom(long_msg, prvkey, b"\x01" * 31)


def test_safe_abort() -> None:
    """An illegal argument does not take the interpreter down with it.

    `secp256k1_ecdsa_sign` is called with NULL where a signature and a
    key go. Upstream's default callbacks `abort()`, which would end the
    hosting process; this returns because the vendored build replaces
    them with do-nothing stubs, compiled as a unit of their own rather
    than by editing the submodule. That the test returns at all is the
    assertion.

    A context of its own, because the shared one has the recording
    callbacks of `context` set on it and this is about the defaults --
    and destroyed after, a context being an allocation that nothing else
    frees. `1` is SECP256K1_CONTEXT_NONE, the flags naming SIGN and
    VERIFY having been deprecated since libsecp256k1 0.2.
    """
    default_callbacks_ctx = lib.secp256k1_context_create(1)
    lib.secp256k1_ecdsa_sign(
        default_callbacks_ctx,
        ffi.new("secp256k1_ecdsa_signature *"),
        b"0" * 32,
        ffi.NULL,
        ffi.NULL,
        b"0" * 32,
    )
    lib.secp256k1_context_destroy(default_callbacks_ctx)


def test_mult() -> None:
    """Generator multiplication answers the point the compressed key names.

    `pubkey_from_prvkey(compressed=False)` is the serialization that
    carries both coordinates, so its x is the x of the compressed form and
    the pair a caller wants is `int.from_bytes` of its two halves.
    """
    pubkey_ = keys.pubkey_from_prvkey(prvkey, compressed=False)
    assert pubkey_[0] == 4
    assert pubkey_[1:33] == pubkey_bytes[1:]
    # the y, which the compressed form does not carry and which nothing
    # here asserted while a call was answering it as an int: it is the
    # even one, `pubkey_bytes` opening with 0x02, and it satisfies the
    # curve equation. That is what a caller reads with int.from_bytes
    x = int.from_bytes(pubkey_[1:33], "big")
    y = int.from_bytes(pubkey_[33:], "big")
    assert y % 2 == 0
    assert (y * y - x * x * x - 7) % P == 0


def test_invalid_inputs() -> None:
    """Every argument out of the domain is refused at the boundary.

    A zero private key, a message hash that is not 32 octets, an
    aux_rand32 that is not, a signature that is not DER, and a public key
    that does not parse -- each raising ValueError with the message
    naming the argument, which is what a caller catches rather than
    finding out from libsecp256k1's return code.
    """
    msg = b"\x01" * 32

    dsa_sig = dsa.sign(msg, prvkey)
    with pytest.raises(ValueError, match="private key"):
        dsa.sign(msg, 0)
    with pytest.raises(ValueError, match="32 bytes"):
        dsa.sign(msg[1:], prvkey)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        dsa.sign(msg, prvkey, b"\x01" * 33)
    with pytest.raises(ValueError, match="message hash"):
        dsa.verify(msg[1:], pubkey_bytes, dsa_sig)
    with pytest.raises(ValueError, match="DER"):
        dsa.verify(msg, pubkey_bytes, b"\x00" * 10)
    with pytest.raises(ValueError, match="public key"):
        dsa.verify(msg, b"\x02" + b"\x00" * 32, dsa_sig)

    ssa_sig = ssa.sign(msg, prvkey)
    with pytest.raises(ValueError, match="private key"):
        ssa.sign(msg, 0)
    with pytest.raises(ValueError, match="message hash"):
        ssa.sign(msg[1:], prvkey)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ssa.sign(msg, prvkey, b"\x01" * 33)
    with pytest.raises(ValueError, match="64 bytes"):
        ssa.verify(msg, xonly_bytes, ssa_sig[1:])
    with pytest.raises(ValueError, match="invalid public key"):
        # 32 bytes which are not the x coordinate of a curve point
        ssa.verify(msg, b"\x00" * 32, ssa_sig)

    # a tampered signature does not raise: it just does not verify
    tampered = bytes([ssa_sig[0] ^ 1]) + ssa_sig[1:]
    assert not ssa.verify(msg, xonly_bytes, tampered)

    # an int scalar out of the 32-byte range is an invalid argument like
    # any other, on both sides of the range: it must not surface as the
    # OverflowError of int.to_bytes
    with pytest.raises(ValueError, match="fit in 32 bytes"):
        dsa.sign(msg, 2**256)
    with pytest.raises(ValueError, match="fit in 32 bytes"):
        keys.pubkey_from_prvkey(-1, compressed=False)

    # generator multiplication is keys.pubkey_from_prvkey, so what its
    # message names is the private key the scalar of it is
    with pytest.raises(ValueError, match="private key"):
        keys.pubkey_from_prvkey(0, compressed=False)


def test_type_checks_refuse_what_merely_has_a_length() -> None:
    """A size check alone is not a check: `len` answers for more than bytes.

    What the boundary takes is bytes, a bytearray and a memoryview --
    `tests/test_bytes_like.py` drives every entry point with each of the
    three. What it refuses is everything else, and it refuses it by
    name: a `str` has a length and is not octets, a `float` has none and
    came back as `object of type 'float' has no len()` before there was
    a type check to meet.

    Every call below is annotated for what it is: an argument of a type
    the signature refuses, which is why each carries the `type: ignore`
    that says mypy already knew.
    """
    prvkey = 7
    pubkey_bytes = keys.pubkey_from_prvkey(prvkey, compressed=False)

    with pytest.raises(TypeError, match="tag must be bytes, not str"):
        hashes.tagged_sha256("TapLeaf", b"")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="message hash must be bytes, not str"):
        dsa.sign("x" * 32, prvkey)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ElligatorSwift public key must be bytes"):
        ellswift.decode(None)  # type: ignore[arg-type]

    # the scalars take an int too, so their message says so
    with pytest.raises(
        TypeError, match="private key must be bytes or an int, not float"
    ):
        keys.pubkey_from_prvkey(1.0, compressed=False)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="tweak must be bytes or an int, not str"):
        keys.prvkey_tweak_add(prvkey, "x" * 32)  # type: ignore[call-overload]

    # a sequence of public keys handed one public key: bytes is itself a
    # sequence, so what reaches parse is an int, and saying so is the
    # whole of the diagnosis
    with pytest.raises(TypeError, match="public key must be bytes, not int"):
        keys.pubkey_sort(pubkey_bytes)  # type: ignore[arg-type]


def test_a_bool_is_not_a_scalar() -> None:
    """A bool is refused where a scalar goes, python making it an int.

    This is the one type whose acceptance could not be seen in the
    answer. `keys.prvkey_verify(False)` returned False, which is the
    correct verdict on the scalar zero and indistinguishable from the
    correct verdict on whatever the caller meant; the public key of
    `True` returned the generator. A `float` or a `str` in the same place is a
    typo that raises, and always did.

    Nor could the type checker say so: `bool` is a subtype of `int`, so
    these two calls are the only ones in this module that need no
    `type: ignore` -- mypy holds them to be correct. That is the whole
    argument for the check being made at run time.

    Refused for the scalars alone. `recid`, `party` and the y parity
    take a bool as the 0 or 1 it is, those being flags rather than
    values, and reading one as `True` guesses at nothing.
    """
    for value in (True, False):
        with pytest.raises(TypeError, match="private key must be bytes or an int"):
            keys.prvkey_verify(value)
        with pytest.raises(TypeError, match="tweak must be bytes or an int, not bool"):
            keys.prvkey_tweak_add(7, value)

    # the flags are unaffected: a bool there is the 0 or 1 it is, and
    # the recovery id of any signature is one of the two
    msg = b"\x01" * 32
    sig_bytes, recid = recovery.sign(msg, 7)
    assert recid in (0, 1)
    assert recovery.recover(msg, sig_bytes, bool(recid)) == keys.pubkey_from_prvkey(7)


def test_a_flag_that_is_not_an_int_is_refused_by_name() -> None:
    """What a flag refuses is what is not a number at all.

    A recovery id, a y parity, an ElligatorSwift party and a label index
    are each a small number libsecp256k1 takes as a C int, and each is
    held to one place -- so a `float` is refused by all four alike, and
    the message names the argument. `0.0` is the value that makes the
    check worth making: it passes an `in (0, 1)` test, python holding it
    equal to the int, and what it would reach cffi as is a float.
    """
    msg = b"\x01" * 32
    sig_bytes, _ = recovery.sign(msg, 7)
    xonly_bytes, parity = xonly.from_pubkey(keys.pubkey_from_prvkey(7))
    tweaked, tweaked_parity = xonly.tweak_add(xonly_bytes, 11)
    ell = ellswift.create(7, bytes(32))

    with pytest.raises(TypeError, match="recovery id must be an int, not float"):
        recovery.recover(msg, sig_bytes, 0.0)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="parity must be an int, not float"):
        xonly.tweak_add_check(tweaked, float(tweaked_parity), xonly_bytes, 11)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="party must be an int, not float"):
        ellswift.xdh(ell, ell, 7, 0.0)  # type: ignore[call-overload]
    with pytest.raises(TypeError, match="label m must be an int, not float"):
        silentpayments.label(7, 0.0)  # type: ignore[arg-type]

    # and the y parity of a key is unchanged by any of it
    assert parity in (0, 1)


def test_a_memoryview_of_wider_items_is_not_octets() -> None:
    """A memoryview states its width in items, and only octets are octets.

    The other type whose acceptance could not be seen in the answer, and
    the argument for taking a `bytearray` and a `memoryview` at all does
    not reach it: eight `uint32` state eight items, and the 32 octets
    `bytes` reads underneath them are whatever this machine's byte order
    made of the value -- a private key nobody wrote, of exactly the
    length the size check asks for, and a different one on a big endian
    build of the same program.

    Nor could the type checker say so, so neither call below needs a
    `type: ignore`: `memoryview` is the annotated type whatever its items
    are. That is the whole argument for the check being made at run time.

    What is refused is the reinterpretation and not the shape: a view of
    octets is the argument it always was, a stride included, `bytes` of
    one answering the octets it logically holds.
    """
    wider = memoryview(array.array("I", [1, 2, 3, 4, 5, 6, 7, 8]))
    assert wider.itemsize == 4
    assert len(bytes(wider)) == 32, "it would pass the size check"

    with pytest.raises(TypeError, match="private key must be a memoryview of bytes"):
        keys.prvkey_verify(wider)
    with pytest.raises(TypeError, match="message hash must be a memoryview of bytes"):
        dsa.sign(wider, 7)

    # the same octets, said to be octets, and a strided view of octets
    assert keys.prvkey_verify(wider.cast("B"))
    assert keys.prvkey_verify(memoryview(b"\x07\x00" * 32)[::2])


def test_size_checks_refuse_both_sides() -> None:
    """Every size check refuses a value too long as well as one too short.

    A check written `!= 32` has two edges, and a test at one of them leaves
    the other unasserted: the first mutation session found exactly that,
    every one of these surviving a `!=` turned into `<` or `>` while the
    line still ran and coverage still read 100%. So each is exercised at
    n-1 and at n+1 here, whichever side the tests elsewhere already had.

    The int scalar is the same shape one step further out: `0 <= num <
    2**256` mutated to `0 <= num != 2**256` accepts everything above the
    range, and `2**256` alone cannot say so -- both spellings refuse that
    one. It takes a value past it.
    """
    msg = b"\x01" * 32
    prvkey = 7
    pubkey_bytes = keys.pubkey_from_prvkey(prvkey, compressed=False)
    der_bytes = dsa.sign(msg, prvkey)
    ssa_sig = ssa.sign(msg, prvkey)
    xonly_bytes = pubkey_bytes[1:33]

    # one octet too many, where the tests above pass one too few
    with pytest.raises(ValueError, match="message hash"):
        dsa.sign(msg + b"\x01", prvkey)
    with pytest.raises(ValueError, match="message hash"):
        dsa.verify(msg + b"\x01", pubkey_bytes, der_bytes)
    with pytest.raises(ValueError, match="compact signature"):
        dsa.to_der(dsa.to_compact(der_bytes) + b"\x01")
    with pytest.raises(ValueError, match="signature"):
        ssa.verify(msg, xonly_bytes, ssa_sig + b"\x01")

    # and one too few, where they pass one too many: 31 octets are none
    # of the three serializations a public key has here
    with pytest.raises(ValueError, match="invalid public key"):
        ssa.verify(msg, xonly_bytes[:-1], ssa_sig)

    # past the top of the scalar range, which 2**256 cannot reach: both
    # the check and its mutant refuse that value
    with pytest.raises(ValueError, match="fit in 32 bytes"):
        dsa.sign(msg, 2**256 + 1)


def test_octets_size_check_compares_by_value() -> None:
    """`_scalar.octets`'s size check is `!=`, not `is not`.

    No wrapper here ever asks for a size past 256, which is exactly why a
    mutant turning that `!=` into `is not` survived a mutation session:
    every size this package checks -- 32, 33, 65 -- sits inside CPython's
    cached range for small ints, where two equal ones are the same object
    and the two operators cannot be told apart. 300 does not, and `size`
    stays referenced for the whole call, so the object `len(value_bytes)`
    computes cannot be allocated at its address once it is freed --
    `!=` accepts it, `is not` would refuse it as a false mismatch.
    """
    value = bytes(300)
    assert _scalar.octets(value, "value", len(value)) == value


def test_der_reaches_all_72_octets() -> None:
    """The longest DER this curve can encode is 72, and both paths reach it.

    72 is structural: libsecp256k1 writes `6 + lenR + lenS`, and each of
    those is at most 33 -- 32 octets of scalar, plus the leading zero DER
    wants when the top bit is set. It is also what the output buffers of
    `_serialize_der` and `recovery.to_der` are sized to, and nothing was
    holding them to it.

    The vendored vectors cannot: every signature libsecp256k1 *produces*
    is low-s, so s stays below 2**255, its top bit is clear, and no
    padding octet is added -- all 398 of them stop at 71. Only a
    signature this package is *given* can be high-s, which is what
    `to_der` documents itself as passing through, and it is the one way
    the last octet of those buffers is ever written.

    Held to the encoding rather than to itself: the expected bytes are
    spelled out as BIP66 describes them -- 0x30, the length of what
    follows, then each integer as 0x02, its length, the zero, the value.
    """
    # the top bit set, and below the group order, so DER pads it
    high = b"\x80" + bytes(31)
    integer = b"\x02\x21\x00" + high
    expected = b"\x30" + bytes([2 * len(integer)]) + integer + integer

    assert len(expected) == 72
    assert dsa.to_der(high + high) == expected
    # the same serialization, reached through the recoverable signature,
    # where a second buffer of its own is what would come up short
    for recid in (0, 1, 2, 3):
        assert recovery.to_der(high + high, recid) == expected

    # and what signing produces, for contrast: low-s, so one octet less
    assert len(dsa.sign(b"\x01" * 32, 7)) < 72


def test_generated_randomness_is_always_32_octets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every octet count this package asks `secrets` for is 32.

    Four calls generate randomness rather than accept it: the context
    seed, the BIP340 aux of a signature signed without one, and the two
    ElligatorSwift ones. No answer reveals how long any of them was -- a
    shorter aux is hashed into a different signature that verifies just
    as well, and a context seeded with half the entropy behaves exactly
    like one seeded with all of it -- which is why the mutation session
    leaves every one of those lengths alive.

    So this is the one thing that can hold them to it: what is asked of
    `secrets`, rather than what comes back. 32 is
    secp256k1_context_randomize's seed length and BIP340's aux_rand,
    both required rather than conventional.
    """
    requested: list[int] = []
    real_token_bytes = secrets.token_bytes

    def recording(size: int) -> bytes:
        requested.append(size)
        return real_token_bytes(size)

    monkeypatch.setattr(secrets, "token_bytes", recording)

    msg = b"\x02" * 32
    # re-blinding the shared context is what import time does once
    context._randomize(context.ctx)
    ssa.sign(msg, prvkey)
    ellswift.create(prvkey)
    ellswift.encode(pubkey_bytes)

    assert requested == [32, 32, 32, 32]


def test_a_signature_crosses_in_either_serialization() -> None:
    """`compact` decides the form, and the two forms are one signature.

    A signature is `r` and `s`; DER is what the wire carries, and a
    caller holding the two scalars has no reason to write a structure
    around them for a call that takes it straight apart again. So `sign`
    answers either form and `verify` takes either, and what says which is
    the flag rather than the length: a DER signature of 64 octets exists,
    and begins with an 0x30 a compact `r` may begin with too.
    """
    msg = hashlib.sha256(b"btclib_secp256k1").digest()
    prvkey = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    pubkey = keys.pubkey_from_prvkey(prvkey)

    der = dsa.sign(msg, prvkey)
    compact = dsa.sign(msg, prvkey, compact=True)
    assert len(compact) == 64
    assert compact == dsa.to_compact(der)
    assert der == dsa.to_der(compact)

    assert dsa.verify(msg, pubkey, der)
    assert dsa.verify(msg, pubkey, compact, compact=True)
    # the aux_rand32 argument keeps its place before the flag
    assert dsa.sign(msg, prvkey, bytes(32), compact=True) == dsa.to_compact(
        dsa.sign(msg, prvkey, bytes(32))
    )

    # each form is refused as the other: DER read as compact is the wrong
    # length, and 64 octets read as DER are no structure
    with pytest.raises(ValueError, match="compact signature"):
        dsa.verify(msg, pubkey, der, compact=True)
    with pytest.raises(ValueError, match="DER"):
        dsa.verify(msg, pubkey, compact)

    # and normalize is the flag it always was, on either form
    high_s = dsa.to_compact(der)
    s = int.from_bytes(high_s[32:], "big")
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    malleated = high_s[:32] + (order - s).to_bytes(32, "big")
    assert not dsa.verify(msg, pubkey, malleated, compact=True)
    assert dsa.verify(msg, pubkey, malleated, normalize=True, compact=True)

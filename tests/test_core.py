# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Core tests: signing round-trips, input validation, and safe aborts.

The safe-abort test drives libsecp256k1 with deliberately illegal
arguments: it passes only because the vendored default callbacks are
replaced by do-nothing stubs, instead of the abort()ing upstream ones
that would take the hosting Python process down with them.
"""

import pytest

from btclib_libsecp256k1 import dsa, ffi, lib, mult, ssa

prvkey = 1
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
    with pytest.raises(ValueError, match="ndata must be 32 bytes"):
        dsa.sign(msg, prvkey, b"\x01")

    ssa_sig = ssa.sign(msg, prvkey)
    # BIP340 verification takes the x-only public key, and only it: a
    # full public key is converted by the caller, through xonly
    assert ssa.verify(msg, xonly_bytes, ssa_sig)
    with pytest.raises(ValueError, match="x-only public key must be 32 bytes"):
        ssa.verify(msg, pubkey_bytes, ssa_sig)


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
    """
    lib.secp256k1_ecdsa_sign(
        lib.secp256k1_context_create(769),
        ffi.new("secp256k1_ecdsa_signature *"),
        b"0" * 32,
        ffi.NULL,
        ffi.NULL,
        b"0" * 32,
    )


def test_mult() -> None:
    """Both spellings of generator multiplication reach the same point.

    `mult_` answers the serialized public key and `mult` the coordinates,
    so the x of the second is the x the first carries.
    """
    pubkey_ = mult.mult_(prvkey)
    assert pubkey_[1:33] == pubkey_bytes[1:]
    pubkey = mult.mult(prvkey)
    assert pubkey[0] == int.from_bytes(pubkey_bytes[1:], "big")


def test_invalid_inputs() -> None:
    """Every argument out of the domain is refused at the boundary.

    A zero private key, a message hash that is not 32 octets, an
    ndata that is not, a signature that is not DER, and a public key
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
    with pytest.raises(ValueError, match="ndata must be 32 bytes"):
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
    with pytest.raises(ValueError, match="invalid x-only public key"):
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
        mult.mult(-1)

    with pytest.raises(ValueError, match="scalar"):
        mult.mult(0)


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
    pubkey_bytes = mult.mult_(prvkey)
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

    # and one too few, where they pass one too many
    with pytest.raises(ValueError, match="x-only public key"):
        ssa.verify(msg, xonly_bytes[:-1], ssa_sig)

    # past the top of the scalar range, which 2**256 cannot reach: both
    # the check and its mutant refuse that value
    with pytest.raises(ValueError, match="fit in 32 bytes"):
        dsa.sign(msg, 2**256 + 1)

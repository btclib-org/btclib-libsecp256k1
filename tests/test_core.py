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
    lib.secp256k1_ecdsa_sign(
        lib.secp256k1_context_create(769),
        ffi.new("secp256k1_ecdsa_signature *"),
        b"0" * 32,
        ffi.NULL,
        ffi.NULL,
        b"0" * 32,
    )


def test_mult() -> None:
    pubkey_ = mult.mult_(prvkey)
    assert pubkey_[1:33] == pubkey_bytes[1:]
    pubkey = mult.mult(prvkey)
    assert pubkey[0] == int.from_bytes(pubkey_bytes[1:], "big")


def test_invalid_inputs() -> None:
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

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import pytest

from btclib_libsecp256k1 import dsa, ffi, lib, mult, ssa

# [B101:assert_used] Use of assert detected. The enclosed code will be
# removed when compiling to optimised byte code.
# https://bandit.readthedocs.io/en/1.7.4/plugins/b101_assert_used.html


prvkey = 1
pubkey_bytes = b"\x02y\xbef~\xf9\xdc\xbb\xacU\xa0b\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb-\xce(\xd9Y\xf2\x81[\x16\xf8\x17\x98"


def test_sign_and_verify() -> None:
    msg = b"\xa0\xdce\xff\xcay\x98s\xcb\xea\n\xc2t\x01[\x95&P]\xaa\xae\xd3\x85\x15T%\xf73w\x04\x88>"

    dsa_sig = dsa.sign(msg, prvkey)
    assert dsa.verify(msg, pubkey_bytes, dsa_sig)  # nosec B101
    assert dsa_sig == dsa.sign(msg, prvkey.to_bytes(32, "big"))

    ssa_sig = ssa.sign(msg, prvkey)
    assert ssa.verify(msg, pubkey_bytes, ssa_sig)  # nosec B101
    assert ssa.verify(msg, pubkey_bytes[1:], ssa_sig)  # nosec B101
    # assert ssa_sig == ssa.sign(msg, prvkey.to_bytes(32, "big"))  # nosec B101


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
    with pytest.raises(ValueError, match="DER"):
        dsa.verify(msg, pubkey_bytes, b"\x00" * 10)
    with pytest.raises(ValueError, match="public key"):
        dsa.verify(msg, b"\x02" + b"\x00" * 32, dsa_sig)

    ssa_sig = ssa.sign(msg, prvkey)
    with pytest.raises(ValueError, match="private key"):
        ssa.sign(msg, 0)
    with pytest.raises(ValueError, match="64 bytes"):
        ssa.verify(msg, pubkey_bytes, ssa_sig[1:])
    with pytest.raises(ValueError, match="public key"):
        ssa.verify(msg, b"\x00" * 32, ssa_sig)

    # a tampered signature does not raise: it just does not verify
    tampered = bytes([ssa_sig[0] ^ 1]) + ssa_sig[1:]
    assert not ssa.verify(msg, pubkey_bytes, tampered)  # nosec B101

    with pytest.raises(ValueError, match="scalar"):
        mult.mult(0)

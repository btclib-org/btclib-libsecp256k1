# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The nonce each signer derives, held to the signature it produced.

A nonce is checked against nothing but itself unless something else
knows it, and here that something is the signature: `r` is the x
coordinate of the nonce times the generator, reduced modulo the group
order, and BIP340's `R` is the same x without the reduction. So every
assertion below signs and then re-derives, which is what makes these
wrappers an oracle rather than a second implementation to trust.
"""

from __future__ import annotations

import hashlib

import pytest

from btclib_secp256k1 import dsa, keys, lib, recovery, ssa

# secp256k1 group order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

msg = hashlib.sha256(b"btclib_secp256k1").digest()
# 6 is the small scalar whose public key has odd y, which is the case
# BIP340 signs with the negated key
EVEN_Y, ODD_Y = 7, 6


def x_of(nonce: bytes) -> bytes:
    """Return the x coordinate of the nonce times the generator.

    Args:
        nonce: the 32-byte nonce.

    Returns:
        The 32 bytes of x, which is what a signature carries as r.
    """
    return keys.pubkey_from_prvkey(nonce, compressed=False)[1:33]


def test_the_default_nonce_function_is_the_rfc6979_one() -> None:
    """What `dsa.sign` selects and what `dsa.nonce_rfc6979` calls are one.

    `sign` passes NULL where the nonce function goes, which is
    `secp256k1_nonce_function_default`; this wrapper calls
    `secp256k1_nonce_function_rfc6979`. libsecp256k1's own header says
    they are "currently the same pointer", and every other assertion in
    this file rests on that: were upstream to split them, the signature
    comparisons would fail and say only that a nonce does not match its
    signature. This one says why.
    """
    assert lib.secp256k1_nonce_function_default == lib.secp256k1_nonce_function_rfc6979


@pytest.mark.parametrize("aux_rand32", [None, b"\x11" * 32], ids=["no aux", "aux"])
def test_rfc6979_nonce_is_the_one_the_signature_was_made_with(
    aux_rand32: bytes | None,
) -> None:
    """`dsa.nonce_rfc6979` answers the k of `dsa.sign` of the same arguments.

    Checked through the signature rather than against a vendored value:
    r is the x of k*G reduced modulo the group order, so a nonce that
    gives that r is the nonce that made that signature. Both spellings of
    the entropy are exercised, none and 32 octets, because ndata is what
    the RFC6979 derivation mixes in and what a grinding caller drives.
    """
    nonce = dsa.nonce_rfc6979(msg, EVEN_Y, aux_rand32)
    signature = dsa.sign(msg, EVEN_Y, aux_rand32, compact=True)

    assert len(nonce) == 32
    assert int.from_bytes(x_of(nonce), "big") % N == int.from_bytes(
        signature[:32], "big"
    )

    # the recoverable signer derives its nonce the same way, so the same
    # answer explains its r too
    recoverable, _ = recovery.sign(msg, EVEN_Y, aux_rand32)
    assert recoverable[:32] == signature[:32]


def test_rfc6979_attempt_is_the_counter_the_derivation_retries_on() -> None:
    """A later attempt is a different nonce, and 0 is what signing takes.

    RFC6979 retries when the candidate it derives is not a scalar in
    [1, n-1]; the counter is libsecp256k1's to drive and every signature
    this package makes has taken the first candidate, which is what the
    equality above asserts. What the argument is for is checking the rest
    of the contract, and what it must not be is out of range.
    """
    first = dsa.nonce_rfc6979(msg, EVEN_Y)
    assert dsa.nonce_rfc6979(msg, EVEN_Y, attempt=0) == first
    assert dsa.nonce_rfc6979(msg, EVEN_Y, attempt=1) != first

    with pytest.raises(ValueError, match=r"attempt must be in \[0, 4294967295\]"):
        dsa.nonce_rfc6979(msg, EVEN_Y, attempt=2**32)
    with pytest.raises(TypeError, match="attempt must be an int"):
        dsa.nonce_rfc6979(msg, EVEN_Y, attempt=1.0)  # type: ignore[call-overload]


@pytest.mark.parametrize("prvkey", [EVEN_Y, ODD_Y], ids=["even y", "odd y"])
def test_bip340_nonce_is_the_one_the_signature_was_made_with(prvkey: int) -> None:
    """`ssa.nonce_bip340` answers the k of `ssa.sign` of the same arguments.

    The first 32 octets of a BIP340 signature are the x of k*G, so the
    signature is what knows the nonce. The odd-y key is the case worth
    parametrizing: BIP340 signs with the key of the even-y point, so both
    the private key and the public key entering the derivation are the
    negated ones, and a wrapper that passed the caller's key would answer
    a nonce no signature was made with.
    """
    aux_rand32 = b"\x22" * 32
    nonce = ssa.nonce_bip340(msg, prvkey, aux_rand32)

    assert len(nonce) == 32
    assert x_of(nonce) == ssa.sign(msg, prvkey, aux_rand32)[:32]


def test_bip340_nonce_takes_a_message_of_any_length() -> None:
    """BIP340 signs messages of any length, and so derives nonces for them.

    `sign_custom` is the signer that takes one, and the nonce function
    takes the length beside the message for the same reason.
    """
    aux_rand32 = b"\x33" * 32
    for message in (b"", b"Satoshi Nakamoto" * 7):
        nonce = ssa.nonce_bip340(message, EVEN_Y, aux_rand32)
        assert x_of(nonce) == ssa.sign_custom(message, EVEN_Y, aux_rand32)[:32]


def test_bip340_without_aux_is_the_aux_of_zeros() -> None:
    """No auxiliary randomness is what 32 zero octets are, and not an error.

    libsecp256k1 substitutes the tagged hash of 32 zeros where the caller
    passes none, so the two spellings answer one nonce -- which is worth
    asserting because a python implementation has to choose one of them
    and BIP340's own text leaves the aux optional.
    """
    assert ssa.nonce_bip340(msg, EVEN_Y) == ssa.nonce_bip340(msg, EVEN_Y, bytes(32))
    # and a different aux is a different nonce, so the argument is read
    assert ssa.nonce_bip340(msg, EVEN_Y, b"\x01" * 32) != ssa.nonce_bip340(msg, EVEN_Y)


def test_the_nonce_wrappers_refuse_what_the_signers_refuse() -> None:
    """Every argument is held to what the signer holds it to.

    The message hash of the ECDSA derivation is 32 octets, the auxiliary
    randomness is 32 or nothing, and the private key is a scalar in
    [1, n-1] -- the last one refused by the public key derivation the
    BIP340 nonce needs, and by libsecp256k1 itself for RFC6979.
    """
    with pytest.raises(ValueError, match="message hash must be 32 bytes"):
        dsa.nonce_rfc6979(msg[:-1], EVEN_Y)
    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        dsa.nonce_rfc6979(msg, EVEN_Y, b"\x01" * 31)
    with pytest.raises(ValueError, match="private key must be 32 bytes"):
        dsa.nonce_rfc6979(msg, b"\x01" * 31)

    with pytest.raises(ValueError, match="aux_rand32 must be 32 bytes"):
        ssa.nonce_bip340(msg, EVEN_Y, b"\x01" * 33)
    with pytest.raises(ValueError, match="private key"):
        ssa.nonce_bip340(msg, 0)
    with pytest.raises(TypeError, match="message must be bytes"):
        ssa.nonce_bip340(11, EVEN_Y)  # type: ignore[call-overload]

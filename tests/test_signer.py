# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A signer signs what the module functions sign, and then wipes.

`ssa.Signer` is one of the two module functions with the keypair hoisted
out of it, so what has to hold is an equality -- signature for signature,
message length for message length -- and that equality is what the
published BIP340 vectors already pin on the other side: tests/
test_vectors.py signs each vector through a signer as well as through
`ssa.sign_custom`, so the value both are held against comes from
bitcoin/bips rather than from this package agreeing with itself.

What is left for this file is the half a vector cannot state: the
lifetime the signer hands the caller. The keypair is the private key in
libsecp256k1's layout, in memory this package owns, so what is asserted
here is that it is still there while the signer is usable, that `wipe`
and the `with` block each overwrite it, and that a wiped signer refuses
to sign instead of signing with the zeros.
"""

from __future__ import annotations

import hashlib

import pytest

from btclib_secp256k1 import ffi, keys, ssa, xonly

PRVKEY = (7).to_bytes(32, "big")
AUX = bytes(32)
MSG = hashlib.sha256(b"btclib_secp256k1").digest()
XONLY, PARITY = xonly.from_pubkey(keys.pubkey_from_prvkey(PRVKEY))


def keypair_memory(signer: ssa.Signer) -> bytes:
    """Return the octets of the keypair a signer holds.

    Reaching into the object is the only way to ask: nothing a signer
    answers with says whether the secret is still in there, which is the
    property under test.

    Args:
        signer: the signer to look inside.

    Returns:
        The 96 octets of the `secp256k1_keypair`, or an empty bytes once
        the signer has dropped it.
    """
    keypair = signer._keypair
    return b"" if keypair is None else bytes(ffi.buffer(keypair))


def test_a_signer_signs_what_the_function_signs() -> None:
    """Both signatures, over both message lengths, for the same aux.

    The aux is fixed, so a BIP340 signature is a value rather than a
    distribution and the two sides are comparable at all. A message of
    any other length is `sign_custom`'s, and a 32-byte one is signed the
    same way by both, which is what makes the four assertions two pairs
    rather than four values.
    """
    long_msg = b"a message longer than a hash, and of no particular length"

    with ssa.Signer(PRVKEY) as signer:
        assert signer.sign(MSG, AUX) == ssa.sign(MSG, PRVKEY, AUX)
        assert signer.sign_custom(MSG, AUX) == ssa.sign_custom(MSG, PRVKEY, AUX)
        assert signer.sign_custom(long_msg, AUX) == ssa.sign_custom(
            long_msg, PRVKEY, AUX
        )
        # and the signatures verify against the x-only key of the private
        # key the signer was built from, which is what they are for
        assert ssa.verify(MSG, XONLY, signer.sign(MSG))
        assert ssa.verify(long_msg, XONLY, signer.sign_custom(long_msg))


def test_a_signer_signs_more_than_once() -> None:
    """The motivating case: one keypair, several signatures.

    Signing does not consume or change the keypair -- the C call takes it
    const -- so a caller signing a batch under one key builds it once.
    Checked by signing three messages through one signer and verifying
    each, and then asserting the keypair is still the one the signer was
    built with rather than something the signatures left behind.
    """
    signer = ssa.Signer(PRVKEY)
    before = keypair_memory(signer)
    for index in range(3):
        msg = hashlib.sha256(index.to_bytes(4, "big")).digest()
        assert ssa.verify(msg, XONLY, signer.sign(msg))
    assert keypair_memory(signer) == before
    signer.wipe()


def test_a_signer_answers_the_key_it_signs_under() -> None:
    """`pubkey()` is the x-only key of the private key, read off the keypair.

    The keypair already holds the point, so this is the derivation the
    caller would otherwise make a second time -- and it is asserted
    against both of the ways of making it, `xonly.from_prvkey` and the
    serialized public key of the same private key. The parity comes with
    it, and is the one of the point before BIP340's negation, so a
    signature made here verifies against the 32 bytes whichever it is.
    """
    with ssa.Signer(PRVKEY) as signer:
        assert signer.pubkey() == (XONLY, PARITY)
        assert signer.pubkey() == xonly.from_prvkey(PRVKEY)
        assert ssa.verify(MSG, signer.pubkey()[0], signer.sign(MSG))

    # and a wiped signer has no key to answer with, as it has none to
    # sign with: the keypair is gone, and this refuses before reaching it
    signer = ssa.Signer(PRVKEY)
    signer.wipe()
    with pytest.raises(ValueError, match="wiped"):
        signer.pubkey()


def test_an_int_private_key_is_the_same_signer() -> None:
    """The constructor takes what `sign` takes, the int scalar included."""
    with ssa.Signer(7) as by_int, ssa.Signer(PRVKEY) as by_bytes:
        assert by_int.sign(MSG, AUX) == by_bytes.sign(MSG, AUX)


@pytest.mark.parametrize("prvkey", [0, b"\x01" * 31, bytes(32)], ids=str)
def test_a_private_key_is_refused_where_sign_refuses_it(prvkey: bytes | int) -> None:
    """What `sign` refuses, the constructor refuses, and at construction.

    Zero and the 32 zero octets are not scalars in [1, n-1], and 31
    octets are not a private key at all: the signer is the same check as
    `sign`'s, made once instead of once per signature.

    Args:
        prvkey: the value no signer can be built from.
    """
    with pytest.raises(ValueError, match="private key"):
        ssa.Signer(prvkey)
    with pytest.raises(ValueError, match="private key"):
        ssa.sign(MSG, prvkey, AUX)


def test_a_signer_checks_every_other_argument_too() -> None:
    """What the keypair was hoisted out of, the rest of the call still is.

    A message hash that is not 32 octets, and an aux that is not 32:
    both refused by the signer exactly as by the function, a bare
    pointer's length being what no C return code can report.
    """
    with ssa.Signer(PRVKEY) as signer:
        with pytest.raises(ValueError, match="message hash"):
            signer.sign(MSG[1:])
        with pytest.raises(ValueError, match="aux_rand32"):
            signer.sign(MSG, b"\x01" * 31)
        with pytest.raises(ValueError, match="aux_rand32"):
            signer.sign_custom(b"any length at all", b"\x01" * 33)


def test_wipe_overwrites_the_keypair() -> None:
    """The private key is in there until `wipe`, and gone after it.

    The keypair holds the 32 octets of the key, so the assertion is that
    they are found in the memory the signer holds and are not found
    afterwards -- which is the same thing tests/test_secret.py asserts of
    the buffer a call owns, over the one a caller owns.
    """
    signer = ssa.Signer(PRVKEY)
    assert PRVKEY in keypair_memory(signer)

    signer.wipe()
    assert keypair_memory(signer) == b""


def test_the_with_block_wipes_whatever_ended_it() -> None:
    """A signature, and an exception, leave the same zeroed keypair.

    The second is the case the `finally` in `sign` covers for a call, and
    the one a caller holding a keypair across calls would otherwise have
    to write for themselves.
    """
    with ssa.Signer(PRVKEY) as signer:
        signer.sign(MSG, AUX)
    assert keypair_memory(signer) == b""

    raising = ssa.Signer(PRVKEY)
    with pytest.raises(ValueError, match="what the block raised"), raising:
        raise ValueError("what the block raised")
    assert keypair_memory(raising) == b""


def test_wiping_twice_is_not_an_error() -> None:
    """Wiping inside the block is the case that makes it one.

    A caller that ends with the secret rather than with the block writes
    `signer.wipe()` and then leaves the `with`, so `__exit__` finds a
    signer already wiped: that is a signer with nothing left to do, not
    a mistake to report.
    """
    with ssa.Signer(PRVKEY) as signer:
        signer.wipe()
    signer.wipe()
    assert keypair_memory(signer) == b""


def test_a_wiped_signer_refuses_to_sign() -> None:
    """Rather than signing with the zeros the wipe left.

    Both entry points refuse, and the refusal is the one a caller can
    act on: the key is kept nowhere else here, so the answer is another
    signer rather than a way back.
    """
    signer = ssa.Signer(PRVKEY)
    signer.wipe()

    with pytest.raises(ValueError, match="wiped"):
        signer.sign(MSG, AUX)
    with pytest.raises(ValueError, match="wiped"):
        signer.sign_custom(MSG, AUX)

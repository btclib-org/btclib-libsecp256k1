# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A signer checks its own signature before answering with it.

BIP340 puts the check inside *Default Signing* -- "If Verify(bytes(P), m,
sig) returns failure, abort" -- and Bitcoin Core's `CKey::Sign` does the
same for ECDSA without offering a way out, both for the same reason: a
computation that went wrong, whether by bad memory or by an induced
fault, yields a signature that is invalid and may say something about the
key, and the protection is not publishing one.

What can be tested about it is not the fault, which no input produces.
It is the four things around it: that the check changes no signature,
that it is on where nothing asks, that a refusal is wired to the raise
rather than merely written near it, and that `verify=False` does not
reach the check at all.

The last two are one substituted verification read in both directions,
and the last is the one nothing else covers: the signature is the same
bytes whether or not the flag was honoured, so a `verify` ignored
altogether would answer exactly what it should. Replacing every
`if verify:` in the package with `if True:` leaves every other test here
passing.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from typing import Any

import pytest

from btclib_secp256k1 import dsa, ssa, xonly

MSG = hashlib.sha256(b"a message to sign twice").digest()
PRVKEY = 7
AUX = bytes(32)

# every entry point that took a `verify`, as a call of one key and one
# message: the pair is the same signature asked for with the check and
# without it, which is the equality every test here is built on
SIGNERS: list[tuple[str, Callable[..., bytes]]] = [
    ("dsa.sign", lambda **kw: dsa.sign(MSG, PRVKEY, **kw)),
    ("dsa.sign compact", lambda **kw: dsa.sign(MSG, PRVKEY, compact=True, **kw)),
    ("dsa.sign grind", lambda **kw: dsa.sign(MSG, PRVKEY, grind=True, **kw)),
    ("dsa._sign_", lambda **kw: dsa.serialize_der(dsa._sign_(MSG, PRVKEY, **kw))),
    ("ssa.sign", lambda **kw: ssa.sign(MSG, PRVKEY, AUX, **kw)),
    ("ssa.sign_custom", lambda **kw: ssa.sign_custom(MSG, PRVKEY, AUX, **kw)),
    ("Signer.sign", lambda **kw: _through_signer("sign", **kw)),
    ("Signer.sign_custom", lambda **kw: _through_signer("sign_custom", **kw)),
]


def _refusing(*_args: Any, **_kwargs: Any) -> bool:
    """Stand in for a verification, and refuse whatever it is handed.

    Substituted for `dsa._verify_` and `ssa._verify_` in the two tests
    that ask what the signing path does with each answer: no input makes
    a real verification of a fresh signature fail, so a stand-in is the
    only way to reach either branch.

    Args:
        _args: whatever the verification would have taken.
        _kwargs: the same.

    Returns:
        False, always.
    """
    return False


def _through_signer(method: str, **kwargs: Any) -> bytes:
    """Sign through a `Signer` built and wiped for the one call.

    Args:
        method: `sign` or `sign_custom`.
        kwargs: what to pass it beyond the message and the aux.

    Returns:
        The 64-byte signature.
    """
    with ssa.Signer(PRVKEY) as signer:
        signed: bytes = getattr(signer, method)(MSG, AUX, **kwargs)
    return signed


@pytest.mark.parametrize("name,signer", SIGNERS, ids=[n for n, _ in SIGNERS])
def test_the_check_changes_no_signature(
    name: str, signer: Callable[..., bytes]
) -> None:
    """Checking a signature is a question, so it answers the same bytes.

    The point of the parametrization is the entry points rather than the
    signatures: each of them grew an argument, and an argument passed to
    the wrong half of a call -- or not passed on at all -- is what this
    would catch. Deterministic on both sides, RFC6979 for ECDSA and a
    fixed aux for BIP340, so the equality is of one signature and not of
    two that happen to verify.

    Args:
        name: the entry point, for the test id.
        signer: it, as a call taking the keyword under test.
    """
    assert signer(verify=True) == signer(verify=False)


@pytest.mark.parametrize("name,signer", SIGNERS, ids=[n for n, _ in SIGNERS])
def test_the_check_is_on_where_nothing_asks(
    name: str, signer: Callable[..., bytes]
) -> None:
    """Not passing the argument is passing True, which is the default.

    Stated in five docstrings and checked here, because the difference
    between the two defaults is invisible in every other test in this
    suite: the signature is the same either way, and only the cost and
    the guarantee differ.

    Args:
        name: the entry point, for the test id.
        signer: it, as a call taking the keyword under test.
    """
    assert signer() == signer(verify=True)


@pytest.mark.parametrize(
    "name,function",
    [
        ("dsa.sign", dsa.sign),
        ("dsa._sign_", dsa._sign_),
        ("ssa.sign", ssa.sign),
        ("ssa.sign_custom", ssa.sign_custom),
        ("ssa._sign32", ssa._sign32),
        ("ssa._sign_custom", ssa._sign_custom),
        ("Signer.sign", ssa.Signer.sign),
        ("Signer.sign_custom", ssa.Signer.sign_custom),
    ],
)
def test_every_signer_defaults_to_checking(
    name: str, function: Callable[..., Any]
) -> None:
    """The default is True everywhere it exists, private halves included.

    A private half left at False would be the hole the public ones
    closed: `Signer.sign` reaches `_sign32` and passes what it was given,
    so a default that disagreed would be a second policy nobody stated.

    Args:
        name: the entry point, for the test id.
        function: it, to read the signature of.
    """
    assert inspect.signature(function).parameters["verify"].default is True


@pytest.mark.parametrize("name,signer", SIGNERS, ids=[n for n, _ in SIGNERS])
def test_a_signature_that_does_not_verify_is_not_answered_with(
    name: str, signer: Callable[..., bytes]
) -> None:
    """The raise is wired to the check, and not merely written near it.

    No input makes a verification of a fresh signature fail -- that is
    why the `raise RuntimeError` is excluded from coverage -- so the
    verification is substituted for one that refuses. What this holds is
    the wiring: that a False there stops the signature from being
    returned, at every entry point rather than at one of them.

    Args:
        name: the entry point, for the test id.
        signer: it, as a call taking the keyword under test.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(dsa, "_verify_", _refusing)
        patch.setattr(ssa, "_verify_", _refusing)
        with pytest.raises(RuntimeError, match="does not verify"):
            signer()


@pytest.mark.parametrize("name,signer", SIGNERS, ids=[n for n, _ in SIGNERS])
def test_the_refused_check_is_not_made_at_all(
    name: str, signer: Callable[..., bytes]
) -> None:
    """`verify=False` does not reach the check, which nothing else sees.

    The other direction, and the one no assertion above can stand in for:
    the signature is the same bytes whether or not the flag was honoured,
    so a `verify` ignored altogether would answer exactly what it should.
    Replacing every `if verify:` with `if True:` leaves the whole suite
    passing without this test, and fails it with it.

    The refusing verification is what makes the difference visible: if
    the check were made in spite of the False it would raise here, and
    what this asserts is that a signature comes back instead.

    Args:
        name: the entry point, for the test id.
        signer: it, as a call taking the keyword under test.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(dsa, "_verify_", _refusing)
        patch.setattr(ssa, "_verify_", _refusing)
        assert signer(verify=False)


def test_the_keypair_is_checked_against_the_key_that_signed() -> None:
    """BIP340 negates an odd-y key, and the check follows it there.

    The failure this rules out is a check that passes for the wrong
    reason: `_verified` reads the x-only key off the keypair, which is
    the negated one where the point has odd y, and a signature verifies
    against those 32 bytes whichever the parity was. Signing with keys of
    both parities is what exercises the two sides, so both are asserted
    to occur rather than assumed to.
    """
    parities = set()
    for prvkey in range(1, 8):
        pubkey, parity = xonly.from_prvkey(prvkey)
        parities.add(parity)
        # verify=True is the default: what this asserts is that it did
        # not raise, and the signature is held to the key besides
        assert ssa.verify(MSG, pubkey, ssa.sign(MSG, prvkey, AUX))
    assert parities == {0, 1}

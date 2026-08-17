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

`recovery` asks a different question for the same reason, as Core's
`CKey::SignCompact` does: it recovers the key from the signature and
refuses one that is not the signer's, the recovery id being what this
signature has beyond a plain one and what a verification does not look
at. So the refusal substituted below is per module rather than one for
all three.

For `dsa` and `ssa` the fault itself is out of reach -- no input makes a
fresh signature fail its own verification -- so what is tested is the
four things around it: that the check changes no signature, that it is on
where nothing asks, that a refusal is wired to the raise rather than
merely written near it, and that `verify=False` does not reach the check
at all.

The last two are one substituted verification read in both directions,
and the second of them is the one nothing else covers: the signature is
the same bytes whether or not the flag was honoured, so a `verify`
ignored altogether would answer exactly what it should. Replacing every
`if verify:` in the package with `if True:` leaves every other test here
passing.

`recovery` adds a fifth, and it is the one that says what the check is
for rather than that the raise is wired to it. There the fault *is*
reachable from an input -- a wrong recovery id is one `parse_compact`
away -- so the last test in this file needs no stand-in at all: it
signs, re-parses under each id, and holds real libsecp256k1 to refusing
every one but the signature's own, while a verification of the same
octets still succeeds.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from typing import Any, NoReturn

import pytest

from btclib_secp256k1 import CData, dsa, keys, recovery, ssa, xonly

MSG = hashlib.sha256(b"a message to sign twice").digest()
PRVKEY = 7
PRVKEY_BYTES = PRVKEY.to_bytes(32, "big")
AUX = bytes(32)

# what a refused check reports, which is not one message: `dsa` and `ssa`
# verify and say so, `recovery` recovers and says which half of that
# failed. Carried per entry point so that the test asserting the raise
# pins the module that raised rather than the prefix they share
_UNVERIFIED = "does not verify"
_UNRECOVERED = "no key recovers from"

# every entry point that took a `verify`, as a call of one key and one
# message, and the refusal it answers with: the pair is the same
# signature asked for with the check and without it, which is the
# equality every test here is built on
SIGNERS: list[tuple[str, Callable[..., Any], str]] = [
    ("dsa.sign", lambda **kw: dsa.sign(MSG, PRVKEY, **kw), _UNVERIFIED),
    (
        "dsa.sign compact",
        lambda **kw: dsa.sign(MSG, PRVKEY, compact=True, **kw),
        _UNVERIFIED,
    ),
    (
        "dsa.sign grind",
        lambda **kw: dsa.sign(MSG, PRVKEY, grind=True, **kw),
        _UNVERIFIED,
    ),
    (
        "dsa._sign_",
        lambda **kw: dsa.serialize_der(dsa._sign_(MSG, PRVKEY, **kw)),
        _UNVERIFIED,
    ),
    ("ssa.sign", lambda **kw: ssa.sign(MSG, PRVKEY, AUX, **kw), _UNVERIFIED),
    (
        "ssa.sign_custom",
        lambda **kw: ssa.sign_custom(MSG, PRVKEY, AUX, **kw),
        _UNVERIFIED,
    ),
    ("Signer.sign", lambda **kw: _through_signer("sign", **kw), _UNVERIFIED),
    (
        "Signer.sign_custom",
        lambda **kw: _through_signer("sign_custom", **kw),
        _UNVERIFIED,
    ),
    ("recovery.sign", lambda **kw: recovery.sign(MSG, PRVKEY, **kw), _UNRECOVERED),
    (
        "recovery._sign_",
        lambda **kw: recovery.serialize_compact(recovery._sign_(MSG, PRVKEY, **kw)),
        _UNRECOVERED,
    ),
]


def _refusing(*_args: Any, **_kwargs: Any) -> bool:
    """Stand in for a verification, and refuse whatever it is handed.

    Substituted for `dsa._verify_` and `ssa._verify_`: no input makes a
    real verification of a fresh signature fail, so a stand-in is the
    only way to reach either branch.

    Args:
        _args: whatever the verification would have taken.
        _kwargs: the same.

    Returns:
        False, always.
    """
    return False


def _not_recovering(*_args: Any, **_kwargs: Any) -> NoReturn:
    """Stand in for a recovery, and fail the way a real one fails.

    `recovery`'s check is a recovery and a comparison rather than a
    verification, so refusing it is refusing this. The `ValueError` is
    the one `recovery._recover_` raises of a signature no key comes back
    from, which is what the signing path has to turn into a
    `RuntimeError`: for a signature made a line earlier, nothing was
    passed that could have caused it.

    Args:
        _args: whatever the recovery would have taken.
        _kwargs: the same.

    Raises:
        ValueError: always.
    """
    raise ValueError("public key recovery failed")


def _recovering_another_key(*_args: Any, **_kwargs: Any) -> CData:
    """Stand in for a recovery, and answer a key that is not the signer's.

    The other half of what `recovery`'s check asks. A signature carrying
    the wrong recovery id verifies perfectly and recovers somebody else's
    key, so answering a valid key that is not this one is the fault worth
    substituting -- and the one a plain verification would have missed.

    Args:
        _args: whatever the recovery would have taken.
        _kwargs: the same.

    Returns:
        The parsed public key of a different private key.
    """
    return keys._pubkey_from_prvkey_(PRVKEY + 1)


def _refuse_every_check(patch: pytest.MonkeyPatch) -> None:
    """Make the check refuse, in whichever module is about to run one.

    The three modules do not ask the same question -- `dsa` and `ssa`
    verify, `recovery` recovers and compares -- so one parametrization
    over every entry point needs all three refusals in place at once.
    Each is inert for the entry points that do not reach it.

    Args:
        patch: the monkeypatch context to install them in.
    """
    patch.setattr(dsa, "_verify_", _refusing)
    patch.setattr(ssa, "_verify_", _refusing)
    patch.setattr(recovery, "_recover_", _not_recovering)


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


@pytest.mark.parametrize("name,signer,refusal", SIGNERS, ids=[n for n, *_ in SIGNERS])
def test_the_check_changes_no_signature(
    name: str, signer: Callable[..., Any], refusal: str
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
        refusal: what a refused check reports there, unused where the
            test does not refuse one.
    """
    assert signer(verify=True) == signer(verify=False)


@pytest.mark.parametrize("name,signer,refusal", SIGNERS, ids=[n for n, *_ in SIGNERS])
def test_the_check_is_on_where_nothing_asks(
    name: str, signer: Callable[..., Any], refusal: str
) -> None:
    """Not passing the argument is passing True, which is the default.

    Stated in a docstring at every entry point and checked here,
    because the difference between the two defaults is invisible in
    every other test in this suite: the signature is the same either
    way, and only the cost and the guarantee differ.

    Args:
        name: the entry point, for the test id.
        signer: it, as a call taking the keyword under test.
        refusal: what a refused check reports there, unused where the
            test does not refuse one.
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
        ("recovery.sign", recovery.sign),
        ("recovery._sign_", recovery._sign_),
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


@pytest.mark.parametrize("name,signer,refusal", SIGNERS, ids=[n for n, *_ in SIGNERS])
def test_a_signature_that_does_not_verify_is_not_answered_with(
    name: str, signer: Callable[..., Any], refusal: str
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
        refusal: what a refused check reports there, unused where the
            test does not refuse one.
    """
    with pytest.MonkeyPatch.context() as patch:
        _refuse_every_check(patch)
        with pytest.raises(RuntimeError, match=refusal):
            signer()


@pytest.mark.parametrize("name,signer,refusal", SIGNERS, ids=[n for n, *_ in SIGNERS])
def test_the_refused_check_is_not_made_at_all(
    name: str, signer: Callable[..., Any], refusal: str
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
        refusal: what a refused check reports there, unused where the
            test does not refuse one.
    """
    with pytest.MonkeyPatch.context() as patch:
        _refuse_every_check(patch)
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


def test_a_signature_that_recovers_another_key_is_not_answered_with() -> None:
    """The failure a verification would have missed, and this one does not.

    A recoverable signature whose recovery id is wrong verifies perfectly
    and recovers somebody else's key, so `recovery` compares the key that
    comes back instead of verifying: this substitutes a recovery that
    answers a valid key which is not the signer's, and holds the signing
    path to refusing it.

    The second assertion is what says the refusal is the comparison and
    not the recovery: nothing failed on the way, a real key came back,
    and `verify=False` still answers a signature.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(recovery, "_recover_", _recovering_another_key)
        with pytest.raises(RuntimeError, match="recovers another key"):
            recovery.sign(MSG, PRVKEY)
        assert recovery.sign(MSG, PRVKEY, verify=False)


def test_the_recovery_id_is_what_the_check_catches() -> None:
    """The premise of `recovery`'s check, without a stand-in anywhere.

    Every other test here substitutes the recovery, so what they prove is
    that the signing path refuses what a recovery reports -- not that a
    wrong recovery id is what produces the report. That needs no
    substitution at all: one real signature, parsed under each of the
    four ids, and the real libsecp256k1 asked about each.

    Which id does which is structural rather than lucky. The other
    parity of the same `r` is a point like any other, so it recovers a
    key -- somebody else's. Ids 2 and 3 ask for the point at `r + n`,
    which exceeds the field for any `r` a signature is likely to carry,
    so nothing is recovered at all and `_recover_`'s `ValueError`
    becomes the `RuntimeError` this module converts it into. Both
    branches, both messages, no monkeypatch.

    The last assertion is the argument of the whole change in one line:
    the octets a verification accepts are the octets refused above. `r`
    and `s` are the signer's and verify under the signer's key -- the id,
    which a verification never looks at, is the entire difference.
    """
    signature, recid = recovery.sign(MSG, PRVKEY)
    assert recid == 1

    # the id it was made with, which is what makes the refusals below a
    # refusal of the id rather than of the signature
    recovery._abort_unless_recovered(
        recovery.parse_compact(signature, recid), MSG, PRVKEY_BYTES
    )

    with pytest.raises(RuntimeError, match="recovers another key"):
        recovery._abort_unless_recovered(
            recovery.parse_compact(signature, 1 - recid), MSG, PRVKEY_BYTES
        )
    for beyond_the_field in (2, 3):
        with pytest.raises(RuntimeError, match=_UNRECOVERED):
            recovery._abort_unless_recovered(
                recovery.parse_compact(signature, beyond_the_field), MSG, PRVKEY_BYTES
            )

    assert dsa._verify_(
        MSG, keys._pubkey_from_prvkey_(PRVKEY_BYTES), dsa.parse_compact(signature)
    )

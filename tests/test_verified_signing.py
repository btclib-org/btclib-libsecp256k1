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

`dsa` adds a group of its own, for the public key a caller may hand the
check instead of having it derived. Those turn on the key being taken on
trust: what it costs -- a failure that has two causes, told apart in both
directions, one of them needing the same stand-in as above -- and what it
cannot cost, which is a signature wrongly accepted. That last one is the
strongest thing in this file, and it is a property over many keys rather
than a case.

`recovery` takes the same key and adds the group after it, where the
failure has three causes rather than two: the key given, the recovery id,
or the computation. The first is an argument and the other two are not,
and what separates them is the derivation the matching path skipped. The
last of those tests is the one nothing else in the package can write --
a right key and a wrong id, both real, no stand-in anywhere -- and the
property over many keys is asserted again there, because what makes the
trust safe is a different sentence when the key is recovered rather than
verified against.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable
from typing import Any, NoReturn

import pytest

from btclib_secp256k1 import CData, dsa, ffi, keys, recovery, ssa, xonly

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

# what each test is actually handed, derived from the rows above rather
# than written a second time: the calls alone for the three that never
# provoke a refusal, the call and its refusal for the one that does.
# `SIGNERS` stays the whole truth about an entry point and the refusal
# stays beside the call it belongs to, while no test declares an argument
# it does not read -- the name included, which `ids` supplies and no body
# has ever looked at
SIGNING_CALLS: list[Callable[..., Any]] = [signer for _, signer, _ in SIGNERS]
REFUSING_CALLS: list[tuple[Callable[..., Any], str]] = [
    (signer, refusal) for _, signer, refusal in SIGNERS
]

# one statement of the ids, every table here being those rows in that
# order
SIGNER_IDS = [name for name, *_ in SIGNERS]

# every function that took a `verify`, which is not the same list: a
# default is a property of a signature rather than of a call, so the
# private halves are here and the three shapes of `dsa.sign` are not. A
# mapping, because the name is the id and nothing else reads it
_DEFAULTING: dict[str, Callable[..., Any]] = {
    "dsa.sign": dsa.sign,
    "dsa._sign_": dsa._sign_,
    "ssa.sign": ssa.sign,
    "ssa.sign_custom": ssa.sign_custom,
    "ssa._sign32": ssa._sign32,
    "ssa._sign_custom": ssa._sign_custom,
    "Signer.sign": ssa.Signer.sign,
    "Signer.sign_custom": ssa.Signer.sign_custom,
    "recovery.sign": recovery.sign,
    "recovery._sign_": recovery._sign_,
}


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


def _refusing_to_derive(*_args: Any, **_kwargs: Any) -> NoReturn:
    """Stand in for the derivation, and fail if anything makes it.

    What a key handed in is for is not deriving one, and every other test
    of that argument would pass with the saving deleted: the derived
    comparison that follows agrees with the one handed in, so a check
    ignoring the argument answers the same signature. Substituting the
    multiplication itself is what turns the saving into an assertion.

    Args:
        _args: whatever the derivation would have taken.
        _kwargs: the same.

    Raises:
        AssertionError: always.
    """
    raise AssertionError("the key handed in was derived anyway")


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


@pytest.mark.parametrize("signer", SIGNING_CALLS, ids=SIGNER_IDS)
def test_the_check_changes_no_signature(signer: Callable[..., Any]) -> None:
    """Checking a signature is a question, so it answers the same bytes.

    The point of the parametrization is the entry points rather than the
    signatures: each of them grew an argument, and an argument passed to
    the wrong half of a call -- or not passed on at all -- is what this
    would catch. Deterministic on both sides, RFC6979 for ECDSA and a
    fixed aux for BIP340, so the equality is of one signature and not of
    two that happen to verify.

    Args:
        signer: the entry point, as a call taking the keyword under test.
    """
    assert signer(verify=True) == signer(verify=False)


@pytest.mark.parametrize("signer", SIGNING_CALLS, ids=SIGNER_IDS)
def test_the_check_is_on_where_nothing_asks(signer: Callable[..., Any]) -> None:
    """Not passing the argument is passing True, which is the default.

    Stated in a docstring at every entry point and checked here,
    because the difference between the two defaults is invisible in
    every other test in this suite: the signature is the same either
    way, and only the cost and the guarantee differ.

    Args:
        signer: the entry point, as a call taking the keyword under test.
    """
    assert signer() == signer(verify=True)


@pytest.mark.parametrize("function", list(_DEFAULTING.values()), ids=list(_DEFAULTING))
def test_every_signer_defaults_to_checking(function: Callable[..., Any]) -> None:
    """The default is True everywhere it exists, private halves included.

    A private half left at False would be the hole the public ones
    closed: `Signer.sign` reaches `_sign32` and passes what it was given,
    so a default that disagreed would be a second policy nobody stated.

    Args:
        function: the entry point, to read the signature of.
    """
    assert inspect.signature(function).parameters["verify"].default is True


@pytest.mark.parametrize("signer,refusal", REFUSING_CALLS, ids=SIGNER_IDS)
def test_a_signature_that_does_not_verify_is_not_answered_with(
    signer: Callable[..., Any], refusal: str
) -> None:
    """The raise is wired to the check, and not merely written near it.

    No input makes a verification of a fresh signature fail -- that is
    why the `raise RuntimeError` is excluded from coverage -- so the
    verification is substituted for one that refuses. What this holds is
    the wiring: that a False there stops the signature from being
    returned, at every entry point rather than at one of them.

    Args:
        signer: the entry point, as a call taking the keyword under test.
        refusal: what a refused check reports there, and what this
            matches on: the module and not the package, `dsa` and `ssa`
            saying a signature does not verify where `recovery` says no
            key recovers from one.
    """
    with pytest.MonkeyPatch.context() as patch:
        _refuse_every_check(patch)
        with pytest.raises(RuntimeError, match=refusal):
            signer()


@pytest.mark.parametrize("signer", SIGNING_CALLS, ids=SIGNER_IDS)
def test_the_refused_check_is_not_made_at_all(signer: Callable[..., Any]) -> None:
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
        signer: the entry point, as a call taking the keyword under test.
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
        recovery.parse_compact(signature, recid), MSG, PRVKEY_BYTES, None
    )

    with pytest.raises(RuntimeError, match="recovers another key"):
        recovery._abort_unless_recovered(
            recovery.parse_compact(signature, 1 - recid), MSG, PRVKEY_BYTES, None
        )
    for beyond_the_field in (2, 3):
        with pytest.raises(RuntimeError, match=_UNRECOVERED):
            recovery._abort_unless_recovered(
                recovery.parse_compact(signature, beyond_the_field),
                MSG,
                PRVKEY_BYTES,
                None,
            )

    assert dsa._verify_(
        MSG, keys._pubkey_from_prvkey_(PRVKEY_BYTES), dsa.parse_compact(signature)
    )


def test_a_key_handed_in_is_the_key_that_would_have_been_derived() -> None:
    """The signature is the same one, whichever way the check got its key.

    What the argument is for is skipping a point multiplication, so what
    has to hold is that nothing else changed with it: the same message
    and key answer the same octets in both serializations and with the
    grinding loop, which is the third place the check could have been
    reached from.
    """
    uncompressed = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
    compressed = keys.pubkey_from_prvkey(PRVKEY, compressed=True)
    for compact, grind in ((False, False), (True, False), (False, True)):
        derived = dsa.sign(MSG, PRVKEY, None, compact, grind)
        for held in (uncompressed, compressed):
            assert dsa.sign(MSG, PRVKEY, None, compact, grind, pubkey=held) == derived


def test_the_wrong_key_is_told_apart_from_a_wrong_computation() -> None:
    """A key that is not this private key's is an argument, not a fault.

    The whole reason the failing branch derives: without it a caller who
    passed the wrong key is told the computation went wrong, which is
    what `RuntimeError` means here and what somebody would go looking
    for their hardware over. The two are distinguishable only by which
    exception arrives, since the signature is fine either way.
    """
    other = keys.pubkey_from_prvkey(PRVKEY + 1, compressed=False)
    with pytest.raises(ValueError, match="not this private key's"):
        dsa.sign(MSG, PRVKEY, pubkey=other)


def test_octets_that_are_not_a_key_are_refused_before_anything_is_signed() -> None:
    """Parsed on the way in, so a mistyped argument is not a verdict.

    A key parsed inside the check would make bad octets arrive as a
    failed verification of a signature the caller now holds, which reads
    as the signature being wrong. Refusing at the boundary is the same
    discipline every other argument of this package gets.
    """
    with pytest.raises(ValueError, match="invalid public key"):
        dsa.sign(MSG, PRVKEY, pubkey=b"\x02" + bytes(32))


def test_a_key_is_refused_beside_the_flag_that_declines_the_check() -> None:
    """A key to check with is refused where the check is declined.

    `verify=False` and a key to check under is a caller contradicting
    themselves, and the package answers those rather than resolving
    them -- as it does for `aux_rand32` beside `grind`.
    """
    pubkey = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
    with pytest.raises(ValueError, match="verify=False declines"):
        dsa.sign(MSG, PRVKEY, verify=False, pubkey=pubkey)


def test_the_private_half_refuses_that_contradiction_too() -> None:
    """`_sign_` is the row the table recommends, not an internal detail.

    A caller holding a parsed point calls `_sign_` to save the parse, so
    the private half is where the argument is cheapest and the one place
    a `pubkey` must not be ignored beside `verify=False`. The copy of the
    refusal there is for that caller, and this is the case that reaches
    it -- the same reason `test_every_signer_defaults_to_checking`
    exists.
    """
    with pytest.raises(ValueError, match="verify=False declines"):
        dsa._sign_(
            MSG, PRVKEY, verify=False, pubkey=keys._pubkey_from_prvkey_(PRVKEY_BYTES)
        )


def test_a_key_fixed_in_advance_cannot_pass_a_signature_of_another_key() -> None:
    """What makes taking the key on trust safe, stated as a property.

    The keys a signature verifies under are a property of that signature
    -- `recovery.recover` walks them -- so a key chosen before the
    signature exists is not one of them. That is why the trust can cost
    a wrong diagnosis and never a wrong success, and it is checked here
    over keys and messages rather than argued in a docstring.
    """
    wrong = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
    for other_key in range(PRVKEY + 1, PRVKEY + 41):
        msg = hashlib.sha256(other_key.to_bytes(32, "big")).digest()
        with pytest.raises(ValueError, match="not this private key's"):
            dsa.sign(msg, other_key, pubkey=wrong)


def test_a_fault_under_a_handed_in_key_is_not_reported_as_a_wrong_key() -> None:
    """The other half of the discrimination, and the one coverage hides.

    `raise RuntimeError` is outside the coverage ratchet by design, so a
    hundred percent says nothing about this branch. What it guards is the
    inversion of the misdiagnosis the whole argument is built to avoid:
    with the second verification stubbed to succeed, every genuine fault
    met under a handed-in key would be reported as "the public key given
    is not this private key's" -- a caller told they mistyped an argument
    because their hardware went wrong.

    The key handed in here is the right one, so the only reason either
    verification can fail is the substitution, and what has to arrive is
    the fault.
    """
    pubkey = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
    with pytest.MonkeyPatch.context() as patch:
        _refuse_every_check(patch)
        with pytest.raises(RuntimeError, match=_UNVERIFIED):
            dsa.sign(MSG, PRVKEY, pubkey=pubkey)


def test_a_key_handed_in_is_the_key_recovery_would_have_derived() -> None:
    """The signature is the same pair, whichever way the check got its key.

    `recovery`'s answer is the compact signature and its id, so both have
    to be the same: an argument that changed the id would be a different
    signature recovering a different key, which is the one thing this
    module cannot get wrong quietly. Both serializations of the key are
    handed in, the parse being the only difference between them.
    """
    derived = recovery.sign(MSG, PRVKEY)
    for held in (
        keys.pubkey_from_prvkey(PRVKEY, compressed=False),
        keys.pubkey_from_prvkey(PRVKEY, compressed=True),
    ):
        assert recovery.sign(MSG, PRVKEY, pubkey=held) == derived


def test_the_key_given_is_told_apart_from_the_signature_being_wrong() -> None:
    """A key that is not this private key's is an argument, not a fault.

    The reason the failing branch derives, and here it separates one
    cause from two rather than one from one: `RuntimeError` means the
    signature does not recover its own signer -- a wrong id or a fault,
    neither of them anything the caller passed -- while a wrong key given
    is a `ValueError` and stays one.
    """
    other = keys.pubkey_from_prvkey(PRVKEY + 1, compressed=False)
    with pytest.raises(ValueError, match="not this private key's"):
        recovery.sign(MSG, PRVKEY, pubkey=other)


def test_octets_that_are_not_a_key_are_refused_before_signing_recoverably() -> None:
    """Parsed on the way in, so a mistyped argument is not a verdict.

    `dsa.sign` is held to this too. Here what a key parsed inside the
    check would produce is a report that the signature recovers somebody
    else, which is the module's most alarming message and would be about
    the caller's own typing.
    """
    with pytest.raises(ValueError, match="invalid public key"):
        recovery.sign(MSG, PRVKEY, pubkey=b"\x02" + bytes(32))


def test_a_key_is_refused_where_the_recoverable_check_is_declined() -> None:
    """A key to compare with is refused where the comparison is declined.

    Both halves refuse it, and the private one is not a copy for its own
    sake: a caller holding a parsed point calls `_sign_` precisely to save
    the parse, so that is where the argument is cheapest and where it must
    not be silently ignored.
    """
    with pytest.raises(ValueError, match="verify=False declines"):
        recovery.sign(MSG, PRVKEY, verify=False, pubkey=keys.pubkey_from_prvkey(PRVKEY))
    with pytest.raises(ValueError, match="verify=False declines"):
        recovery._sign_(
            MSG, PRVKEY, verify=False, pubkey=keys._pubkey_from_prvkey_(PRVKEY_BYTES)
        )


def test_a_wrong_id_under_a_right_key_is_not_reported_as_a_wrong_key() -> None:
    """The three-way failure, all three real, no stand-in anywhere.

    This is the case no other module can write. A wrong recovery id is
    reachable from an input -- `parse_compact` is one call -- so the two
    causes that are not the caller's can be told from the one that is
    without substituting a recovery: the same signature, its own id and
    the other, and the signer's key handed in beside a stranger's.

    What it guards is the misdiagnosis in both directions. A right key
    with a wrong id must not arrive as "the public key given is not this
    private key's", which would send a caller to check an argument that
    was correct; and a wrong key with a right id must not arrive as the
    `RuntimeError`, which is this package's word for the computation
    having gone wrong.
    """
    signature, recid = recovery.sign(MSG, PRVKEY)
    signer = keys._pubkey_from_prvkey_(PRVKEY_BYTES)
    stranger = keys._pubkey_from_prvkey_(PRVKEY + 1)

    # the signature's own id and the key that made it: the case the other
    # two are read against
    recovery._abort_unless_recovered(
        recovery.parse_compact(signature, recid), MSG, PRVKEY_BYTES, signer
    )

    with pytest.raises(RuntimeError, match="recovers another key"):
        recovery._abort_unless_recovered(
            recovery.parse_compact(signature, 1 - recid), MSG, PRVKEY_BYTES, signer
        )
    with pytest.raises(ValueError, match="not this private key's"):
        recovery._abort_unless_recovered(
            recovery.parse_compact(signature, recid), MSG, PRVKEY_BYTES, stranger
        )


def test_a_key_fixed_in_advance_cannot_pass_a_recovered_signature() -> None:
    """What makes taking the key on trust safe here, as a property.

    Stronger than the `dsa` sentence rather than the same one: there the
    key handed in has to be one of the keys the signature verifies under,
    and here it has to be the single key the signature recovers. So a key
    chosen before the signature exists passes only by having been the
    signer's, and over forty keys and messages none of them is.
    """
    wrong = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
    for other_key in range(PRVKEY + 1, PRVKEY + 41):
        msg = hashlib.sha256(other_key.to_bytes(32, "big")).digest()
        with pytest.raises(ValueError, match="not this private key's"):
            recovery.sign(msg, other_key, pubkey=wrong)


def test_the_derivation_the_argument_saves_is_not_made_at_all() -> None:
    """The saving itself, asserted rather than measured.

    The check compares the recovered key with the one handed in and
    derives only where they differ, so nothing that reads the answer can
    tell that early return from its absence -- delete it and the derived
    comparison below agrees, answering the same signature and the same
    id. With the multiplication substituted for one that raises, the
    signature coming back at all is what says it was never made.
    """
    pubkey = keys.pubkey_from_prvkey(PRVKEY)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(keys, "_pubkey_from_prvkey_", _refusing_to_derive)
        assert recovery.sign(MSG, PRVKEY, pubkey=pubkey) == recovery.sign(
            MSG, PRVKEY, verify=False
        )


def test_the_discrimination_holds_for_a_key_held_in_a_buffer() -> None:
    """The reason `scalar` takes a cffi array, rather than the mechanism.

    The failing branch derives, and the derivation asks for a scalar. So
    a caller holding the private key in memory it can wipe -- which is
    what `tests/test_secret.py` is about -- used to reach this branch and
    be told `the private key must be bytes or an int`: a type error about
    an argument they had passed correctly, in place of the one diagnosis
    this check exists to make.

    Both sides of that diagnosis are held here with the key in a buffer.
    The wrong public key is still a `ValueError` about the argument, and a
    fault under the right one is still the `RuntimeError` -- and the
    second needs the stand-in for the reason it always did: no input makes
    a fresh signature fail its own verification.
    """
    held = ffi.new("unsigned char[32]", PRVKEY_BYTES)

    other = keys.pubkey_from_prvkey(PRVKEY + 1, compressed=False)
    with pytest.raises(ValueError, match="not this private key's"):
        dsa.sign(MSG, held, pubkey=other)

    pubkey = keys.pubkey_from_prvkey(PRVKEY)
    with pytest.MonkeyPatch.context() as patch:
        _refuse_every_check(patch)
        with pytest.raises(RuntimeError, match=_UNVERIFIED):
            dsa.sign(MSG, held, pubkey=pubkey)

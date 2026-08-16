# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what libsecp256k1 reports through the callbacks of the context.

No wrapper reads those callbacks, so what they record is `context.check`'s
to raise and nobody else's. Two halves are tested here. That `check`
itself reports, clears and attributes per thread; and that a wrapper
handed an object libsecp256k1 cannot read answers *something* -- its own
exception where a return code allowed one, and otherwise a value that
means nothing -- while leaving the reason on the thread for a `check`
that follows.

The second half is the contract a caller has to know, so each of its
shapes is driven rather than described: a raise whose message is the
wrapper's own, a `False` from a verification, an ordering from a
comparison, and 32 bytes from an ECDH that succeeded with nobody. The
public entry points are the counter-case, parsing their octets and so
leaving the thread clean.

An internal error is reachable through neither: libsecp256k1 reports
through that callback what it holds to be unreachable, so the recording
function is called directly, the way test_extension.py drives the branch
of the loader that the build it runs on does not have.
"""

from __future__ import annotations

import threading

import pytest

from btclib_secp256k1 import context, dsa, ecdh, ffi, keys, lib, ssa, xonly
from btclib_secp256k1.context import ctx

# a public key libsecp256k1 is asked to parse into nowhere: the bindings
# always give it a buffer, a call through lib does not have to
NOWHERE_ARGS = (ffi.NULL, b"\x02" + b"\x01" * 32, 33)


def test_check_with_nothing_reported() -> None:
    """With nothing reported, check returns: that is the whole behaviour."""
    # nothing reported is not an error: returning is the whole behaviour
    context.check()


def test_illegal_argument() -> None:
    """An illegal argument reaches the caller as ValueError, with its text.

    Driven through `lib`, which all but two of the bindings' wrappers
    cannot do: they give libsecp256k1 bytes they have already checked.
    `keys.serialize` and `xonly.from_keypair` are the exceptions, and
    have tests of their own below.
    """
    assert not lib.secp256k1_ec_pubkey_parse(ctx, *NOWHERE_ARGS)
    with pytest.raises(ValueError, match="illegal argument: pubkey != NULL"):
        context.check()


def test_check_clears_what_it_reported() -> None:
    """A message is reported once, and not attributed to a later call.

    The second `check` returns, so what was raised is gone: left in
    place, it would surface out of whichever call came next and blame it
    for something it did not do.
    """
    assert not lib.secp256k1_ec_pubkey_parse(ctx, *NOWHERE_ARGS)
    with pytest.raises(ValueError, match="pubkey != NULL"):
        context.check()
    # the message is not reported twice, and cannot be attributed to a
    # later call which did not produce one
    context.check()


def test_serialize_raises_its_own_failure() -> None:
    """`keys.serialize` raises a bare failure, and the reason is on the thread.

    It takes the libsecp256k1 object the caller holds, so there is
    nothing to check about it before the call and the precondition is
    libsecp256k1's to violate. What reaches the caller is this wrapper's
    RuntimeError, the return code being all it read; which precondition
    was violated is what `check` answers after it, and a NULL pointer is
    the shortest way there.
    """
    with pytest.raises(RuntimeError, match="point serialization failed"):
        keys.serialize(ffi.NULL)
    with pytest.raises(ValueError, match="illegal argument: pubkey != NULL"):
        context.check()


def test_serialize_leaves_the_reason_on_the_thread() -> None:
    """And it leaves it there whether or not anybody comes to read it.

    A `secp256k1_pubkey` nothing has written to is the reachable form of
    the mistake: the message is about the zero field it finds, not about
    a pointer. Nothing clears it but a `check`, so the next one reports
    this call's message -- which is why `context.check` documents itself
    as belonging immediately after the call it explains.
    """
    with pytest.raises(RuntimeError, match="point serialization failed"):
        keys.serialize(ffi.new("secp256k1_pubkey *"))
    with pytest.raises(ValueError, match="illegal argument: !secp256k1_fe"):
        context.check()


def test_from_keypair_raises_its_own_failure() -> None:
    """`xonly.from_keypair` does as `keys.serialize` does, and for its reason.

    It takes the keypair the caller holds, so the precondition is
    libsecp256k1's to violate here too, and the conversion answering 0
    is all this wrapper reads. A NULL pointer names itself; a wiped
    keypair is the reachable mistake, and what libsecp256k1 reports of it
    is the zero it finds where the x of a point should be.
    """
    with pytest.raises(RuntimeError, match="x-only public key conversion failed"):
        xonly.from_keypair(ffi.NULL)
    with pytest.raises(ValueError, match="illegal argument: keypair != NULL"):
        context.check()

    signer = ssa.Signer(7)
    keypair = signer._keypair
    signer.wipe()
    with pytest.raises(RuntimeError, match="x-only public key conversion failed"):
        xonly.from_keypair(keypair)
    with pytest.raises(ValueError, match="illegal argument: !secp256k1_fe_is_zero"):
        context.check()


def test_verification_of_an_unreadable_key_is_false_not_a_verdict() -> None:
    """`dsa._verify_` answers False for a key libsecp256k1 cannot read.

    The same False a signature that does not verify gets, and the
    difference is on the thread rather than in the answer. This is the
    shape a caller has to know about: nothing raises, so a caller passing
    objects of its own reads a verdict that was never reached.
    """
    prvkey = (7).to_bytes(32, "big")
    msg = bytes(range(32))
    signature = dsa.parse_der(dsa.sign(msg, prvkey))

    assert dsa._verify_(msg, ffi.new("secp256k1_pubkey *"), signature) is False
    with pytest.raises(ValueError, match="illegal argument"):
        context.check()


def test_ecdh_with_an_unreadable_key_answers_a_secret_with_nobody() -> None:
    """`ecdh._shared_secret_` answers 32 bytes, and they are worth nothing.

    The gravest shape of the same contract, and the reason it is pinned
    here: the call succeeds, the answer is the right length, and nothing
    about it says the public key was one libsecp256k1 refused. Only the
    thread says so.
    """
    secret = ecdh._shared_secret_(ffi.new("secp256k1_pubkey *"), 7)

    assert isinstance(secret, bytes)
    assert len(secret) == 32
    with pytest.raises(ValueError, match="illegal argument"):
        context.check()


def test_comparison_of_unreadable_keys_is_an_ordering_like_any_other() -> None:
    """`keys._pubkey_cmp_` answers zero for two objects it could not read.

    Which is what it answers for two keys that are equal. The sum has the
    same shape and is checked with it: `_pubkey_sum_` answers None for the
    point at infinity and None for a key libsecp256k1 refused.
    """
    blank = ffi.new("secp256k1_pubkey *")

    assert keys._pubkey_cmp_(blank, blank) == 0
    with pytest.raises(ValueError, match="illegal argument"):
        context.check()

    assert keys._pubkey_sum_([ffi.NULL]) is None
    with pytest.raises(ValueError, match="illegal argument"):
        context.check()


def test_the_public_entry_points_leave_the_thread_clean() -> None:
    """A caller who passes octets cannot reach any of that.

    `verify` and `pubkey_tweak_add` parse what they are given, so the
    objects they hand libsecp256k1 are ones it has just built: a bad key
    is refused by the parse, with this package's own message, and nothing
    is recorded on the thread. That is the whole of why the shapes above
    belong to the private halves alone.
    """
    msg = bytes(range(32))
    not_a_point = b"\x02" + bytes(32)

    with pytest.raises(ValueError, match="invalid public key"):
        keys.pubkey_tweak_add(not_a_point, 7)
    context.check()

    with pytest.raises(ValueError, match="invalid public key"):
        dsa.verify(msg, not_a_point, dsa.sign(msg, 7))
    context.check()


def test_internal_error() -> None:
    """An internal error reaches the caller as RuntimeError.

    The recording function is called directly, that callback being how
    libsecp256k1 reports what it holds to be unreachable: there is no
    argument that provokes it.
    """
    context._record_error(ffi.new("char[]", b"deliberate"), ffi.NULL)
    with pytest.raises(RuntimeError, match="internal error: deliberate"):
        context.check()


def test_internal_error_comes_first() -> None:
    """With both reported, the internal error is the one raised.

    A broken invariant and a caller's mistake are not the same news, and
    the first is what has to be told. Both are cleared, so neither
    lingers to be raised by an unrelated call.
    """
    # an internal error is a broken invariant, an illegal argument is a
    # caller mistake: the first is what has to be reported
    context._record_illegal(ffi.new("char[]", b"argument"), ffi.NULL)
    context._record_error(ffi.new("char[]", b"invariant"), ffi.NULL)
    with pytest.raises(RuntimeError, match="invariant"):
        context.check()
    # and both are cleared, so neither lingers
    context.check()


def test_reported_per_thread() -> None:
    """What one thread reports is not another thread's to raise.

    A callback runs on the thread of the call that triggered it, so a
    second thread sees nothing and the first still has its message. This
    is what lets one shared context serve every thread.
    """
    # a callback runs on the thread of the call that triggered it, so
    # what one thread reports is not another thread's to raise
    assert not lib.secp256k1_ec_pubkey_parse(ctx, *NOWHERE_ARGS)

    elsewhere: list[str] = []

    def other_thread() -> None:
        # raises, were the message of the calling thread visible here,
        # and the assertion below then finds nothing appended
        context.check()
        elsewhere.append("nothing reported")

    thread = threading.Thread(target=other_thread)
    thread.start()
    thread.join()

    assert elsewhere == ["nothing reported"]
    # the calling thread still has it
    with pytest.raises(ValueError, match="pubkey != NULL"):
        context.check()

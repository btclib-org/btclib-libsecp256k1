# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what libsecp256k1 reports through the callbacks of the context.

An illegal argument is reachable through `lib`, and through the one
wrapper that takes a libsecp256k1 object rather than bytes; both are
driven here. An internal error is not: libsecp256k1 reports through that
callback what it holds to be unreachable, so the recording function is
called directly, the way test_extension.py drives the branch of the
loader that the build it runs on does not have.
"""

from __future__ import annotations

import threading

import pytest

from btclib_secp256k1 import context, ffi, keys, lib
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

    Driven through `lib`, which all but one of the bindings' wrappers
    cannot do: they give libsecp256k1 bytes they have already checked.
    `keys.serialize` is the exception, and has a test of its own below.
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


def test_serialize_raises_what_was_reported() -> None:
    """`keys.serialize` raises the message, rather than a bare failure.

    It takes the libsecp256k1 object the caller holds, so there is
    nothing to check about it before the call and the precondition is
    libsecp256k1's to violate. A NULL pointer is the shortest way there;
    what comes back names it.
    """
    with pytest.raises(ValueError, match="illegal argument: pubkey != NULL"):
        keys.serialize(ffi.NULL)


def test_serialize_leaves_nothing_on_the_thread() -> None:
    """And what it raised is not left for the next caller to be blamed for.

    A `secp256k1_pubkey` nothing has written to is the reachable form of
    the mistake: the message is about the zero field it finds, not about
    a pointer. Left on the thread, it would come back out of the next
    `check` -- which is the one a MuSig2 caller makes through `lib`,
    about a call of their own.
    """
    with pytest.raises(ValueError, match="illegal argument"):
        keys.serialize(ffi.new("secp256k1_pubkey *"))
    # raising it took it off the thread: this reports nothing
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

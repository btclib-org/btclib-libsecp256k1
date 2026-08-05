# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what libsecp256k1 reports through the callbacks of the context.

An illegal argument is reachable through `lib` and driven that way here.
An internal error is not: libsecp256k1 reports through that callback what
it holds to be unreachable, so the recording function is called directly,
the way test_extension.py drives the branch of the loader that the build
it runs on does not have.
"""

from __future__ import annotations

import threading

import pytest

from btclib_libsecp256k1 import context, ffi, lib
from btclib_libsecp256k1.context import ctx

# a public key libsecp256k1 is asked to parse into nowhere: the bindings
# always give it a buffer, a call through lib does not have to
NOWHERE_ARGS = (ffi.NULL, b"\x02" + b"\x01" * 32, 33)


def test_check_with_nothing_reported() -> None:
    """With nothing reported, check returns: that is the whole behaviour."""
    # nothing reported is not an error: returning is the whole behaviour
    context.check()


def test_illegal_argument() -> None:
    """An illegal argument reaches the caller as ValueError, with its text.

    Driven through `lib`, which the bindings' own wrappers cannot do:
    they always give libsecp256k1 the buffer it asks for.
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

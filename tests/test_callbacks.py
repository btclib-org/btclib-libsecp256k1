# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

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
    # nothing reported is not an error: returning is the whole behaviour
    context.check()


def test_illegal_argument() -> None:
    assert not lib.secp256k1_ec_pubkey_parse(ctx, *NOWHERE_ARGS)
    with pytest.raises(ValueError, match="illegal argument: pubkey != NULL"):
        context.check()


def test_check_clears_what_it_reported() -> None:
    assert not lib.secp256k1_ec_pubkey_parse(ctx, *NOWHERE_ARGS)
    with pytest.raises(ValueError, match="pubkey != NULL"):
        context.check()
    # the message is not reported twice, and cannot be attributed to a
    # later call which did not produce one
    context.check()


def test_internal_error() -> None:
    context._record_error(ffi.new("char[]", b"deliberate"), ffi.NULL)
    with pytest.raises(RuntimeError, match="internal error: deliberate"):
        context.check()


def test_internal_error_comes_first() -> None:
    # an internal error is a broken invariant, an illegal argument is a
    # caller mistake: the first is what has to be reported
    context._record_illegal(ffi.new("char[]", b"argument"), ffi.NULL)
    context._record_error(ffi.new("char[]", b"invariant"), ffi.NULL)
    with pytest.raises(RuntimeError, match="invariant"):
        context.check()
    # and both are cleared, so neither lingers
    context.check()


def test_reported_per_thread() -> None:
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

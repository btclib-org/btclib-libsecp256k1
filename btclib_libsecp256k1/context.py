# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Shared libsecp256k1 context, and what it reports through its callbacks."""

from __future__ import annotations

import secrets
import threading

from . import CData, ffi, lib

# 1 is SECP256K1_CONTEXT_NONE: since libsecp256k1 0.2 signing and
# verification work with any context, and the SIGN/VERIFY flags are
# deprecated
ctx = lib.secp256k1_context_create(1)


class _Reported(threading.local):
    """What libsecp256k1 last reported on the calling thread.

    A callback runs on the thread of the call that triggered it, so a
    thread local is what attributes a message to the right call.

    Attributes:
        illegal: the last violated precondition, or None.
        error: the last internal error, or None.
    """

    illegal: str | None = None
    error: str | None = None


_reported = _Reported()


def _record_illegal(message: CData, data: CData) -> None:
    """Record a violated precondition. Called by libsecp256k1.

    Args:
        message: the failed condition, as a C string.
        data: the pointer the callback was registered with, NULL here.
    """
    _reported.illegal = ffi.string(message).decode()


def _record_error(message: CData, data: CData) -> None:
    """Record an internal error. Called by libsecp256k1.

    Args:
        message: the failed condition, as a C string.
        data: the pointer the callback was registered with, NULL here.
    """
    _reported.error = ffi.string(message).decode()


# libsecp256k1 reports a violated precondition (an illegal argument, an
# object in an invalid state) through the illegal callback and an
# internal error through the error one, then returns 0. Its abort()ing
# defaults are replaced, in the vendored build, by stubs that do nothing:
# that keeps an illegal argument from taking the hosting process down,
# but leaves the caller with a bare 0 and no reason for it.
#
# On the shared context the callbacks instead record what was reported,
# so that check() can raise it. The reference to the cffi callback has to
# outlive the context, hence the module level names
_illegal_callback = ffi.callback("void(*)(const char *, void *)", _record_illegal)
_error_callback = ffi.callback("void(*)(const char *, void *)", _record_error)
lib.secp256k1_context_set_illegal_callback(ctx, _illegal_callback, ffi.NULL)
lib.secp256k1_context_set_error_callback(ctx, _error_callback, ffi.NULL)

# re-blind the signing precomputation, protecting against side-channel
# leakage, as recommended by libsecp256k1
if not lib.secp256k1_context_randomize(ctx, secrets.token_bytes(32)):
    raise RuntimeError("libsecp256k1 context randomization failed")


def check() -> None:
    """Raise what libsecp256k1 reported on this thread, if anything.

    The message is the failed precondition itself, as libsecp256k1
    stringifies the condition of its own check: signing twice with the
    same MuSig2 secret nonce, for one, is reported as the failed magic
    check of the nonce that the first signature zeroed.

    The bindings validate their arguments before calling, so a violated
    precondition is unreachable through them and none of them calls
    this. It is meant for a call made through `lib` directly, as a
    MuSig2 session is, and it reports what was last recorded: call it
    right after the call whose return value you are explaining.

    What was recorded is cleared, so a second call reports nothing and
    a later one cannot inherit this call's message.

    Raises:
        ValueError: if libsecp256k1 reported a violated precondition.
        RuntimeError: if it reported an internal error, which takes
            precedence, being the graver of the two.
    """
    illegal, error = _reported.illegal, _reported.error
    _reported.illegal = _reported.error = None
    if error is not None:
        raise RuntimeError(f"libsecp256k1 internal error: {error}")
    if illegal is not None:
        raise ValueError(f"libsecp256k1 illegal argument: {illegal}")

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Shared libsecp256k1 context, and what it reports through its callbacks."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Iterator
from contextlib import contextmanager

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


def _randomize(context: CData) -> None:
    """Re-blind the signing precomputation of that context.

    Protects against side-channel leakage, as libsecp256k1 recommends,
    and is called below on the shared context at import time.

    Repeating it is a caller's to do and needs exclusive access to the
    context: this is one of the few libsecp256k1 calls that mutates one,
    and the header says to randomize at creation time -- which is what
    happens below -- or to hold a read-write lock. Everything else in
    these bindings is safe to call from several threads *because* the
    shared context is randomized once, before any of them exists, so a
    second call on `ctx` while another thread is signing takes that
    guarantee away. See the Thread safety section of the README.

    The context is an argument rather than the module-level `ctx` for
    the same reason `_load_lib` takes the module: a line called once, at
    import, is a line no test can reach afterwards -- and what is worth
    reaching here is the 32, an entropy requirement of
    secp256k1_context_randomize that no answer this package returns
    would reveal if it were wrong.

    Args:
        context: the libsecp256k1 context to re-blind.

    Raises:
        RuntimeError: if libsecp256k1 fails, which a 32-octet seed
            cannot make it do.
    """
    if not lib.secp256k1_context_randomize(context, secrets.token_bytes(32)):
        raise RuntimeError("libsecp256k1 context randomization failed")


_randomize(ctx)


def check() -> None:
    """Raise what libsecp256k1 reported on this thread, if anything.

    The message is the failed precondition itself, as libsecp256k1
    stringifies the condition of its own check: signing twice with the
    same MuSig2 secret nonce, for one, is reported as the failed magic
    check of the nonce that the first signature zeroed.

    It is meant for a call made through `lib` directly, as a MuSig2
    session is, and it reports what was last recorded: call it right
    after the call whose return value you are explaining.

    The wrappers do not need it where they hand libsecp256k1 bytes,
    having proved those bytes first; where they hand it an object the
    caller built, they cannot prove anything and run the call inside
    `guarded` below, which is what calls this. So a violated
    precondition raised through a wrapper is this message, and no
    wrapper leaves one on the thread for the next caller to be blamed
    for.

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


@contextmanager
def guarded() -> Iterator[None]:
    """Run a libsecp256k1 call whose argument could not be checked first.

    Every argument these bindings pass as bytes is proved before the
    call, a bare pointer's length being what no C return code can
    report. An argument that is a libsecp256k1 object is the case that
    cannot be: `keys.serialize` takes a public key, `xonly.from_keypair`
    a keypair, and every private half takes what a `parse` returned, and
    of none of them is there anything to ask before handing it over. So
    what answers for those is libsecp256k1 itself, through the illegal
    callback, and this is how what it says reaches the caller.

    Both halves are here because either alone is a bug. The clearing is
    what makes the message this call's own: recorded and left by an
    earlier call, one would be raised out of this one, which is the
    misattribution `check` exists to prevent. The `check` is what makes
    the failure speak: `secp256k1_ec_pubkey_negate` of a pointer to
    nothing returns 0 like any other refusal, and the reason it returns
    0 is on the thread and nowhere else.

    And it is called whatever the call answered, not only on a failure,
    because a violated precondition does not always show in the return
    value: `secp256k1_ecdsa_verify` of an unreadable key answers False,
    which is a verdict a caller would believe, and
    `secp256k1_ecdh` of one answers success and 32 bytes that are a
    shared secret with nobody.

    Yields:
        None: nothing, the block being what this is for. It should hold
        that call and nothing else -- an exception raised inside it
        passes through with the thread left as libsecp256k1 set it.

    Raises:
        ValueError: if libsecp256k1 reported a violated precondition.
        RuntimeError: if it reported an internal error.

    Example:
        >>> from btclib_secp256k1 import ffi, keys
        >>> keys.serialize(ffi.NULL)
        Traceback (most recent call last):
        ValueError: libsecp256k1 illegal argument: pubkey != NULL
    """
    _reported.illegal = _reported.error = None
    yield
    check()

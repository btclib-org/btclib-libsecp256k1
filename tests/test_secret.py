# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The buffers a secret passes through are overwritten before being dropped.

What the wrappers do with these is invisible from their answers -- the
buffer is a local, and it is gone by the time a caller could look -- so
the two functions are driven here directly, on the two shapes they are
given: the `char[32]` a tweaked private key comes back in, and the
`secp256k1_keypair` a BIP340 signature is made with.
"""

from __future__ import annotations

import array
import ast
import importlib
import inspect
import mmap
import pkgutil
from types import FunctionType

import pytest

import btclib_secp256k1
from btclib_secp256k1 import (
    _secret,
    dsa,
    ecdh,
    ellswift,
    ffi,
    keys,
    lib,
    ssa,
    xonly,
)
from btclib_secp256k1.context import ctx

SECRET = b"\x07" * 32


def _calls(function: FunctionType) -> set[str]:
    """Return the names a function calls, read off its syntax tree.

    Off the tree and not out of the text, because a mention is not a
    call: `keys.pubkey_tweak_add`'s docstring writes
    `prvkey_tweak_add(k, t)` to say what the private-key side does with
    the same tweak, and a source matched as text answers that a
    public-key call produces a private key.

    Args:
        function: the function to read.

    Returns:
        The bare names, `keys.parse` and `parse` alike: what the walk
        below asks is which function was called, not through which
        module it was reached.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(function))):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                names.add(node.func.attr)
            elif isinstance(node.func, ast.Name):
                names.add(node.func.id)
    return names


def test_take_reads_the_secret_out_and_zeroes_the_buffer() -> None:
    """What the caller gets is the secret; what is left is zeros."""
    buffer = ffi.new("char[32]", SECRET)

    assert _secret.take(buffer) == SECRET
    assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))


def test_wipe_asks_the_buffer_for_its_own_size() -> None:
    """A keypair is wiped whole, and it is larger than the pointer to it.

    This is the reason the length is taken from `ffi.buffer` rather than
    from `ffi.sizeof`: on a `secp256k1_keypair *` the latter answers 8,
    the size of the pointer, and wiping 8 octets would clear the first
    quarter of the private key and leave the rest -- while every
    assertion about the call still passed.
    """
    keypair = ffi.new("secp256k1_keypair *")
    assert lib.secp256k1_keypair_create(ctx, keypair, SECRET)

    memory = ffi.buffer(keypair)
    # the private key is in there, and there is more of the struct than
    # there is of a pointer to it
    assert SECRET in bytes(memory)
    assert len(memory) > ffi.sizeof(keypair)

    _secret.wipe(keypair)
    assert bytes(memory) == bytes(len(memory))


def test_take_writes_into_the_caller_s_buffer_and_returns_nothing() -> None:
    """With `into` the secret lands where the caller can overwrite it.

    Which is the whole of what the argument is for: a `bytes` holds the
    same secret and cannot be zeroed, so the copy this package has to
    make is made somewhere the caller owns.
    """
    buffer = ffi.new("char[32]", SECRET)
    into = bytearray(32)

    assert _secret.take(buffer, into=into) is None
    assert bytes(into) == SECRET
    # this package's own buffer is wiped either way
    assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))
    # and the caller can do what a bytes would not have let them
    into[:] = bytes(32)
    assert bytes(into) == bytes(32)


def test_take_into_a_writable_memoryview() -> None:
    """A memoryview of a bytearray is the other spelling, and writes through."""
    buffer = ffi.new("char[32]", SECRET)
    owner = bytearray(32)

    assert _secret.take(buffer, into=memoryview(owner)) is None
    assert bytes(owner) == SECRET


def test_take_refuses_a_buffer_of_the_wrong_length() -> None:
    """And wipes its own buffer anyway, the refusal being no reason not to.

    A longer buffer is the one worth refusing rather than filling: the
    secret would sit in its first octets with whatever was already there
    behind it, which reads as a secret that is not this one.

    What the second assertion holds is the finding this test was written
    the wrong way round for: the value never reached the caller, so
    keeping it costs them nothing and leaves a live private key in cffi
    memory that is freed without being overwritten.
    """
    for wrong in (bytearray(31), bytearray(33)):
        buffer = ffi.new("char[32]", SECRET)
        with pytest.raises(ValueError, match="must be 32 bytes"):
            _secret.take(buffer, into=wrong)
        assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))
        assert bytes(wrong) == bytes(len(wrong))


def test_take_refuses_a_buffer_it_cannot_write() -> None:
    """A read-only view would defeat the facility silently, so it is refused.

    `bytes` is the same mistake spelled shorter, and reaches the same
    refusal through `readonly` rather than through a type check. An
    `int` is not a buffer at all, and `memoryview` is what says so.
    """
    wrong: list[tuple[object, str]] = [
        (memoryview(bytes(32)), "must be writable"),
        (b"\x00" * 32, "must be writable"),
        (7, "must be a writable buffer, not int"),
    ]
    for value, message in wrong:
        buffer = ffi.new("char[32]", SECRET)
        with pytest.raises(TypeError, match=message):
            _secret.take(buffer, into=value)  # type: ignore[call-overload]
        assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))


def test_take_accepts_any_writable_contiguous_buffer() -> None:
    """An mmap and an array of octets are destinations too, and are taken.

    The refusals are about what a buffer *is*, not about which class
    produced it: an `mlock`ed `mmap` is a plausible place for the caller
    this argument exists for to want a secret. `MutableBytesLike` names
    the two a typed caller passes bare, `collections.abc.Buffer` being
    3.12 where the floor here is 3.10; anything else is wrapped in a
    `memoryview`, which costs nothing and is what these two do.
    """
    with mmap.mmap(-1, 32) as anonymous:
        buffer = ffi.new("char[32]", SECRET)
        assert _secret.take(buffer, into=memoryview(anonymous)) is None
        assert anonymous[:] == SECRET

    octets = array.array("B", bytes(32))
    buffer = ffi.new("char[32]", SECRET)
    assert _secret.take(buffer, into=memoryview(octets)) is None
    assert octets.tobytes() == SECRET


def test_take_refuses_a_buffer_that_is_not_contiguous_octets() -> None:
    """Two shapes that pass every other check, one of which used to crash.

    A two-dimensional view is writable, octet-wide and 32 octets long,
    and the copy through it raises `NotImplementedError` -- neither of
    the exceptions the caller was told to expect. A strided one works,
    and is refused all the same: the secret would land scattered through
    64 octets of an owner whose other 32 nothing says are involved.
    """
    for wrong in (
        memoryview(bytearray(32)).cast("B", (4, 8)),
        memoryview(bytearray(64))[::2],
    ):
        buffer = ffi.new("char[32]", SECRET)
        with pytest.raises(TypeError, match="must be contiguous octets"):
            _secret.take(buffer, into=wrong)
        assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))


def test_take_refuses_a_view_of_wider_items() -> None:
    """Eight uint32 are 32 octets of nobody's byte order.

    `memoryview.cast("B")` is how a caller says the octets are what they
    meant, which is the rule `_scalar.octets` states on the way in.
    """
    buffer = ffi.new("char[32]", SECRET)
    wide = memoryview(bytearray(32)).cast("I")
    with pytest.raises(TypeError, match="not of 4-byte items"):
        _secret.take(buffer, into=wide)
    assert ffi.unpack(buffer, ffi.sizeof(buffer)) == bytes(ffi.sizeof(buffer))


def test_every_function_that_takes_a_secret_out_offers_into() -> None:
    """Found by walking the package, so that a ninth producer is caught.

    A hardcoded list of the eight cannot notice a ninth, which is what
    this test is for; `_secret.take` is the one thing every producer of
    a secret has in common, so its call sites are the population. They
    are not the whole of it: a public half answers the secret its
    private half read out, without calling `take` itself, so whatever
    calls a producer is asked the same question -- `ecdh.shared_secret`
    is that shape, and being caught by its own name is what keeps a
    ninth written that way from being checked by hand. Two names are
    exempt, and naming them here is what keeps SECURITY.md's sentence
    honest.

    What the walk cannot see is a secret that never goes through `take`
    at all: `silentpayments._found_output` reads the per-output tweak
    out of the struct as a `bytes` of its own, so no population defined
    this way can contain it, and SECURITY.md names it for that reason.
    """
    # the tweak of a label, in both halves that answer it: it is one
    # member of a returned tuple, where an argument could not say which
    # it names; SECURITY.md says so too
    exempt = {"_label_", "label"}
    functions: dict[tuple[str, str], FunctionType] = {}
    called: dict[tuple[str, str], set[str]] = {}
    for info in pkgutil.iter_modules(btclib_secp256k1.__path__):
        module = importlib.import_module(f"btclib_secp256k1.{info.name}")
        for name, function in vars(module).items():
            if (
                not inspect.isfunction(function)
                or function.__module__ != module.__name__
            ):
                continue
            try:
                called[info.name, name] = _calls(function)
            except OSError:  # pragma: no cover - source ships with the wheel
                continue
            functions[info.name, name] = function

    producers = {key for key, names in called.items() if "take" in names}
    assert producers, "no call site of _secret.take was found: the walk is broken"
    forwarders = {
        key for key, names in called.items() if names & {name for _, name in producers}
    }
    for key in sorted(producers | forwarders):
        if key[1] in exempt:
            continue
        assert "into" in inspect.signature(functions[key]).parameters, (
            f"{key[0]}.{key[1]} has no into"
        )
    assert exempt <= {name for _, name in producers | forwarders}, (
        "an exemption names a function that no longer answers a secret"
    )


def test_the_two_spellings_of_a_producer_agree() -> None:
    """Each entry point answers through `into` what it answers as bytes."""
    ell = ellswift.create(2, bytes(32))
    calls = (
        (keys.prvkey_negate, (7,)),
        (keys.prvkey_tweak_add, (7, 3)),
        (keys.prvkey_tweak_mul, (7, 3)),
        (xonly.prvkey_tweak_add, (7, 3)),
        (ecdh.shared_secret, (keys.pubkey_from_prvkey(3), 7)),
        (ellswift.xdh, (ell, ell, 2, 0)),
        (dsa.nonce_rfc6979, (bytes(32), 7)),
        (ssa.nonce_bip340, (bytes(32), 7, bytes(32))),
    )
    for call, args in calls:
        into = bytearray(32)
        assert call(*args, into=into) is None, call.__name__
        assert bytes(into) == call(*args), call.__name__

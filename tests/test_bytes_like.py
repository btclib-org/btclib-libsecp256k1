# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every argument that takes bytes takes a bytearray and a memoryview.

The check is a normalization, so it has to be the normalized value that
reaches libsecp256k1: a call site that checks its argument and then
passes the one it was given would still hand cffi a bytearray, and cffi
would refuse it. Nothing in the answers distinguishes the two, so this
drives every entry point taking such an argument with each of the three
types and asserts one answer -- which is what makes a call site that
checks without assigning fail here rather than in a caller's code.

The sweep is written as data so that a function added to the boundary
and not added here is visible as an absence: `test_the_sweep_is_whole`
holds it to the modules' own contents.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from btclib_libsecp256k1 import (
    dsa,
    ecdh,
    ellswift,
    hashes,
    keys,
    mult,
    recovery,
    ssa,
    xonly,
)

PRVKEY = (7).to_bytes(32, "big")
TWEAK = (11).to_bytes(32, "big")
MSG = b"\x01" * 32
PUBKEY = keys.pubkey_from_prvkey(PRVKEY)
PUBKEY_LONG = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
XONLY, PARITY = xonly.from_pubkey(PUBKEY)
DER = dsa.sign(MSG, PRVKEY)
COMPACT = dsa.to_compact(DER)
SSA_SIG = ssa.sign(MSG, PRVKEY, bytes(32))
RECOVERABLE, RECID = recovery.sign(MSG, PRVKEY)
ELL_A = ellswift.create(PRVKEY, bytes(32))
ELL_B = ellswift.create(TWEAK, bytes(32))
TWEAKED, TWEAKED_PARITY = xonly.tweak_add(XONLY, TWEAK)

# every entry point taking an argument that crosses as a bare pointer,
# with the arguments it takes: the bytes ones are retyped below
CALLS: list[tuple[str, Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = [
    ("keys.prvkey_verify", keys.prvkey_verify, (PRVKEY,), {}),
    ("keys.prvkey_negate", keys.prvkey_negate, (PRVKEY,), {}),
    ("keys.prvkey_tweak_add", keys.prvkey_tweak_add, (PRVKEY, TWEAK), {}),
    ("keys.prvkey_tweak_mul", keys.prvkey_tweak_mul, (PRVKEY, TWEAK), {}),
    ("keys.pubkey_from_prvkey", keys.pubkey_from_prvkey, (PRVKEY,), {}),
    ("keys.pubkey_negate", keys.pubkey_negate, (PUBKEY,), {}),
    ("keys.pubkey_tweak_add", keys.pubkey_tweak_add, (PUBKEY, TWEAK), {}),
    ("keys.pubkey_tweak_mul", keys.pubkey_tweak_mul, (PUBKEY, TWEAK), {}),
    ("keys.pubkey_combine", keys.pubkey_combine, ([PUBKEY, PUBKEY_LONG],), {}),
    ("keys.pubkey_cmp", keys.pubkey_cmp, (PUBKEY, PUBKEY_LONG), {}),
    ("keys.pubkey_sort", keys.pubkey_sort, ([PUBKEY, PUBKEY_LONG],), {}),
    ("mult.mult_", mult.mult_, (PRVKEY,), {}),
    ("mult.mult", mult.mult, (PRVKEY,), {}),
    ("hashes.tagged_sha256", hashes.tagged_sha256, (b"TapLeaf", MSG), {}),
    ("dsa.sign", dsa.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("dsa.verify", dsa.verify, (MSG, PUBKEY, DER), {}),
    ("dsa.normalize", dsa.normalize, (DER,), {}),
    ("dsa.is_low_s", dsa.is_low_s, (DER,), {}),
    ("dsa.to_compact", dsa.to_compact, (DER,), {}),
    ("dsa.to_der", dsa.to_der, (COMPACT,), {}),
    ("ssa.sign", ssa.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("ssa.sign_custom", ssa.sign_custom, (b"a message", PRVKEY, bytes(32)), {}),
    ("ssa.verify", ssa.verify, (MSG, XONLY, SSA_SIG), {}),
    ("xonly.from_pubkey", xonly.from_pubkey, (PUBKEY,), {}),
    ("xonly.tweak_add", xonly.tweak_add, (XONLY, TWEAK), {}),
    (
        "xonly.tweak_add_check",
        xonly.tweak_add_check,
        (TWEAKED, TWEAKED_PARITY, XONLY, TWEAK),
        {},
    ),
    ("xonly.prvkey_tweak_add", xonly.prvkey_tweak_add, (PRVKEY, TWEAK), {}),
    ("recovery.sign", recovery.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("recovery.recover", recovery.recover, (MSG, RECOVERABLE, RECID), {}),
    ("recovery.to_der", recovery.to_der, (RECOVERABLE, RECID), {}),
    ("ecdh.shared_secret", ecdh.shared_secret, (PUBKEY, PRVKEY), {}),
    ("ellswift.create", ellswift.create, (PRVKEY, bytes(32)), {}),
    ("ellswift.encode", ellswift.encode, (PUBKEY, bytes(32)), {}),
    ("ellswift.decode", ellswift.decode, (ELL_A,), {}),
    ("ellswift.xdh", ellswift.xdh, (ELL_A, ELL_B, PRVKEY, 0), {}),
]

MODULES = {
    "dsa": dsa,
    "ecdh": ecdh,
    "ellswift": ellswift,
    "hashes": hashes,
    "keys": keys,
    "mult": mult,
    "recovery": recovery,
    "ssa": ssa,
    "xonly": xonly,
}

# the two that take no argument crossing as a bare pointer: `parse` takes
# one and is covered through every wrapper above, `serialize` takes the
# libsecp256k1 object `parse` hands back and no bytes at all
NOT_SWEPT = {"keys.serialize", "keys.parse"}


def retyped(value: Any, kind: type) -> Any:
    """Return the argument as a bytearray or a memoryview, if it is bytes.

    A list of them is retyped element by element, which is what the two
    functions taking a sequence of public keys are given.

    Args:
        value: one argument of a call below.
        kind: `bytearray` or `memoryview`.

    Returns:
        The same value in that type, or unchanged if it is not bytes.
    """
    if isinstance(value, bytes):
        return kind(value)
    if isinstance(value, list):
        return [retyped(item, kind) for item in value]
    return value


@pytest.mark.parametrize("kind", [bytearray, memoryview])
@pytest.mark.parametrize("name,call,args,kwargs", CALLS, ids=[c[0] for c in CALLS])
def test_answers_the_same_for_every_bytes_like(
    name: str,
    call: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    kind: type,
) -> None:
    """The answer does not depend on which of the three types was passed.

    Args:
        name: the entry point, for the test id.
        call: the entry point itself.
        args: its arguments, as bytes.
        kwargs: its keyword arguments.
        kind: the type to retype the bytes arguments to.
    """
    assert call(*args, **kwargs) == call(*(retyped(a, kind) for a in args), **kwargs)


def test_the_sweep_is_whole() -> None:
    """Every public function of every wrapped module is swept, or excused.

    A function added to the boundary and not added to `CALLS` is a hole
    this sweep would not cover and nothing else would report, so the
    list is checked against what the modules actually export rather than
    trusted to have been kept up to date.
    """
    swept = {name for name, *_ in CALLS} | NOT_SWEPT
    exported = {
        f"{module_name}.{name}"
        for module_name, module in MODULES.items()
        for name in dir(module)
        if not name.startswith("_")
        and callable(getattr(module, name))
        and getattr(getattr(module, name), "__module__", "")
        == f"btclib_libsecp256k1.{module_name}"
    }

    assert exported - swept == set()

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

from btclib_secp256k1 import (
    dsa,
    ecdh,
    ellswift,
    ffi,
    hashes,
    keys,
    recovery,
    silentpayments,
    ssa,
    xonly,
)

PRVKEY = (7).to_bytes(32, "big")
TWEAK = (11).to_bytes(32, "big")
MSG = b"\x01" * 32
PUBKEY = keys.pubkey_from_prvkey(PRVKEY)
PUBKEY_LONG = keys.pubkey_from_prvkey(PRVKEY, compressed=False)
XONLY, PARITY = xonly.from_pubkey(PUBKEY)
# the parsed forms the inner halves take, which are what those entry
# points have in place of the bytes rather than an argument to retype
PARSED = keys.parse(PUBKEY)
PARSED_XONLY = xonly.parse(XONLY)
DER = dsa.sign(MSG, PRVKEY)
PARSED_DER = dsa.parse_der(DER)
COMPACT = dsa.to_compact(DER)
SSA_SIG = ssa.sign(MSG, PRVKEY, bytes(32))
RECOVERABLE, RECID = recovery.sign(MSG, PRVKEY)
ELL_A = ellswift.create(PRVKEY, bytes(32))
ELL_B = ellswift.create(TWEAK, bytes(32))
TWEAKED, TWEAKED_PARITY = xonly.tweak_add(XONLY, TWEAK)

# a silent payment of the input PRVKEY funds to an address of its own,
# scanned back: the outpoint is zeros, which is a serialization like any
# other here, and PRVKEY's public key is the one input
SCAN_PRVKEY = (13).to_bytes(32, "big")
SPEND_PRVKEY = (17).to_bytes(32, "big")
SCAN_PUBKEY = keys.pubkey_from_prvkey(SCAN_PRVKEY)
SPEND_PUBKEY = keys.pubkey_from_prvkey(SPEND_PRVKEY)
OUTPOINT = bytes(36)
SP_OUTPUTS = silentpayments.create_outputs(
    [(SCAN_PUBKEY, SPEND_PUBKEY)], OUTPOINT, prvkeys=[PRVKEY]
)
SP_SUMMARY = silentpayments.prevouts_summary(OUTPOINT, pubkeys_bytes=[PUBKEY])
SP_LABEL, SP_LABEL_TWEAK = silentpayments.label(SCAN_PRVKEY, 0)


def signed(prvkey: Any, msg_bytes: Any, aux_rand32: Any) -> bytes:
    """Sign a 32-byte message hash through a signer, and wipe it.

    Args:
        prvkey: the private key to build the signer from.
        msg_bytes: the 32-byte message hash.
        aux_rand32: the 32 bytes of auxiliary randomness.

    Returns:
        The 64-byte signature.
    """
    with ssa.Signer(prvkey) as signer:
        return signer.sign(msg_bytes, aux_rand32)


def signed_custom(prvkey: Any, msg_bytes: Any, aux_rand32: Any) -> bytes:
    """Sign a message of any length through a signer, and wipe it.

    Args:
        prvkey: the private key to build the signer from.
        msg_bytes: the message.
        aux_rand32: the 32 bytes of auxiliary randomness.

    Returns:
        The 64-byte signature.
    """
    with ssa.Signer(prvkey) as signer:
        return signer.sign_custom(msg_bytes, aux_rand32)


def created(prvkey: Any) -> bytes:
    """Derive a public key through the inner half, and serialize it.

    Args:
        prvkey: the private key.

    Returns:
        The compressed public key, which is what the outer half answers.
    """
    return keys.serialize(keys._pubkey_from_prvkey_(prvkey))


def decoded(ell_bytes: Any) -> bytes:
    """Decode an ElligatorSwift key through the inner half, and serialize.

    Args:
        ell_bytes: the 64-byte encoding.

    Returns:
        The compressed public key.
    """
    return keys.serialize(ellswift._decode_(ell_bytes))


def recovered(msg_bytes: Any, signature_bytes: Any, recid: int) -> bytes:
    """Recover a public key through the inner half, and serialize it.

    Args:
        msg_bytes: the 32-byte message hash.
        signature_bytes: the 64-byte compact signature.
        recid: the recovery id.

    Returns:
        The compressed recovered public key.
    """
    return keys.serialize(
        recovery._recover_(msg_bytes, recovery.parse_compact(signature_bytes, recid))
    )


def labeled(scan_prvkey: Any, m: int) -> tuple[bytes, bytes]:
    """Create a label through the inner half, and serialize it.

    Args:
        scan_prvkey: the recipient's scan private key.
        m: which label.

    Returns:
        The 33-byte label and its 32-byte tweak, which is what the outer
        half answers.
    """
    label_obj, tweak = silentpayments._label_(scan_prvkey, m)
    return silentpayments.serialize_label(label_obj), tweak


def signed_dsa(msg_bytes: Any, prvkey: Any, aux_rand32: Any) -> bytes:
    """Sign through the private half, and serialize what it built.

    Args:
        msg_bytes: the 32-byte message hash.
        prvkey: the private key.
        aux_rand32: the 32 bytes of extra entropy.

    Returns:
        The DER signature, which is what the public half answers.
    """
    return dsa.serialize_der(dsa._sign_(msg_bytes, prvkey, aux_rand32))


def signed_recoverable(
    msg_bytes: Any, prvkey: Any, aux_rand32: Any
) -> tuple[bytes, int]:
    """Sign recoverably through the private half, and serialize the pair.

    Args:
        msg_bytes: the 32-byte message hash.
        prvkey: the private key.
        aux_rand32: the 32 bytes of extra entropy.

    Returns:
        The 64-byte compact signature and its recovery id.
    """
    return recovery.serialize_compact(recovery._sign_(msg_bytes, prvkey, aux_rand32))


def created_outputs(outpoint_smallest36: Any, prvkeys: Any) -> list[bytes]:
    """Create silent payment outputs through the private half.

    The recipient's keys are parsed here rather than retyped: what this
    sweeps is the outpoint and the private keys, which are the octets
    that half still takes.

    Args:
        outpoint_smallest36: the 36-byte smallest outpoint.
        prvkeys: the private keys of the eligible inputs.

    Returns:
        The 32-byte x-only key of each output.
    """
    return [
        xonly.serialize(output)
        for output in silentpayments._create_outputs_(
            [(keys.parse(SCAN_PUBKEY), keys.parse(SPEND_PUBKEY))],
            outpoint_smallest36,
            prvkeys=prvkeys,
        )
    ]


def summarized(outpoint_smallest36: Any) -> bytes:
    """Summarize the inputs through the private half, and read the struct.

    Args:
        outpoint_smallest36: the 36-byte smallest outpoint.

    Returns:
        The octets `prevouts_summary` answers with.
    """
    return bytes(
        ffi.buffer(
            silentpayments._prevouts_summary_(
                outpoint_smallest36, pubkeys=[keys.parse(PUBKEY)]
            )
        )
    )


def scanned(scan_prvkey: Any, labels: Any) -> list[tuple[bytes, bytes, bytes | None]]:
    """Scan the transaction through the private half.

    Args:
        scan_prvkey: the recipient's scan private key.
        labels: the label cache.

    Returns:
        One triple per output found.
    """
    return silentpayments._scan_outputs_(
        [xonly.parse(output) for output in SP_OUTPUTS],
        scan_prvkey,
        silentpayments._prevouts_summary_(OUTPOINT, pubkeys=[keys.parse(PUBKEY)]),
        keys.parse(SPEND_PUBKEY),
        labels,
    )


# every entry point taking an argument that crosses as a bare pointer,
# with the arguments it takes: the bytes ones are retyped below
CALLS: list[tuple[str, Callable[..., Any], tuple[Any, ...], dict[str, Any]]] = [
    ("keys.prvkey_verify", keys.prvkey_verify, (PRVKEY,), {}),
    ("keys.prvkey_negate", keys.prvkey_negate, (PRVKEY,), {}),
    ("keys.prvkey_tweak_add", keys.prvkey_tweak_add, (PRVKEY, TWEAK), {}),
    ("keys.prvkey_tweak_mul", keys.prvkey_tweak_mul, (PRVKEY, TWEAK), {}),
    ("keys.pubkey_from_prvkey", keys.pubkey_from_prvkey, (PRVKEY,), {}),
    # the producing inner halves answer with a cffi object, and two of
    # those are equal to nothing at all: each is driven through a
    # function above which serializes what it built, so what the sweep
    # compares is the bytes its outer half would have answered
    ("keys._pubkey_from_prvkey_", created, (PRVKEY,), {}),
    ("keys.pubkey_verify", keys.pubkey_verify, (PUBKEY,), {}),
    ("keys.pubkey_negate", keys.pubkey_negate, (PUBKEY,), {}),
    ("keys.pubkey_tweak_add", keys.pubkey_tweak_add, (PUBKEY, TWEAK), {}),
    ("keys.pubkey_tweak_mul", keys.pubkey_tweak_mul, (PUBKEY, TWEAK), {}),
    ("keys.pubkey_combine", keys.pubkey_combine, ([PUBKEY, PUBKEY_LONG],), {}),
    ("keys.reserialize", keys.reserialize, (PUBKEY,), {}),
    ("keys.pubkey_sum", keys.pubkey_sum, ([PUBKEY, PUBKEY_LONG],), {}),
    (
        "keys.pubkey_tweak_mul_sum",
        keys.pubkey_tweak_mul_sum,
        ([PUBKEY, PUBKEY_LONG], [TWEAK, TWEAK]),
        {},
    ),
    ("keys.pubkey_cmp", keys.pubkey_cmp, (PUBKEY, PUBKEY_LONG), {}),
    ("keys.pubkey_sort", keys.pubkey_sort, ([PUBKEY, PUBKEY_LONG],), {}),
    ("hashes.tagged_sha256", hashes.tagged_sha256, (b"TapLeaf", MSG), {}),
    ("dsa.sign", dsa.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("dsa.nonce_rfc6979", dsa.nonce_rfc6979, (MSG, PRVKEY, bytes(32)), {}),
    ("dsa.verify", dsa.verify, (MSG, PUBKEY, DER), {}),
    ("dsa._verify_", dsa._verify_, (MSG, PARSED, PARSED_DER), {}),
    ("dsa._sign_", signed_dsa, (MSG, PRVKEY, bytes(32)), {}),
    ("dsa.normalize", dsa.normalize, (DER,), {}),
    ("dsa.is_low_s", dsa.is_low_s, (DER,), {}),
    ("dsa.is_low_r", dsa.is_low_r, (DER,), {}),
    ("dsa.signature_verify", dsa.signature_verify, (DER,), {}),
    ("dsa.to_compact", dsa.to_compact, (DER,), {}),
    ("dsa.to_der", dsa.to_der, (COMPACT,), {}),
    ("ssa.sign", ssa.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("ssa.nonce_bip340", ssa.nonce_bip340, (MSG, PRVKEY, bytes(32)), {}),
    ("ssa.sign_custom", ssa.sign_custom, (b"a message", PRVKEY, bytes(32)), {}),
    # the signer's own two, which is where its three bytes-like arguments
    # are: the private key the constructor takes, and the message and aux
    # of each signature. Driven through the two functions below, so that
    # what is compared is a signature rather than the object holding the
    # keypair -- and so that the keypair is wiped, as it is anywhere else
    ("ssa.Signer.sign", signed, (PRVKEY, MSG, bytes(32)), {}),
    ("ssa.Signer.sign_custom", signed_custom, (PRVKEY, b"a message", bytes(32)), {}),
    ("ssa.verify", ssa.verify, (MSG, XONLY, SSA_SIG), {}),
    ("ssa._verify_", ssa._verify_, (MSG, PARSED_XONLY, SSA_SIG), {}),
    ("xonly.pubkey_verify", xonly.pubkey_verify, (XONLY,), {}),
    ("xonly.to_pubkey", xonly.to_pubkey, (XONLY,), {}),
    ("xonly.from_pubkey", xonly.from_pubkey, (PUBKEY,), {}),
    ("xonly.from_prvkey", xonly.from_prvkey, (PRVKEY,), {}),
    ("xonly.tweak_add", xonly.tweak_add, (XONLY, TWEAK), {}),
    # the parsed key is not retyped, being no bytes; the tweak beside it
    # is, and what comes back is 32 bytes and a parity, which compare
    ("xonly._tweak_add_", xonly._tweak_add_, (PARSED, TWEAK), {}),
    (
        "xonly.tweak_add_check",
        xonly.tweak_add_check,
        (TWEAKED, TWEAKED_PARITY, XONLY, TWEAK),
        {},
    ),
    ("xonly.prvkey_tweak_add", xonly.prvkey_tweak_add, (PRVKEY, TWEAK), {}),
    ("recovery.sign", recovery.sign, (MSG, PRVKEY, bytes(32)), {}),
    ("recovery._sign_", signed_recoverable, (MSG, PRVKEY, bytes(32)), {}),
    ("recovery.recover", recovery.recover, (MSG, RECOVERABLE, RECID), {}),
    ("recovery._recover_", recovered, (MSG, RECOVERABLE, RECID), {}),
    ("recovery.to_der", recovery.to_der, (RECOVERABLE, RECID), {}),
    ("ecdh.shared_secret", ecdh.shared_secret, (PUBKEY, PRVKEY), {}),
    ("ecdh._shared_secret_", ecdh._shared_secret_, (PARSED, PRVKEY), {}),
    ("ellswift.create", ellswift.create, (PRVKEY, bytes(32)), {}),
    ("ellswift.encode", ellswift.encode, (PUBKEY, bytes(32)), {}),
    # the parsed key is not retyped, being no bytes; the randomness
    # beside it is, and pinning it is what makes two encodings comparable
    ("ellswift._encode_", ellswift._encode_, (PARSED, bytes(32)), {}),
    ("ellswift.decode", ellswift.decode, (ELL_A,), {}),
    ("ellswift._decode_", decoded, (ELL_A,), {}),
    ("ellswift.xdh", ellswift.xdh, (ELL_A, ELL_B, PRVKEY, 0), {}),
    # the silentpayments arguments are passed positionally, keyword
    # defaults though they are: what is retyped below is `args`, so a
    # sequence of keys handed in as a keyword would be swept as bytes and
    # the sweep would say it passed
    (
        "silentpayments.create_outputs",
        silentpayments.create_outputs,
        ([(SCAN_PUBKEY, SPEND_PUBKEY)], OUTPOINT, (), [PRVKEY]),
        {},
    ),
    ("silentpayments._create_outputs_", created_outputs, (OUTPOINT, [PRVKEY]), {}),
    ("silentpayments.label", silentpayments.label, (SCAN_PRVKEY, 0), {}),
    ("silentpayments._label_", labeled, (SCAN_PRVKEY, 0), {}),
    (
        "silentpayments.labeled_spend_pubkey",
        silentpayments.labeled_spend_pubkey,
        (SPEND_PUBKEY, SP_LABEL),
        {},
    ),
    ("silentpayments._prevouts_summary_", summarized, (OUTPOINT,), {}),
    (
        "silentpayments._scan_outputs_",
        scanned,
        (SCAN_PRVKEY, {SP_LABEL: SP_LABEL_TWEAK}),
        {},
    ),
    (
        "silentpayments.prevouts_summary",
        silentpayments.prevouts_summary,
        (OUTPOINT, (), [PUBKEY]),
        {},
    ),
    (
        "silentpayments.scan_outputs",
        silentpayments.scan_outputs,
        (
            SP_OUTPUTS,
            SCAN_PRVKEY,
            SP_SUMMARY,
            SPEND_PUBKEY,
            {SP_LABEL: SP_LABEL_TWEAK},
        ),
        {},
    ),
]

MODULES = {
    "dsa": dsa,
    "ecdh": ecdh,
    "ellswift": ellswift,
    "hashes": hashes,
    "keys": keys,
    "recovery": recovery,
    "silentpayments": silentpayments,
    "ssa": ssa,
    "xonly": xonly,
}

# the ones that take no argument crossing as a bare pointer, or nothing
# this sweep has not already exercised. Every `parse` takes one and is
# covered through the wrappers above -- `keys.parse` and `xonly.parse`
# through all of them, `dsa.parse_der` through `dsa.normalize`,
# `dsa.parse_compact` through `dsa.to_der`, `recovery.parse_compact`
# through `recovery.recover`, `parse_label` through
# `silentpayments.labeled_spend_pubkey` -- and what each answers with is
# a cffi object, which is equal to no other. Every `serialize` is the
# other side of that: it takes the object and no bytes at all, as do the
# private halves listed here, whose sequences and structs hold those same
# objects. The two tweaking private halves do take a tweak, and it is the
# retyped one of `keys.pubkey_tweak_add` and `keys.pubkey_tweak_mul`
# above, which pass theirs straight in: what they answer with is the
# parsed key they mutated, and two calls of it are never equal.
# `PubkeyTweakChain` is the same, calling `parse` on construction and
# reaching `scalar` through `_pubkey_tweak_add_` on every `tweak_add`.
# `ssa.Signer` is a class too and its private key does cross as a bare
# pointer, but it is swept: the two entries above build one and sign
# through it, which is every argument of the constructor and of both
# methods
NOT_SWEPT = {
    "dsa.parse_compact",
    "dsa.parse_der",
    "dsa.serialize_compact",
    "dsa.serialize_der",
    "dsa._is_low_s_",
    "dsa._is_low_r_",
    "dsa._normalize_",
    "keys.parse",
    "keys.serialize",
    "keys.PubkeyTweakChain",
    "keys._pubkey_combine_",
    "keys._pubkey_cmp_",
    "keys._pubkey_negate_",
    "keys._pubkey_sort_",
    "keys._pubkey_sum_",
    "keys._pubkey_tweak_add_",
    "keys._pubkey_tweak_mul_",
    "recovery.parse_compact",
    "recovery.serialize_compact",
    "recovery._to_der_",
    "silentpayments.parse_label",
    "silentpayments.serialize_label",
    "silentpayments._labeled_spend_pubkey_",
    "ssa.Signer",
    "xonly.from_keypair",
    "xonly.parse",
    "xonly.serialize",
    "xonly._from_keypair_",
    "xonly._from_pubkey_",
}


def retyped(value: Any, kind: type) -> Any:
    """Return the argument as a bytearray or a memoryview, if it is bytes.

    A list or a tuple of them is retyped element by element, which is
    what the functions taking a sequence of keys are given, the pairs of
    `create_outputs` included.

    A mapping has its values retyped and its keys left alone, and that is
    not an omission: `scan_outputs` takes a label cache keyed on the 33
    bytes of a label, and neither a `bytearray` nor a `memoryview` is
    hashable, so bytes is the only one of the three a key can be.

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
    if isinstance(value, tuple):
        return tuple(retyped(item, kind) for item in value)
    if isinstance(value, dict):
        return {key: retyped(item, kind) for key, item in value.items()}
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


def at_the_boundary(name: str) -> bool:
    """Return True if a module attribute is one a caller passes octets to.

    The public functions, and the `_foo_` halves beside them: those are
    private to callers but they take octets like any other entry point --
    a message hash, a tweak, a private key -- and a length check missed
    there is missed exactly as badly. What is left out is the ordinary
    private helper, which is reached through the two above.

    Args:
        name: the attribute's name.

    Returns:
        True if the sweep has to account for it.
    """
    if name.startswith("__"):
        return False
    return not name.startswith("_") or name.endswith("_")


def test_the_sweep_is_whole() -> None:
    """Every entry point of every wrapped module is swept, or excused.

    A function added to the boundary and not added to `CALLS` is a hole
    this sweep would not cover and nothing else would report, so the
    list is checked against what the modules actually carry rather than
    trusted to have been kept up to date.
    """
    swept = {name for name, *_ in CALLS} | NOT_SWEPT
    at_boundary = {
        f"{module_name}.{name}"
        for module_name, module in MODULES.items()
        for name in dir(module)
        if at_the_boundary(name)
        and callable(getattr(module, name))
        and getattr(getattr(module, name), "__module__", "")
        == f"btclib_secp256k1.{module_name}"
    }

    assert at_boundary - swept == set()
    # and the sweep names nothing the modules do not have: an entry left
    # behind by a rename would otherwise excuse a function that no longer
    # exists, and cover nothing
    assert NOT_SWEPT - at_boundary == set()

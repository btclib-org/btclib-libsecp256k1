# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from __future__ import annotations

import time
from typing import Callable

import coincurve
from btclib.ecc import dsa, ssa  # type: ignore
from btclib.hashes import reduce_to_hlen  # type: ignore
from btclib.to_pub_key import pub_keyinfo_from_prv_key  # type: ignore

import btclib_libsecp256k1.dsa
import btclib_libsecp256k1.ssa
import secp256k1

prvkey = 1
pubkey = pub_keyinfo_from_prv_key(prvkey)[0]
xonly_pubkey = pubkey[1:]
msg = reduce_to_hlen(b"Satoshi Nakamoto")
dsa_sig = btclib_libsecp256k1.dsa.sign(msg, prvkey)
ssa_sig = btclib_libsecp256k1.ssa.sign(msg, prvkey)


def dsa_btclib() -> None:
    assert dsa.verify_(msg, pubkey, dsa_sig)


def ssa_btclib() -> None:
    assert ssa.verify_(msg, pubkey, ssa_sig)


def dsa_coincurve() -> None:
    assert coincurve.PublicKey(pubkey).verify(dsa_sig, msg, None)


def ssa_coincurve() -> None:
    assert coincurve.PublicKeyXOnly(xonly_pubkey).verify(ssa_sig, msg)


def dsa_secp256k1():
    pubkey_secp = secp256k1.PublicKey(pubkey, raw=True)
    assert pubkey_secp.ecdsa_verify(
        msg, pubkey_secp.ecdsa_deserialize(dsa_sig), raw=True
    )


def ssa_secp256k1():
    pubkey_secp = secp256k1.PublicKey(pubkey, raw=True)
    assert pubkey_secp.schnorr_verify(msg, ssa_sig, None, raw=True)


def dsa_libsecp256k1() -> None:
    assert btclib_libsecp256k1.dsa.verify(msg, pubkey, dsa_sig)


def ssa_libsecp256k1() -> None:
    assert btclib_libsecp256k1.ssa.verify(msg, xonly_pubkey, ssa_sig)


def benchmark(func: Callable[[], None], mult: int = 1) -> None:
    start = time.time()
    for _ in range(1000 * mult):
        func()
    end = time.time()
    print(f"{func.__name__:<17}: {((end - start) / mult):.6f}")


benchmark(dsa_btclib, 10)
benchmark(dsa_coincurve, 100)
benchmark(dsa_secp256k1, 100)
benchmark(dsa_libsecp256k1, 100)

benchmark(ssa_btclib, 10)
benchmark(ssa_coincurve, 100)
benchmark(ssa_secp256k1, 100)
benchmark(ssa_libsecp256k1, 100)

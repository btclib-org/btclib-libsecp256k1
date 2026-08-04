# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Verification timings of four secp256k1 implementations, side by side.

What is measured is one call each of ECDSA and BIP340 *verification*, on
one fixed key and message, through btclib's pure python arithmetic, this
package, coincurve and secp256k1-py. Verification and not signing,
because it is the operation all four expose with the same meaning and no
nonce to agree on.

The point is not a ranking: the three binding packages call the same
libsecp256k1, so what separates them is the boundary crossing, and what
separates them from btclib is the C. Read the output as an order of
magnitude and never as a number to quote -- the loop count differs per
function, the timings are wall clock, and nothing here repeats a
measurement or discards an outlier.

Not part of the test suite and not run by CI: it needs three third-party
packages this project does not depend on.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import coincurve
from btclib.ecc import dsa, ssa
from btclib.hashes import reduce_to_hlen
from btclib.to_pub_key import pub_keyinfo_from_prv_key

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
    """Time ECDSA verification through btclib's pure python arithmetic."""
    assert dsa.verify_(msg, pubkey, dsa_sig)


def ssa_btclib() -> None:
    """Time BIP340 verification through btclib's pure python arithmetic."""
    assert ssa.verify_(msg, pubkey, ssa_sig)


def dsa_coincurve() -> None:
    """Time coincurve's ECDSA verification, which takes a DER signature."""
    assert coincurve.PublicKey(pubkey).verify(dsa_sig, msg, None)


def ssa_coincurve() -> None:
    """Time coincurve's BIP340 verification, over an x-only public key."""
    assert coincurve.PublicKeyXOnly(xonly_pubkey).verify(ssa_sig, msg)


def dsa_secp256k1() -> None:
    """Time secp256k1-py's ECDSA verification.

    The parse of the public key and of the signature is inside the
    timing, that package offering no way to hold either across calls.
    """
    pubkey_secp = secp256k1.PublicKey(pubkey, raw=True)
    assert pubkey_secp.ecdsa_verify(
        msg, pubkey_secp.ecdsa_deserialize(dsa_sig), raw=True
    )


def ssa_secp256k1() -> None:
    """Time secp256k1-py's BIP340 verification.

    The key is parsed per call, as in dsa_secp256k1 above.
    """
    pubkey_secp = secp256k1.PublicKey(pubkey, raw=True)
    assert pubkey_secp.schnorr_verify(msg, ssa_sig, None, raw=True)


def dsa_libsecp256k1() -> None:
    """Time this package's ECDSA verification."""
    assert btclib_libsecp256k1.dsa.verify(msg, pubkey, dsa_sig)


def ssa_libsecp256k1() -> None:
    """Time this package's BIP340 verification."""
    assert btclib_libsecp256k1.ssa.verify(msg, xonly_pubkey, ssa_sig)


def benchmark(func: Callable[[], None], mult: int = 1) -> None:
    """Call `func` 1000 * `mult` times and print the seconds per 1000.

    `mult` is per function rather than shared, the pure python path being
    two orders of magnitude slower than the others: one loop count for
    all of them would either take minutes on btclib or measure the C
    calls against the resolution of the clock.
    """
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

# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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
function, and nothing here repeats a measurement or discards an outlier.

btclib's own rows need its dispatch turned off, which
`python_arithmetic_only` below does and says why: `dsa.verify_` and
`ssa.verify_` delegate to these very bindings for secp256k1 with sha256,
so without it the two rows measured C with a python wrapper in front and
called it python.

Not part of the test suite and not run by CI: it needs three third-party
packages this project does not depend on.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import coincurve
from btclib.curves import curve
from btclib.ecc import dsa, ssa
from btclib.hashes import reduce_to_hlen
from btclib.to_pub_key import pub_keyinfo_from_prv_key

import btclib_secp256k1.dsa
import btclib_secp256k1.ssa
import secp256k1

prvkey = 1
pubkey = pub_keyinfo_from_prv_key(prvkey)[0]
xonly_pubkey = pubkey[1:]
msg = reduce_to_hlen(b"Satoshi Nakamoto")
dsa_sig = btclib_secp256k1.dsa.sign(msg, prvkey)
ssa_sig = btclib_secp256k1.ssa.sign(msg, prvkey)


def python_arithmetic_only() -> None:
    """Turn btclib's libsecp256k1 dispatch off, in every namespace.

    Without this the two btclib rows below measured *these bindings* with
    a btclib wrapper in front, and reported it as python: `dsa.verify_`
    and `ssa.verify_` delegate for secp256k1 with sha256, which is
    exactly what is set up above. The two rows came out a little slower
    than this package's own and nothing said why.

    Every namespace, because `_libsecp256k1_applicable` is imported *by
    name* into `ecc.dsa`, `ecc.ssa` and `curves.curve`: patching one
    leaves the other two delegating, so a partial patch still measures C
    and still looks like python. The multiplication under the
    verification equation lives in the third of them.

    Called once, after the fixtures above are built -- they go through
    btclib too, and there is no reason to slow those down.
    """
    for module in (dsa, ssa, curve):
        module._libsecp256k1_applicable = lambda *_: False


python_arithmetic_only()


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
    assert btclib_secp256k1.dsa.verify(msg, pubkey, dsa_sig)


def ssa_libsecp256k1() -> None:
    """Time this package's BIP340 verification."""
    assert btclib_secp256k1.ssa.verify(msg, xonly_pubkey, ssa_sig)


def benchmark(func: Callable[[], None], mult: int = 1) -> None:
    """Call `func` 1000 * `mult` times and print the seconds per 1000.

    `mult` is per function rather than shared, the pure python path being
    two orders of magnitude slower than the others: one loop count for
    all of them would either take minutes on btclib or measure the C
    calls against the resolution of the clock.
    """
    # perf_counter and not time(): the wall clock can step backwards
    # under an NTP correction, and a benchmark is the one place that
    # shows up as a negative duration
    start = time.perf_counter()
    for _ in range(1000 * mult):
        func()
    end = time.perf_counter()
    print(f"{func.__name__:<17}: {((end - start) / mult):.6f}")


# one thousand calls of the python path is already a second of wall
# clock, where the C rows need a hundred thousand to leave the clock's
# own resolution behind
benchmark(dsa_btclib, 1)
benchmark(dsa_coincurve, 100)
benchmark(dsa_secp256k1, 100)
benchmark(dsa_libsecp256k1, 100)

benchmark(ssa_btclib, 1)
benchmark(ssa_coincurve, 100)
benchmark(ssa_secp256k1, 100)
benchmark(ssa_libsecp256k1, 100)

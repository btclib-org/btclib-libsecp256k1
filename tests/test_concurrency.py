# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Concurrent use of the shared libsecp256k1 context.

The bindings hold one context, created and randomized at import time and
passed to every call. That is safe because a context is only mutated by
secp256k1_context_randomize, which runs once before any thread exists,
and because each call allocates the buffers it writes to; but nothing in
the code says so, and a static wheel is built for the free-threaded
interpreter (cp314t), where these calls are no longer serialized by an
interpreter lock.

Every operation exercised here is deterministic, ECDSA by RFC6979 and
BIP340 by a fixed aux_rand32, so a result that differs between threads
is a shared buffer, not a legitimate difference.
"""

from concurrent.futures import ThreadPoolExecutor

from btclib_libsecp256k1 import dsa, ecdh, keys, mult, ssa, xonly

prvkey = 0xB7331FE4A9F79F4A2B79A5BEE4CCA2C6A0A9DCE05C4EB77C1C8AA1CC1EE47ADD
tweak = 0x3F2B1C7D8E9F0A1B2C3D4E5F60718293A4B5C6D7E8F901A2B3C4D5E6F708192A
msg = b"\xa0\xdce\xff\xcay\x98s\xcb\xea\n\xc2t\x01[\x95&P]\xaa\xae\xd3\x85\x15T%\xf73w\x04\x88>"
aux_rand32 = b"\x11" * 32

WORKERS = 8
ROUNDS = 32


def test_concurrent_round_trips() -> None:
    pubkey_bytes = mult.mult_(prvkey)
    xonly_bytes, _ = xonly.from_pubkey(pubkey_bytes)
    dsa_sig = dsa.sign(msg, prvkey)
    ssa_sig = ssa.sign(msg, prvkey, aux_rand32)
    secret = ecdh.shared_secret(pubkey_bytes, tweak)
    tweaked = xonly.tweak_add(xonly_bytes, tweak)
    combined = keys.pubkey_combine([pubkey_bytes, mult.mult_(tweak)])

    def round_trip(_: int) -> None:
        assert dsa.sign(msg, prvkey) == dsa_sig
        assert dsa.verify(msg, pubkey_bytes, dsa_sig)
        assert ssa.sign(msg, prvkey, aux_rand32) == ssa_sig
        assert ssa.verify(msg, xonly_bytes, ssa_sig)
        assert mult.mult_(prvkey) == pubkey_bytes
        assert ecdh.shared_secret(pubkey_bytes, tweak) == secret
        assert xonly.tweak_add(xonly_bytes, tweak) == tweaked
        assert keys.pubkey_combine([pubkey_bytes, mult.mult_(tweak)]) == combined

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        # map is lazy: the results have to be consumed for an assertion
        # failing in a worker to be raised here
        list(pool.map(round_trip, range(WORKERS * ROUNDS)))

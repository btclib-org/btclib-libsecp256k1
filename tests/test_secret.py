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

from btclib_libsecp256k1 import _secret, ffi, lib
from btclib_libsecp256k1.context import ctx

SECRET = b"\x07" * 32


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

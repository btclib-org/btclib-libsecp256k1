# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the BIP340 tagged hash.

The reference is the definition itself, SHA256(SHA256(tag) ||
SHA256(tag) || msg) computed with hashlib: an implementation of SHA256
that has nothing to do with the one inside libsecp256k1.
"""

from __future__ import annotations

import hashlib

from btclib_libsecp256k1 import hashes


def tagged_sha256(tag: bytes, msg: bytes) -> bytes:
    """Compute a BIP340 tagged hash with hashlib."""
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def test_tagged_sha256() -> None:
    """Match the definition, and check that the tag separates domains.

    The four tags are the taproot ones of BIP341 and the challenge tag of
    BIP340, over messages from empty to a thousand octets. Two further
    assertions are about the construction rather than the digest: one
    message under two tags gives two values, and the tag is not merely
    prefixed to the message -- which is what the doubled tag hash is for,
    and what an empty tag exhibits.
    """
    # the taproot tags of BIP341 and the challenge tag of BIP340
    for tag in (b"TapLeaf", b"TapBranch", b"TapTweak", b"BIP0340/challenge"):
        for msg in (b"", b"\x00", b"btclib_libsecp256k1", b"\xff" * 1000):
            assert hashes.tagged_sha256(tag, msg) == tagged_sha256(tag, msg)

    # the tag is what separates the domains: the same message under two
    # tags hashes to two different values
    assert hashes.tagged_sha256(b"TapLeaf", b"x") != hashes.tagged_sha256(
        b"TapBranch", b"x"
    )
    # and it is not a prefix of the message, which an empty tag shows
    assert hashes.tagged_sha256(b"", b"ab") != hashes.tagged_sha256(b"a", b"b")

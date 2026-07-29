# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Shared libsecp256k1 context."""

import secrets

from . import lib

# 1 is SECP256K1_CONTEXT_NONE: since libsecp256k1 0.2 signing and
# verification work with any context, and the SIGN/VERIFY flags are
# deprecated
ctx = lib.secp256k1_context_create(1)

# re-blind the signing precomputation, protecting against side-channel
# leakage, as recommended by libsecp256k1
if not lib.secp256k1_context_randomize(ctx, secrets.token_bytes(32)):
    raise RuntimeError("libsecp256k1 context randomization failed")

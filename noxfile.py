# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import nox


@nox.session
def pre_commit(session):
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


@nox.session
def tests(session):
    session.install(".")
    session.install("pytest", "pytest-cov")
    pytest = "pytest --cov-report term-missing:skip-covered --cov=btclib_libsecp256k1"
    session.run(*pytest.split())

# Release process

Releases are published by the `release` workflow, which reuses the `lint`
gate and the whole `test` build and test pipeline, and then uploads what
the latter produced. Where
it uploads is not an input to choose at dispatch time: a `v*` tag
publishes to PyPI, a manual run publishes to TestPyPI. Both go through
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/), so no
long-lived token exists anywhere, and both upload PEP 740 attestations.

The version published is the one in `pyproject.toml`; the tag only
decides which index is reached. The `version-check` job cross-checks
them, and runs before anything is built: a `v0.7.1` tag on a tree still
reading `0.7.1rc1` fails there, rather than burning `0.7.1rc1` on PyPI.
The same job checks that `uv.lock` carries the version the tree declares,
and that the libsecp256k1 release named in `README.md` is the commit the
submodule is pinned to.

## Cutting a release

1. bump the version in `pyproject.toml` and run `uv lock`, which carries
   it into `uv.lock`. Version numbers track the wrapped libsecp256k1,
   with a fourth number for a release of the bindings alone: see the
   Versioning section of [README.md](README.md)
2. add the release notes to `HISTORY.md`; if the vendored libsecp256k1
   moved, update the version named at the top of `README.md` too
3. merge `dev` into `master` with a green CI. Development happens on
   `dev`, and `master` only receives merges from it
4. tag the merge commit, and push that tag alone:

       git tag v0.7.1
       git push origin v0.7.1

   `git push --tags` would push whatever other local tags happen to
   exist. The workflow then builds and tests every artifact the release
   ships and stops at the `pypi` environment
5. approve the `pypi` deployment when the run pauses for review. Up to
   here nothing is public and the tag can still be deleted; the upload
   that follows is the point of no return
6. check that what was published installs, and that the PyPI page shows
   the attestations:

       python -m pip install --upgrade btclib_libsecp256k1

7. run the `published` workflow from the Actions tab, and expect it green:
   it installs from PyPI what was just uploaded, on every platform and at
   both ends of the supported interpreter range, and verifies BIP340
   vector 0 with it. From then on it runs weekly on its own, and a failure
   means the outside world moved, not this repository
8. check the GitHub release the workflow created once PyPI had accepted
   the upload: its notes are the tag's section of `HISTORY.md`, and the
   sdist is attached. A run that warns `HISTORY.md has no v0.7.1 section`
   generated the notes from the merged pull requests instead, and they
   are worth replacing by hand

## Rehearsing on TestPyPI

A tag cannot be taken back: a version, once on PyPI, can only be yanked,
never replaced. So the same workflow can be run manually, and a manual
run publishes to TestPyPI instead. It is the same file, the same jobs and
the same gate as the release it rehearses, which a second workflow of its
own could not be: a trusted publisher is registered for a workflow
*filename*, so a `release-test.yml` would only ever prove itself.

The rehearsal is what the release machinery itself is tested with, when
the workflow, the packaging metadata or the build matrix changed. A
release that only bumps versions and notes does not need one.

1. run the `release` workflow from the Actions tab, on the branch holding
   it: a manual run builds the full matrix and stops at the `testpypi`
   environment. Nothing has to be done to the version first. A version is
   consumed by the upload on TestPyPI as much as on PyPI, so every build
   job appends `.dev<run number>` to what `pyproject.toml` declares,
   which is unique per dispatch and sorts before the release being
   rehearsed. Re-running a finished rehearsal would reuse its run number
   and collide: dispatch a fresh run instead.
   Never tag a rehearsal: the trigger is what picks the index, so a
   `v0.7.1rc1` tag would take the pre-release to PyPI itself and burn it
   there, and `0.7.1rc1` is a version PyPI would then hand to `--pre`
   installs. The `version-check` job refuses a tag whose version is not
   digits and dots, so the mistake stops before anything is built
2. approve it, then check that what was published installs:

   <!-- markdownlint-disable MD013 -->

       pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ --pre btclib_libsecp256k1

   <!-- markdownlint-enable MD013 -->

   the extra index being needed for `cffi`, which TestPyPI does not have.
   The version installed carries the `.dev<run number>` suffix, and
   `--pre` is what makes it resolvable

There is no version commit to revert, and nothing to clean up: the
suffix only ever exists inside the run that built it.

What the rehearsal covers is the OIDC exchange, the approval gate, the
artifacts the publish job collects, the PEP 740 attestations, and a real
Warehouse accepting the metadata, which is more than `twine check
--strict` can say. What it cannot cover is the trusted publisher on PyPI
itself, a separate registration that can be wrong on its own, nor the
tag comparison of `version-check`, there being no tag.

## When a release turns out to be broken

Nothing can be reuploaded under the same version, on either index. A
broken release is yanked, which hides it from resolution while leaving it
installable by exact pin, and the fix ships as a new version: a fourth
number when the wrapped libsecp256k1 is unchanged (`0.7.1.1`). Yanking
is done from the PyPI project page; the tag and the GitHub release are
worth keeping, as what a yanked file was built from.

## One-time setup, per index

The PyPI side is already done; this is here for the next index, or the
next fork.

- on PyPI, and on TestPyPI, project Publishing settings: add a GitHub
  trusted publisher for `btclib-org/btclib_libsecp256k1`, workflow
  `release.yml`, environment `pypi` and `testpypi` respectively. The two
  indexes are separate accounts and separate registrations; owning the
  project on one says nothing about the other
- on GitHub, repository Settings, Environments: create the `pypi` and
  `testpypi` environments, each with the required reviewers who approve.
  Leaving `testpypi` without reviewers would be the one part of a
  release that the rehearsal stops exercising

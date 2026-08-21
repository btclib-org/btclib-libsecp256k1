# The package-content policy

A release publishes wheels of two kinds and one sdist. This page states
what a wheel may hold, what it may never hold, and what has to be there;
`.github/scripts/verify_wheel_contents.py` enforces every rule down to
the last section, and `tests/test_wheel_contents.py` compares the two in
both directions, so this page cannot state a rule the script does not
have, and the script cannot grow a rule this page does not state. The
prose around the lists is prose, and is checked by nobody.

`test.yml`'s `check-dist` job runs the script on every wheel it
downloads from `build-cibuildwheel`, `build-dynamic` and `build-windows`
— the artifacts `release.yml`'s own `test` job produces and the publish
jobs upload, so this judges the files that actually reach PyPI rather
than a copy of them.

## Two kinds of wheel

`scripts/hatch_build.py` builds one or the other, never both, and tags
each so the difference is legible from the file name: a **static**
wheel carries one compiled extension, `_btclib_secp256k1`, linked
against libsecp256k1 and tagged for the interpreter that built it
(`cpNN-cpNN-<platform>`); a **dynamic** wheel compiles no C at all,
carries the ABI-mode module `_btclib_secp256k1.py` and the shared
`libsecp256k1` library it `dlopen`s at import, and is tagged
`py3-none-<platform>` because neither file is interpreter-specific. The
script reads the wheel's own file name to tell them apart — the same
distinction `scripts/hatch_build.py` draws when it writes the tag in the
first place.

## What may never be in the wheel

Checked against every member of `btclib_secp256k1/` and the top-level
artifact, not against `.dist-info` — already validated member by
member, against its own allowlist, above: `FORBIDDEN_SUFFIXES` and
`FORBIDDEN_NAMES`.

- `.pth` — executed at interpreter startup, before the first import
- `.pyc` — a compiled module whose source nobody reviewed
- `.egg`, `.tar.gz`, `.whl`, `.zip` — an archive inside an archive, that
  is, a second package installing with the first
- `sitecustomize.py`, `usercustomize.py` — the two names Python imports
  for their side effects alone, at startup, from the root of
  site-packages

A `__pycache__` directory is refused too, by name rather than by suffix.

## What the wheel may hold

Three regions, and nothing outside them.

Under `btclib_secp256k1-<version>.dist-info/` — `WHEEL_METADATA_FILES`
and, under `licenses/`, `WHEEL_LICENSE_FILES`:

- `METADATA`, `RECORD`, `WHEEL` — what hatchling writes for a package
  configured as this one is. No `top_level.txt`: that file is
  setuptools's, and this build backend is hatchling
- `AUTHORS.md`, `COPYRIGHT`, `LICENSE` — `project.license-files` in
  `pyproject.toml`, copied into `licenses/` verbatim

Under `btclib_secp256k1/` — exactly the files this checkout's own
`btclib_secp256k1/` directory has, source and `py.typed` alike. The
script reads that directory fresh rather than carrying a copy of its
file list, which is what `check-wheel-contents --package
btclib_secp256k1` would check too, asked here by hand instead of
through that flag: the flag also judges the third region below, which is
not part of any package tree and is not a mistake for being outside one.

At the wheel's own root, one artifact set per kind, and nothing else — a
second extension, a stray file, a test package shipped by accident, all
fail, whichever kind the wheel is.

A static wheel: exactly one file whose name starts with
`_btclib_secp256k1` and ends in a compiled-extension suffix,
`EXTENSION_SUFFIXES`:

- `.so` — Linux and macOS
- `.pyd` — Windows

A dynamic wheel: exactly `_btclib_secp256k1.py`, the ABI-mode module
`scripts/cffi_build.py` emits, and exactly one file whose name starts
with `libsecp256k1` and ends in a shared-library suffix,
`SHARED_LIBRARY_SUFFIXES`:

- `.so` — Linux
- `.dylib` — macOS
- `.dll` — Windows

Never a versioned name from the symlink chain CMake also leaves behind,
such as `libsecp256k1.so.2` — `scripts/cffi_build.py` itself skips those
when it copies the artifact into the wheel, keeping to one shared
library rather than the chain of names one file on disk can answer to.

## What has to be in there

Every file `btclib_secp256k1/` may hold, per the diff above, and the
kind-appropriate top-level artifact, checked for size as well as
presence: an artifact `scripts/cffi_build.py` failed to finish copying
would still be a member of the archive, at zero bytes, and no other
check here or in `check-wheel-contents` reads a member's size at all.

## The sdist is not this policy's subject

`btclib`'s sibling script checks the sdist because `MANIFEST.in` there
is an *include* list: a file the tree gains and `MANIFEST.in` does not
name is a file the sdist silently drops, which is the failure this whole
class of check exists for. `[tool.hatch.build.targets.sdist] exclude` in
this repository's `pyproject.toml` is the opposite shape — a file the
tree gains ships by default, and has to be named to be left out — so the
failure mode here is an sdist too wide rather than one silently narrow,
and modelling the members the vendored `secp256k1/` submodule and this
repository's own tooling contribute would be an allowlist nobody could
read, let alone maintain, for a question the `exclude` list itself
already answers by construction. What that leaves
unchecked — an exclude pattern naming a file a build still needs — fails
the build outright rather than shipping silently, which is a different
question with a different check to answer it.

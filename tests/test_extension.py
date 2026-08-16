# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of what installing the package provides, rather than its source.

That is the extension module and the distribution metadata.

One package works with both extensions: the static one, which has
libsecp256k1 linked in, and the dynamic one (cffi ABI mode), which has
to find at run time the shared library shipped beside it. Whichever
build these tests run on, the branch of _load_lib taken by the import
itself is the only one that exists, so the search is driven here with a
stand-in module: what is checked is not that a library can be loaded,
but that a directory not holding one is reported instead of being
mistaken for one.
"""

import pathlib
import re
import shutil
import subprocess
import sys
import types

import _btclib_secp256k1
import _cffi_backend
import pytest

import btclib_secp256k1
from btclib_secp256k1 import __version__, _load_lib


def test_version() -> None:
    """Check that __version__ is a non-empty string.

    Not that the distribution is installed under the name __init__.py
    asks for: were it not, the `from` import at the top of this module
    would raise while it is being collected, and there would be no test
    here to fail. What is checked is that the package keeps exposing the
    attribute, and with a value in it -- through a module-level
    `__getattr__`, so that the attribute a caller never reads costs
    nothing to have.
    """
    assert isinstance(__version__, str)
    assert __version__


def test_no_such_attribute() -> None:
    """A name the package does not have is still an AttributeError.

    The other half of the `__getattr__` that builds `__version__`, and
    the one no other test reaches: python calls it for every name the
    module itself has none of, so what it answers for anything but that
    one has to be what a module without it answers on its own.
    Answering None, or the version, would turn a typo into a value.

    The `type: ignore` is the point rather than an annoyance: mypy still
    knows this attribute does not exist, which is what the
    `if TYPE_CHECKING` in `__init__.py` is there to preserve, and a
    module that simply had a `__getattr__` would need no suppression
    here because it would have stopped checking.
    """
    with pytest.raises(AttributeError, match="no attribute 'nonesuch'"):
        _ = btclib_secp256k1.nonesuch  # type: ignore[attr-defined]


def _imported_modules(name: str) -> set[str]:
    """Return what importing this package leaves in sys.modules.

    A subprocess because the answer is about a fresh interpreter: this
    one has the package imported already, and every test module beside
    this one has imported half the standard library into it.

    Args:
        name: the module to import in that interpreter.

    Returns:
        The names in `sys.modules` afterwards.
    """
    code = f"import sys, {name}; print('\\n'.join(sys.modules))"
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    return set(completed.stdout.split())


def test_import_defers_the_metadata() -> None:
    """Importing the package does not import `importlib.metadata`.

    What the deferral in `__init__.py` bought, asserted rather than
    measured: reading `__version__` at import time is most of what made
    that import 15.85 milliseconds where it is now 1.69, CHANGELOG.md
    carrying the split -- `importlib.metadata` pulls `email`, `json` and
    `inspect` behind it. Nothing else says so, and a module level import
    added
    later -- here or in anything this package imports -- puts those
    milliseconds back with every other gate green, which is how they
    arrived in the first place.

    What is asserted is what *this* import adds, the names an empty
    interpreter already holds being subtracted first: asking for
    absolute absence would make a future interpreter, or a stray `.pth`
    preloading one of these, a failure of this package. Nothing is
    subtracted today, a bare interpreter here holding none of them.

    The named modules are the expensive ones rather than all of them: a
    list of everything `importlib.metadata` reaches is a list that
    changes with the interpreter.
    """
    added = _imported_modules("btclib_secp256k1") - _imported_modules("sys")
    assert "importlib.metadata" not in added
    for module in ("email", "json", "inspect", "zipfile"):
        assert module not in added, f"{module} is imported again"


@pytest.mark.skipif(
    not hasattr(_btclib_secp256k1, "lib"),
    reason="a dynamic extension reaches _load_lib's second branch, which uses pathlib",
)
def test_import_defers_pathlib() -> None:
    """A static extension does not import `pathlib` either.

    The other half of the same ratchet, and it holds for the static
    build alone: `_load_lib` returns at `hasattr(module, "lib")` there,
    where a dynamic one goes on to glob for the shared object and
    imports `pathlib` legitimately. The matrix runs the suite both ways,
    so the skip is what keeps this true rather than flaky.

    It only holds alongside the test above, which is why the two are not
    one assertion in one test: `importlib.metadata` imports `pathlib`
    itself, so this one would fail on a tree that deferred `pathlib`
    alone, and the deferral it is really asserting is the pair.
    """
    added = _imported_modules("btclib_secp256k1") - _imported_modules("sys")
    assert "pathlib" not in added


def test_load_lib_no_candidate(tmp_path: pathlib.Path) -> None:
    """A directory holding no library is reported, naming the directory.

    The dynamic branch of `_load_lib` is driven with a stand-in module,
    that being the only way to reach it from a static build -- and the
    other way round.
    """
    module = types.SimpleNamespace(__file__=str(tmp_path / "_extension.py"))
    with pytest.raises(ImportError, match=re.escape(str(tmp_path))):
        _load_lib(module)


@pytest.mark.skipif(
    getattr(_cffi_backend, "__file__", None) is None,
    reason="a PyPy interpreter has _cffi_backend built in, so there is no file",
)
def test_load_lib_returns_a_loadable_candidate(tmp_path: pathlib.Path) -> None:
    """A candidate the loader accepts is returned, which is the point of it.

    The two tests beside this one both end in the raise, so until this one
    the `return ffi.dlopen(...)` of the dynamic branch was never taken --
    invisibly, because coverage sees that line executed by the call that
    raises. What it takes to reach it is a shared object the loader can
    load, under a name the glob matches, and on CPython `_cffi_backend` is
    one whichever of the two builds these tests run on: cffi is a hard
    dependency, so its own extension is always there and is always a real
    shared object.

    A PyPy interpreter is the exception, and the skip above is why this
    test cannot simply pick something else: it has `_cffi_backend` built
    in rather than beside it, so the module has no `__file__` at all, and
    it loads no other C extension this suite could borrow one from. The
    line stays covered because coverage is measured on CPython.
    """
    suffix = {"win32": ".dll", "darwin": ".dylib"}.get(sys.platform, ".so")
    shutil.copy(_cffi_backend.__file__, tmp_path / f"libsecp256k1{suffix}")
    module = types.SimpleNamespace(__file__=str(tmp_path / "_extension.py"))
    assert _load_lib(module) is not None


def test_load_lib_unloadable_candidate(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file that matches the glob but does not load is not a library.

    It is skipped and the search continues, so what the caller is told is
    that the directory holds no loadable libsecp256k1 -- rather than the
    dlopen failure of one candidate, which would report the first
    accident as the whole answer. But that accident is not thrown away:
    it is the one diagnostic that says *why*, and the *last* rejected
    candidate's -- not any other one's -- has to survive to the final
    ImportError, both named in its message and chained as __cause__, for
    a dynamic wheel's import failure to be debuggable rather than just
    "no loadable shared libsecp256k1 found".
    """
    # three files matching the glob, all rejected by the loader: a wheel
    # repaired by auditwheel or delocate can ship more than one match, and
    # the diagnostic of each rejected candidate has to reach the final
    # failure, not just the last one tried. Two would not do here: with a
    # two-element list, index -1 and index 1 name the same element, which
    # is exactly the survivor a mutation session
    # (.github/mutation/bindings.toml) found on `rejected[-1]` -- six
    # variants of the same off-by-index mutant, none of them killed by a
    # test that only checked `isinstance(cause, OSError)`. glob's own
    # order is undocumented, so it is pinned to sorted order here rather
    # than trusted, the same way this project fixes what a test cannot
    # otherwise hold constant about an external call
    names = ["libsecp256k1.so", "libsecp256k1.so.1", "libsecp256k1.so.2"]
    for name in names:
        (tmp_path / name).write_bytes(b"not a shared object")
    real_glob = pathlib.Path.glob

    def sorted_glob(
        self: pathlib.Path, *args: object, **kwargs: object
    ) -> list[pathlib.Path]:
        return sorted(real_glob(self, *args, **kwargs))  # type: ignore[arg-type]

    monkeypatch.setattr(pathlib.Path, "glob", sorted_glob)
    module = types.SimpleNamespace(__file__=str(tmp_path / "_extension.py"))
    with pytest.raises(
        ImportError, match="no loadable shared libsecp256k1"
    ) as exc_info:
        _load_lib(module)
    message = str(exc_info.value)
    for name in names:
        assert name in message
    # sorted order puts libsecp256k1.so.2 last, being the longest of three
    # names sharing a prefix, so its OSError -- naming its own path, as
    # dlopen's does -- is what has to be __cause__, and no other
    # candidate's path is a substring of it
    assert "libsecp256k1.so.2" in str(exc_info.value.__cause__)

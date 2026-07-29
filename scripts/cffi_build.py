# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from __future__ import annotations

import os
import pathlib
import platform
import re
import shutil
import subprocess
from subprocess import PIPE, Popen
from sysconfig import get_config_var, get_path
from typing import Any

import cffi

cross_compile = os.environ.get("BTCLIB_LIBSECP256K1_CROSS_COMPILE", "false") == "true"
static = os.environ.get("BTCLIB_LIBSECP256K1_DYNAMIC", "false") != "true"

# do-nothing implementations of the external default callbacks: they replace
# the abort()ing upstream defaults, so that illegal inputs never crash the
# hosting Python process; compiled as a separate unit, without mutating the
# vendored sources.
#
# These are the defaults, which apply to every context whose callbacks are
# not set: the shared context of the bindings sets them to record what was
# reported, so that context.check() can raise it
CALLBACK_STUBS = """
void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    (void)str;
    (void)data;
}

void secp256k1_default_error_callback_fn(const char* str, void* data) {
    (void)str;
    (void)data;
}
"""

# add the callback stubs to the vendored library target, so that the
# static archive and the shared object alike define the symbols that
# SECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS leaves undefined.
#
# CMake includes this file at the end of every project() call, when the
# target does not exist yet: hence the deferred call, which runs at the
# end of the top level directory, once add_subdirectory(src) has created
# the target, and still before generation. cmake_language(DEFER) needs
# CMake 3.19; the vendored library already requires 3.22.
#
# Nothing of this is written inside the vendored tree: the stubs and this
# file live in the CMake binary directory, which is outside the submodule
PROJECT_INCLUDE = """
if(NOT DEFINED BTCLIB_CALLBACKS_ADDED)
  set(BTCLIB_CALLBACKS_ADDED ON)
  cmake_language(DEFER DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                 CALL target_sources secp256k1 PRIVATE "${BTCLIB_CALLBACKS}")
endif()
"""


# every subprocess call below drives the vendored CMake build with
# argument lists assembled here: no shell, no untrusted input. The
# executables (cmake, cc) are looked up on PATH, as a build from source
# has to do
class FFIExtension:
    # the contract a subclass has to fulfil before calling __init__
    name: str
    static: bool
    clean_patterns: list[str]
    library_dirs: list[pathlib.Path]
    libraries: list[str]

    def __init__(self) -> None:
        self.clean()
        self.platform = os.environ.get("CFFI_PLATFORM", platform.system())

    @property
    def shared_library_extension(self) -> str:
        if self.platform == "Windows":
            return ".dll"
        if self.platform == "Darwin":
            return ".dylib"
        if self.platform == "Linux":
            return ".so"
        raise RuntimeError

    def clean(self) -> None:
        raise NotImplementedError

    def build_c(self) -> None:
        raise NotImplementedError

    def generate_def(self) -> tuple[str, str]:
        raise NotImplementedError

    def create_cffi(self, build_dir: pathlib.Path) -> tuple[Any, list[pathlib.Path]]:
        build_dir = pathlib.Path(build_dir)

        self.build_c()
        ffi = cffi.FFI()
        header, definitions = self.generate_def()
        ffi.cdef(definitions)

        if self.static and platform.system() == "Windows":
            return ffi, self.compile_static_msvc(ffi, header, build_dir)
        # a dynamic (cffi ABI mode) extension is generated from the cdef
        # alone: there is no C source to compile
        ffi.set_source(self.name, header if self.static else None)
        if self.static:
            return ffi, self.compile_static_unix(ffi, build_dir)
        return ffi, self.emit_dynamic(ffi, build_dir)

    def compile_static_msvc(
        self, ffi: Any, ffi_header: str, build_dir: pathlib.Path
    ) -> list[pathlib.Path]:
        # native Windows: compile the extension with the standard
        # setuptools/MSVC toolchain instead of the manual Unix one;
        # SECP256K1_STATIC selects the static-consumer declarations
        # in the header
        ffi.set_source(
            self.name,
            ffi_header,
            library_dirs=[str(d) for d in self.library_dirs],
            libraries=self.libraries,
            define_macros=[("SECP256K1_STATIC", "1")],
        )
        return [pathlib.Path(ffi.compile(tmpdir=str(build_dir)))]

    def compile_static_unix(
        self, ffi: Any, build_dir: pathlib.Path
    ) -> list[pathlib.Path]:
        c_filename = f"{self.name}.c"
        o_filename = f"{self.name}.o"
        so_filename = self.name + get_config_var("EXT_SUFFIX")
        c_path = build_dir / c_filename
        so_path = build_dir / so_filename

        ffi.emit_c_code(str(c_path))
        compile_command = [
            *get_config_var("CC").split(),
            f"-I{get_path('include')}",
            f"-I{get_path('platinclude')}",
            get_config_var("CCSHARED"),
            "-c",
            str(c_filename),
            "-o",
            str(o_filename),
        ]
        link_command = [
            get_config_var("LDSHARED").split()[0],
            str(o_filename),
            *get_config_var("LDSHARED").split()[1:],
            *[f"-L{libs_dir}" for libs_dir in self.library_dirs],
            *[f"-l{lib}" for lib in self.libraries],
            "-o",
            str(so_filename),
        ]

        subprocess.run(compile_command, cwd=build_dir, check=True)
        subprocess.run(link_command, cwd=build_dir, check=True)
        return [so_path]

    def emit_dynamic(self, ffi: Any, build_dir: pathlib.Path) -> list[pathlib.Path]:
        py_filename = f"{self.name}.py"
        py_path = build_dir / py_filename

        ffi.emit_python_code(str(py_path))
        artifacts = [py_path]
        for lib in self.libraries:
            # every candidate directory is searched before giving up: the
            # shared library is in lib on POSIX and in bin on Windows, and
            # which of them exists is not known here
            found: pathlib.Path | None = None
            for libs_dir in self.library_dirs:
                pattern = f"lib{lib}*{self.shared_library_extension}"
                for file in libs_dir.glob(pattern):
                    if not file.is_file():
                        continue
                    # skip the versioned names of the symlink chain, as in
                    # libsecp256k1.2.dylib or libsecp256k1.so.2
                    if len(file.suffixes) > 1:
                        continue
                    if found is not None:
                        msg = f"multiple shared objects found for library: {lib}"
                        raise RuntimeError(msg)
                    found = file
            if found is None:
                raise RuntimeError(f"no shared object found for library: {lib}")
            shutil.copy(found, build_dir / found.name)
            artifacts.append(build_dir / found.name)

        return artifacts


class Secp256k1CFFIExtension(FFIExtension):
    def __init__(self) -> None:
        self.name = "_btclib_libsecp256k1"
        self.static = static and not cross_compile
        self.clean_patterns = [
            "_btclib_libsecp256k1.*",
            "btclib_libsecp256k1/libsecp256k1.*",
        ]
        # working directory
        self.wd = pathlib.Path(__file__).parent.parent.resolve() / "secp256k1"
        self.include_dir = self.wd / "include"
        # #include directives are stripped before preprocessing, so the
        # concatenation order must satisfy the inter-header dependencies:
        # musig needs the extrakeys types, everything needs secp256k1.h
        self.headers = [
            "secp256k1.h",
            "secp256k1_ecdh.h",
            "secp256k1_recovery.h",
            "secp256k1_extrakeys.h",
            "secp256k1_schnorrsig.h",
            "secp256k1_musig.h",
            "secp256k1_ellswift.h",
        ]
        # the library is built out of tree, so that the vendored sources
        # are never written to: build/ is where a wheel build puts its
        # own artifacts too, and is removed wholesale before each of them
        self.cmake_dir = self.wd.parent / "build" / "secp256k1"
        self.library_dirs = [self.cmake_dir / "lib"]
        self.libraries = ["secp256k1"]
        super().__init__()

    def clean(self) -> None:
        # a stale CMake cache remembers the previous configuration
        # (static or shared, host or cross): reconfigure from scratch
        if self.cmake_dir.exists():
            shutil.rmtree(self.cmake_dir)
        for pattern in self.clean_patterns:
            for file in pathlib.Path().glob(pattern):
                file.unlink()

    def build_c(self) -> None:
        """Build the vendored library with CMake, on every platform."""
        self.cmake_dir.mkdir(parents=True, exist_ok=True)
        callbacks = self.cmake_dir / "btclib_default_callbacks.c"
        callbacks.write_text(CALLBACK_STUBS)
        project_include = self.cmake_dir / "btclib_callbacks.cmake"
        project_include.write_text(PROJECT_INCLUDE)

        configure = [
            "cmake",
            "-S",
            str(self.wd),
            "-B",
            str(self.cmake_dir),
            # single configuration generators need it at configure time
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DBUILD_SHARED_LIBS={'OFF' if self.static else 'ON'}",
            # the static archive is linked into a shared extension
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DSECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS=ON",
            f"-DCMAKE_PROJECT_INCLUDE={project_include}",
            f"-DBTCLIB_CALLBACKS={callbacks}",
            # all the modules wrapped by the bindings are requested
            # explicitly: upstream defaults are not part of its API
            # (recovery, in particular, is disabled by default)
            "-DSECP256K1_ENABLE_MODULE_ECDH=ON",
            "-DSECP256K1_ENABLE_MODULE_RECOVERY=ON",
            "-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON",
            "-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON",
            "-DSECP256K1_ENABLE_MODULE_MUSIG=ON",
            "-DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON",
            "-DSECP256K1_BUILD_BENCHMARK=OFF",
            "-DSECP256K1_BUILD_TESTS=OFF",
            "-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF",
            "-DSECP256K1_BUILD_CTIME_TESTS=OFF",
            "-DSECP256K1_BUILD_EXAMPLES=OFF",
            "-DSECP256K1_INSTALL=OFF",
        ]
        if cross_compile:
            # the toolchain file is the vendored one, upstream tested
            toolchain = self.wd / "cmake" / "x86_64-w64-mingw32.toolchain.cmake"
            configure.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain}")
        subprocess.run(configure, check=True)
        subprocess.run(
            ["cmake", "--build", str(self.cmake_dir), "--config", "Release"],
            check=True,
        )

        # multi configuration generators (MSVC) append the configuration
        # name; the shared library goes to lib on POSIX, being a DLL, to
        # bin on Windows
        candidates = ("lib/Release", "lib", "bin/Release", "bin")
        self.library_dirs = [
            directory
            for directory in (self.cmake_dir / c for c in candidates)
            if directory.is_dir()
        ]
        # the MSVC static archive is named libsecp256k1.lib, while the
        # MSVC DLL and every mingw and POSIX artifact keeps the plain name
        if self.static and platform.system() == "Windows":
            self.libraries = ["libsecp256k1"]

    def generate_def(self) -> tuple[str, str]:
        ffi_header = ""
        for h in self.headers:
            location = self.include_dir / h
            with location.open() as f:
                ffi_header += f.read() + "\n"

        ffi_header = re.sub(r"#include .*", "", ffi_header)

        # expand all __attribute__ ((...)) to nothing: cffi cannot parse them
        command = [
            "gcc",
            "-P",
            "-E",
            "-D",
            "SECP256K1_BUILD",
            "-D",
            "__attribute__(x)=",
            "-",
        ]
        with Popen(command, stdin=PIPE, stdout=PIPE) as p:
            definitions = p.communicate(input=ffi_header.encode())[0].decode()
            definitions = definitions.replace("\r", "\n")
        if p.returncode != 0:
            raise RuntimeError(f"header preprocessing failed: {p.returncode}")
        return ffi_header, definitions


ffi_ext = Secp256k1CFFIExtension()

if __name__ == "__main__":
    ffi_ext.create_cffi(pathlib.Path())

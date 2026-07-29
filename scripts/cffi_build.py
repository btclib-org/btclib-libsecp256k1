# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import glob
import os
import pathlib
import platform
import re
import shutil

# [B404:blacklist] Consider possible security implications associated with the subprocess module.
# https://bandit.readthedocs.io/en/1.7.4/blacklists/blacklist_imports.html#b404-import-subprocess
import subprocess  # nosec B404
from subprocess import PIPE, Popen  # nosec B404
from sysconfig import get_config_var, get_path

import cffi

cross_compile = os.environ.get("BTCLIB_LIBSECP256K1_CROSS_COMPILE", "false") == "true"
static = os.environ.get("BTCLIB_LIBSECP256K1_DYNAMIC", "false") != "true"

# do-nothing implementations of the external default callbacks: they replace
# the abort()ing upstream defaults, so that illegal inputs never crash the
# hosting Python process; compiled as a separate unit, without mutating the
# vendored sources
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

# build the callback stubs into the library (static archive and shared
# object alike); -no-undefined is required by libtool to build a DLL
MAKEFILE_AM_EXTRA = """
# btclib additions
LDFLAGS = -no-undefined
libsecp256k1_la_SOURCES += src/btclib_default_callbacks.c
"""

# [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
# https://bandit.readthedocs.io/en/1.7.4/plugins/b603_subprocess_without_shell_equals_true.html

# [B607:start_process_with_partial_path] Starting a process with a partial executable path
# https://bandit.readthedocs.io/en/1.7.4/plugins/b607_start_process_with_partial_path.html


class FFIExtension:
    def __init__(self):
        self.clean()
        self.platform = os.environ.get("CFFI_PLATFORM", platform.system())

    @property
    def shared_library_extension(self):
        if self.platform == "Windows":
            return ".dll"
        elif self.platform == "Darwin":
            return ".dylib"
        elif self.platform == "Linux":
            return ".so"
        else:
            raise RuntimeError

    def clean(self):
        raise NotImplementedError

    def build_c(self):
        raise NotImplementedError

    def generate_def(self):
        raise NotImplementedError

    def create_cffi(self, build_dir):
        build_dir = pathlib.Path(build_dir)

        self.build_c()
        ffi = cffi.FFI()
        ffi_header, definitions = self.generate_def()
        if not self.static:
            ffi_header = None
        ffi.cdef(definitions)

        if self.static and platform.system() == "Windows":
            return ffi, self.compile_static_msvc(ffi, ffi_header, build_dir)
        ffi.set_source(self.name, ffi_header)
        if self.static:
            return ffi, self.compile_static_unix(ffi, build_dir)
        return ffi, self.emit_dynamic(ffi, build_dir)

    def compile_static_msvc(self, ffi, ffi_header, build_dir):
        # native Windows: compile the extension with the standard
        # setuptools/MSVC toolchain instead of the manual Unix one;
        # the callback stubs are compiled into the extension itself,
        # as the CMake-built static library leaves them undefined;
        # SECP256K1_STATIC selects the static-consumer declarations
        # in the header
        ffi.set_source(
            self.name,
            ffi_header + CALLBACK_STUBS,
            library_dirs=[str(d) for d in self.library_dirs],
            libraries=self.libraries,
            define_macros=[("SECP256K1_STATIC", "1")],
        )
        return [pathlib.Path(ffi.compile(tmpdir=str(build_dir)))]

    def compile_static_unix(self, ffi, build_dir):
        c_filename = f"{str(self.name)}.c"
        o_filename = f"{str(self.name)}.o"
        so_filename = str(self.name) + get_config_var("EXT_SUFFIX")
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

        subprocess.run(compile_command, cwd=build_dir, check=True)  # nosec B603 B607
        subprocess.run(link_command, cwd=build_dir, check=True)  # nosec B603 B607
        return [so_path]

    def emit_dynamic(self, ffi, build_dir):
        py_filename = f"{str(self.name)}.py"
        py_path = build_dir / py_filename

        ffi.emit_python_code(str(py_path))
        artifacts = [py_path]
        for lib in self.libraries:
            found = False
            for libs_dir in self.library_dirs:
                pattern = f"lib{lib}*{self.shared_library_extension}"
                for file in pathlib.Path(libs_dir).glob(pattern):
                    if not file.is_file():
                        continue
                    if len(file.suffixes) > 1:
                        continue
                    if found:
                        msg = f"multiple shared objects found for library: {lib}"
                        raise RuntimeError(msg)
                    shutil.copy(file, build_dir / file.name)
                    artifacts.append(build_dir / file.name)
                    found = True
                if not found:
                    raise RuntimeError(f"no shared object found for library: {lib}")

        return artifacts


class Secp256k1CFFIExtension(FFIExtension):
    def __init__(self):
        self.name = "_btclib_libsecp256k1"
        self.static = static and not cross_compile
        self.clean_patterns = [
            "_btclib_libsecp256k1.*",
            "btclib_libsecp256k1/libsecp256k1.*",
        ]
        # working directory
        self.wd = pathlib.Path(__file__).parent.parent.resolve() / "secp256k1"
        self.include_dir = self.wd / "include"
        self.headers = [
            "secp256k1.h",
            "secp256k1_extrakeys.h",
            "secp256k1_schnorrsig.h",
        ]
        self.library_dirs = [self.wd / ".libs"]
        self.libraries = ["secp256k1"]
        super().__init__()

    def clean(self) -> None:
        # in an sdist there is no .git: skip the git cleanup
        if (self.wd / ".git").exists():
            subprocess.run(
                ["git", "reset", "--hard"], cwd=self.wd, check=True
            )  # nosec B603 B607
            subprocess.run(
                ["git", "clean", "-fxd"], cwd=self.wd, check=True
            )  # nosec B603 B607
        clean_libs = any(libs_dir.exists() for libs_dir in self.library_dirs)
        if clean_libs and (self.wd / "Makefile").exists():
            subprocess.run(
                ["make", "clean"], cwd=self.wd, check=True
            )  # nosec B603 B607
        for pattern in self.clean_patterns:
            for file in glob.glob(pattern):
                os.remove(file)

    def build_c(self) -> None:
        # cross-compilation (CFFI_PLATFORM=Windows on a POSIX host) keeps
        # using autotools/mingw: dispatch on the actual system
        if platform.system() == "Windows":
            self.build_c_cmake()
        else:
            self.build_c_autotools()

    def build_c_cmake(self) -> None:
        """Build the vendored library natively on Windows (CMake, MSVC)."""
        build_dir = "build_cmake"
        configure = [
            "cmake",
            "-S",
            ".",
            "-B",
            build_dir,
            "-DBUILD_SHARED_LIBS=OFF",
            "-DSECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS=ON",
            "-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON",
            "-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON",
            "-DSECP256K1_BUILD_BENCHMARK=OFF",
            "-DSECP256K1_BUILD_TESTS=OFF",
            "-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF",
            "-DSECP256K1_BUILD_CTIME_TESTS=OFF",
            "-DSECP256K1_BUILD_EXAMPLES=OFF",
        ]
        subprocess.run(configure, cwd=self.wd, check=True)  # nosec B603 B607
        subprocess.run(
            ["cmake", "--build", build_dir, "--config", "Release"],
            cwd=self.wd,
            check=True,
        )  # nosec B603 B607
        # multi-config generators (MSVC) append the configuration name
        self.library_dirs = [
            self.wd / build_dir / "lib" / "Release",
            self.wd / build_dir / "lib",
        ]
        # the MSVC static archive is named libsecp256k1.lib
        self.libraries = ["libsecp256k1"]

    def build_c_autotools(self) -> None:
        # the callback stubs live in their own compilation unit: overwriting
        # is idempotent, so repeated build passes of a PEP 517 frontend on
        # the same tree (where the git cleanup is unavailable, e.g. in an
        # sdist) are safe
        (self.wd / "src" / "btclib_default_callbacks.c").write_text(CALLBACK_STUBS)

        # idempotent guard for the same reason as above
        makefile_am = self.wd / "Makefile.am"
        if MAKEFILE_AM_EXTRA not in makefile_am.read_text():
            with open(makefile_am, "a") as f:
                f.write(MAKEFILE_AM_EXTRA)

        subprocess.run(
            ["bash", "autogen.sh"], cwd=self.wd, check=True
        )  # nosec B603 B607
        command = [
            "bash",
            "configure",
            "--disable-tests",
            "--disable-exhaustive-tests",
            "--disable-benchmark",
            "--enable-experimental",
            "--enable-module-schnorrsig",
            "--enable-external-default-callbacks",
            "--with-pic",
        ]
        if cross_compile:
            command.append("--host=x86_64-w64-mingw32")
        elif static:
            command.append("--disable-shared")
        subprocess.run(command, cwd=self.wd, check=True)  # nosec B603

        subprocess.run(["make"], cwd=self.wd, check=True)  # nosec B603 B607
        if (self.wd / ".git").exists():
            subprocess.run(
                ["git", "reset", "--hard"], cwd=self.wd, check=True
            )  # nosec B603 B607

    def generate_def(self):
        ffi_header = ""
        for h in self.headers:
            location = self.include_dir / h
            with open(location) as f:
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
        with Popen(command, stdin=PIPE, stdout=PIPE) as p:  # nosec B603
            definitions = p.communicate(input=ffi_header.encode())[0].decode()
            definitions = definitions.replace("\r", "\n")
        if p.returncode != 0:
            raise RuntimeError(f"header preprocessing failed: {p.returncode}")
        return ffi_header, definitions


ffi_ext = Secp256k1CFFIExtension()

if __name__ == "__main__":
    ffi_ext.create_cffi(pathlib.Path("."))

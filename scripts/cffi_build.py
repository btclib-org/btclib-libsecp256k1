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
        ffi.set_source(self.name, ffi_header)

        artifacts = []

        if self.static:
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

            subprocess.call(compile_command, cwd=build_dir)  # nosec B603 B607
            subprocess.call(link_command, cwd=build_dir)  # nosec B603 B607
            artifacts.append(so_path)
        else:
            py_filename = f"{str(self.name)}.py"
            py_path = build_dir / py_filename

            ffi.emit_python_code(str(py_path))
            artifacts.append(py_path)
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

        return ffi, artifacts


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
        subprocess.call(["git", "reset", "--hard"], cwd=self.wd)  # nosec B603 B607
        subprocess.call(["git", "clean", "-fxd"], cwd=self.wd)  # nosec B603 B607
        clean_libs = False
        for libs_dir in self.library_dirs:
            if libs_dir.exists():
                clean_libs = True
        if clean_libs:
            subprocess.call(["make", "clean"], cwd=self.wd)  # nosec B603 B607
        for pattern in self.clean_patterns:
            for file in glob.glob(pattern):
                os.remove(file)

    def build_c(self) -> None:
        subprocess.call(["bash", "autogen.sh"], cwd=self.wd)  # nosec B603 B607
        with open(self.wd / "Makefile.am", "a") as f:
            f.write("\nLDFLAGS = -no-undefined\n")
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
        subprocess.call(command, cwd=self.wd)  # nosec B603

        # add source for safe callback
        # idempotent guard: in an sdist there is no .git, so the git reset
        # below cannot undo the append, and the second build pass of a
        # PEP 517 frontend would duplicate the definitions, failing the
        # compilation with "error: redefinition of ..."
        callbacks = """
            void secp256k1_default_illegal_callback_fn(const char* str, void* data) {
            }
            void secp256k1_default_error_callback_fn(const char* str, void* data) {
            }
            """
        src_file = self.wd / "src" / "secp256k1.c"
        with open(src_file) as f:
            already_appended = callbacks in f.read()
        if not already_appended:
            with open(src_file, "a") as f:
                f.write(callbacks)

        subprocess.call(["make"], cwd=self.wd)  # nosec B603 B607
        subprocess.call(["git", "reset", "--hard"], cwd=self.wd)  # nosec B603 B607

    def generate_def(self):
        ffi_header = ""
        for h in self.headers:
            location = self.include_dir / h
            with open(location) as f:
                ffi_header += f.read() + "\n"

        ffi_header = re.sub(r"#include .*", "", ffi_header)

        command = "gcc -P -E -D SECP256K1_BUILD  -".split()
        with Popen(command, stdin=PIPE, stdout=PIPE) as p:  # nosec B603
            definitions = p.communicate(input=ffi_header.encode())[0].decode()
            definitions = definitions.replace(
                '__attribute__ ((visibility ("default")))', ""
            )
            definitions = definitions.replace(
                "__attribute__ ((__warn_unused_result__))", ""
            )
            definitions = definitions.replace("\r", "\n")
        return ffi_header, definitions


ffi_ext = Secp256k1CFFIExtension()

if __name__ == "__main__":
    ffi_ext.create_cffi(pathlib.Path("."))

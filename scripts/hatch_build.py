# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Hatchling build hook: what the compiled extension makes of the wheel.

The extension is built by scripts/cffi_build.py; what is decided here is
how the wheel that carries it is labelled and what goes into it. Two
answers, and which one applies is a property of the build rather than of
this file: a static wheel has libsecp256k1 linked into a `cpNN` extension
and takes the tag hatchling infers for the interpreter, while a dynamic
one compiles no C at all and is tagged `py3-none-<platform>`, the shared
object travelling beside it as a forced include.

See scripts/README.md for the three build paths, and README.md for why
the distinction reaches the installed package at all.
"""

import os
import platform
import shutil
import sysconfig
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface[Any]):
    """The hook hatchling calls, once per target, before it builds one.

    It is registered in pyproject.toml, whose `cffi_modules` entries name
    the build description to run and the object to take out of it.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Record which platform is being built for.

        `CFFI_PLATFORM` overrides the running system, which is what makes
        a cross-compiled Windows wheel possible from Linux: everything
        downstream reads this attribute rather than asking the host.
        """
        super().__init__(*args, **kwargs)
        self.platform = os.environ.get("CFFI_PLATFORM", platform.system())

    def get_ext_object(self, script: Path, ext_name: str) -> Any:
        """Take the named object out of a cffi build description.

        Raises RuntimeError if the script defines no such name, which is a
        pyproject.toml `cffi_modules` entry that has gone stale rather
        than anything a user did.
        """
        # the cffi build description is a module of this very repository,
        # named in pyproject.toml: exec() runs it without importing it,
        # so that the build backend needs no import path setup
        src = Path(script).read_text()
        code = compile(src, script, "exec")
        build_vars = {"__name__": "__cffi__", "__file__": script}
        exec(code, build_vars, build_vars)
        if ext_name not in build_vars:
            raise RuntimeError
        return build_vars[ext_name]

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Build the extensions and tell hatchling what it is packaging.

        An sdist returns at once, carrying sources and no build; a wheel
        gets `pure_python` cleared, every artifact force-included under its
        own name, and one of the two tags -- inferred for a static build,
        `py3-none-<platform>` for a dynamic one. A wheel holding both kinds
        is a build that went wrong in a way nothing downstream could
        notice, so it is reported here rather than shipped quietly.
        """
        if self.target_name != "wheel":
            return

        cffi_config = [x.split(":") for x in self.config.get("cffi_modules", [])]

        build_dir = Path("build")
        if build_dir.exists():
            shutil.rmtree(build_dir)

        build_data["pure_python"] = False
        static = True

        for script, ext_name in cffi_config:
            ext = self.get_ext_object(script, ext_name)

            temp_dir = build_dir / ext.name
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            temp_dir.mkdir(parents=True)

            ffi, artifacts = ext.create_cffi(temp_dir)

            if ffi._assigned_source[1]:  # static
                if not static:
                    msg = "Warning: this wheel contains both dynamic and static extensions"
                    print(msg)
            else:  # dynamic
                static = False

            for artifact in artifacts:
                build_data["force_include"][artifact] = artifact.name

        if static:
            build_data["infer_tag"] = True
        else:
            build_data["tag"] = f"py3-none-{self.dynamic_platform_tag()}"

    def dynamic_platform_tag(self) -> str:
        """Platform tag of a dynamic (cffi ABI mode) wheel."""
        if self.platform != platform.system():
            # cross-compilation: the target machine cannot be inspected;
            # x86_64 mingw Windows is the only supported cross target
            return "win_amd64"
        # the architecture of the interpreter, not of the host: the two
        # differ under emulation (an x86-64 CPython on Windows arm64 or on
        # Rosetta), and what this wheel carries is a library built for the
        # former, as scripts/cffi_build.py explains
        machine = sysconfig.get_platform().rsplit("-", 1)[-1]
        if self.platform == "Windows":
            return {"amd64": "win_amd64", "arm64": "win_arm64", "win32": "win32"}[
                machine
            ]
        if self.platform == "Darwin":
            target = os.environ.get("MACOSX_DEPLOYMENT_TARGET") or platform.mac_ver()[0]
            major, _, minor = target.partition(".")
            # from macOS 11 on, compatibility is per major version
            minor = "0" if int(major) >= 11 else minor.split(".")[0]
            return f"macosx_{major}_{minor}_{machine}"
        # Linux: auditwheel repair upgrades this to a manylinux tag
        return f"{self.platform.lower()}_{machine}"

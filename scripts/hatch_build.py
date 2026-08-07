# Copyright (c) The btclib developers
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
        src = Path(script).read_text(encoding="utf-8")
        code = compile(src, script, "exec")
        build_vars = {"__name__": "__cffi__", "__file__": script}
        exec(code, build_vars, build_vars)
        if ext_name not in build_vars:
            # the message names both halves of the pyproject.toml entry,
            # that entry being the only thing that can be wrong here: a
            # bare `raise RuntimeError` said nothing at all, and this line
            # is excluded from the coverage measure, so the message is the
            # whole of what a maintainer would have to go on
            msg = f"{script} defines no {ext_name}: stale cffi_modules entry"
            raise RuntimeError(msg)
        return build_vars[ext_name]

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Build the extensions and tell hatchling what it is packaging.

        An sdist returns at once, carrying sources and no build; a wheel
        gets `pure_python` cleared, every artifact force-included under its
        own name, and one of the two tags -- inferred for a static build,
        `py3-none-<platform>` for a dynamic one.

        Raises RuntimeError unless the modules agree on which of the two it
        is. The tag is a property of the whole wheel, so a wheel holding
        both kinds has no tag that is true of it: `py3-none-<platform>`
        over a `cpNN` extension is installable on any interpreter of that
        platform and broken on most of them. Nothing downstream could
        notice, and no configuration CI builds can produce it -- which is
        why it is refused here rather than reported and shipped.
        """
        if self.target_name != "wheel":
            return

        cffi_config = [x.split(":") for x in self.config.get("cffi_modules", [])]

        build_dir = Path("build")
        if build_dir.exists():
            shutil.rmtree(build_dir)

        build_data["pure_python"] = False
        # one entry per module, True where libsecp256k1 is linked into the
        # extension. A set rather than a running flag: the disagreement is
        # what has to be caught, and a flag catches it in one order of the
        # modules only -- a dynamic module after a static one used to leave
        # the wheel tagged py3-none with no message at all
        modes = set()

        for script, ext_name in cffi_config:
            ext = self.get_ext_object(script, ext_name)

            temp_dir = build_dir / ext.name
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
            temp_dir.mkdir(parents=True)

            ffi, artifacts = ext.create_cffi(temp_dir)
            modes.add(bool(ffi._assigned_source[1]))

            for artifact in artifacts:
                build_data["force_include"][artifact] = artifact.name

        # an empty set is the same failure seen from the other side: a
        # wheel with pure_python cleared and no extension in it
        if len(modes) != 1:
            raise RuntimeError(
                "the cffi modules disagree on static/dynamic, "
                f"or there are none: {modes}"
            )

        if modes.pop():
            build_data["infer_tag"] = True
        else:
            build_data["tag"] = f"py3-none-{self.dynamic_platform_tag()}"

    def dynamic_platform_tag(self) -> str:
        """Platform tag of a dynamic (cffi ABI mode) wheel.

        Raises RuntimeError on a Windows architecture this does not know,
        rather than the KeyError a dict subscript would: the four targets
        below are the four `scripts/cffi_build.py` aims CMake at, and the
        two files disagreeing about which of them exist is the failure
        this shape rules out -- `win-arm32` was in that file and not in
        this one, so the one build that reached here would have ended in
        a bare KeyError from a dict literal.
        """
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
            tags = {
                "win32": "win32",
                "amd64": "win_amd64",
                "arm32": "win_arm32",
                "arm64": "win_arm64",
            }
            if machine not in tags:
                msg = f"no wheel tag known for the Windows architecture {machine}"
                raise RuntimeError(msg)
            return tags[machine]
        if self.platform == "Darwin":
            target = os.environ.get("MACOSX_DEPLOYMENT_TARGET") or platform.mac_ver()[0]
            major, _, minor = target.partition(".")
            # from macOS 11 on, compatibility is per major version
            minor = "0" if int(major) >= 11 else minor.split(".")[0]
            return f"macosx_{major}_{minor}_{machine}"
        # Linux: auditwheel repair upgrades this to a manylinux tag
        return f"{self.platform.lower()}_{machine}"

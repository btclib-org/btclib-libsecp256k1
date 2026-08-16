# scripts

The build backend of this package. Nothing here is
part of the installed package: `btclib_secp256k1` never imports these
modules, and they carry no public API. They are, however, shipped in the
sdist, because building it from source runs two of them.

Ruff exempts this directory from the docstring rules (`D`) and grants the
`subprocess` and `exec` allowances that driving a C build requires; the
exemptions are listed, one file at a time, under
`tool.ruff.lint.per-file-ignores` in `pyproject.toml`.

## hatch_build.py

The hatchling build hook, registered as
`tool.hatch.build.targets.wheel.hooks.custom`. It runs on the wheel
target only: an sdist is pure sources, and building one must not compile
anything.

It removes `build/` wholesale before starting, so that no artifact of a
previous configuration (static or dynamic, host or cross) survives into
the wheel, then loads each entry of its own `cffi_modules` setting and
compiles it. The description is a module of this repository, so it is run
by `exec()` rather than imported: the build backend then needs no import
path setup for a package that is not installed yet.

What it does with the result:

- every artifact is `force_include`d at the wheel root, next to the
  package, which is where `btclib_secp256k1/__init__.py` looks for it
- the wheel tag is set from the extension mode: `infer_tag` for a static
  extension, which is ABI-specific, and an explicit
  `py3-none-<platform>` for a dynamic one, which is not
- a wheel mixing both modes raises, and so does one with no extension at
  all. Neither can arise from the configurations CI builds, which is the
  argument for refusing them rather than for reporting them: nothing
  downstream inspects a wheel's tag against its contents, so a `py3-none`
  wheel carrying a `cpNN` extension would install on any interpreter of
  the platform and fail to import on most of them

`dynamic_platform_tag()` is the one place that has to name the target
platform itself, since a dynamic wheel gets no tag from the interpreter
that built it. On Linux the tag it produces is a plain `linux_*`, which
`auditwheel repair` later upgrades to a manylinux one. On macOS it reads
`MACOSX_DEPLOYMENT_TARGET`, and falls back to `platform.mac_ver()` when
nothing set one — which is honest, CMake having built the library for
that same host default, and narrow: the wheel is then one only the build
machine's macOS accepts. Every wheel that ships is built with the
variable exported, by `test.yml` for the dynamic ones and by
`cibuildwheel` for the static ones; a local build reproducing either has
to export it too, and CONTRIBUTING.md says so where it gives the
command.

## cffi_build.py

The cffi build description named in `cffi_modules`, exposing the
`ffi_ext` object the hook picks up. Three stages, in order.

**Build the vendored library.** CMake, on every platform, out of tree
into `build/secp256k1`: the submodule is only ever read from. The
configure line requests each module the bindings wrap
(`ecdh`, `recovery`, `extrakeys`, `schnorrsig`, `musig`, `ellswift`,
`silentpayments`) explicitly, rather than relying on upstream defaults,
which are not part of upstream's API and which leave `recovery` off.
One option is named for a different reason: `SECP256K1_VALGRIND` is
pinned `OFF` because its default answers with the build machine rather
than with a value — `AUTO` is `find_package(Valgrind)`, so a runner that
happens to have the header ships a library compiled with `-DVALGRIND`,
which is a wheel this repository cannot tell from any other. Upstream's
own tests, benchmarks and install rules are all turned off. A stale
CMake cache is deleted first, because it remembers the previous
configuration.

The build also replaces libsecp256k1's default callbacks, which
`abort()`, with do-nothing ones, so that an illegal input can never take
the hosting Python process down. Those are compiled as a separate unit
and attached to the library target through `CMAKE_PROJECT_INCLUDE` and a
deferred `target_sources` call; both the stub source and the CMake
fragment are written into the binary directory, so the vendored tree
stays untouched. These are only the defaults, applying to contexts whose
callbacks are unset — the shared context of the bindings installs its
own, which is how `context.check()` can raise what was reported.

**Derive the cdef.** The public headers are concatenated in dependency
order — `#include` directives are stripped before preprocessing, so the
order of the list is load-bearing — and run through `gcc -E` with
`__attribute__(x)=` defined away, which cffi cannot parse. A `gcc` on
PATH is therefore required even on Windows, where MSVC compiles the
extension.

**Compile the extension**, by one of three paths:

- static on Windows: the standard setuptools/MSVC toolchain, with
  `SECP256K1_STATIC` selecting the static-consumer declarations
- static elsewhere: `emit_c_code()`, then an explicit compile and link
  with the interpreter's own `CC`, `CCSHARED` and `LDSHARED`
- dynamic: no C is compiled at all. `emit_python_code()` writes the ABI
  mode module, and the shared libsecp256k1 is copied next to it — found
  by searching every candidate directory CMake may have used, skipping
  the versioned names of a symlink chain

Running this file directly performs the same work with the current
directory as the build directory, which is useful for an in-place build
outside a wheel:

```shell
uv run python scripts/cffi_build.py
```

### Environment variables

The mode is chosen by the environment, so that CI can build every
artifact from one source tree:

- `BTCLIB_LIBSECP256K1_DYNAMIC=true` builds the dynamic, cffi ABI mode
  extension against a shared libsecp256k1. The default is static
- `BTCLIB_LIBSECP256K1_CROSS_COMPILE=true` cross-compiles with the
  vendored mingw-w64 toolchain file, x86_64 Windows being the only
  supported target. It implies dynamic: a cross-built static extension
  would need the target interpreter's toolchain
- `CFFI_PLATFORM` overrides the detected platform when the target is not
  the host, and is what the cross-compiled wheel is tagged from; it is
  set to `Windows` alongside the variable above

Note that the two are not interchangeable as predicates: the choice
between the MSVC and the Unix static path keys off the real host, while
the shared library suffix and the wheel tag key off the target.

## The benchmark is not here

It compared these bindings against `coincurve`, `secp256k1` and btclib's
pure python arithmetic, which made the packages it timed dependencies of
this repository's lock — btclib among them, and btclib is what depends on
this package rather than the other way round. It lives in
[btclib-benchmarks](https://github.com/btclib-org/btclib-benchmarks) now,
as `scripts/libsecp256k1_wrappers.py`, where its comparands are what the
project is for.

# DeuceSSH — Drepper DSO Best Practices Audit

Audit of the shared library build against Ulrich Drepper's "How To
Write Shared Libraries" (2002), updated for modern toolchains.

The audit below is a historical build snapshot. The
[symbol-versioning plan](#symbol-versioning-plan) records the proposed v1.0
policy; version-script implementation is still outstanding.

## 1. Export Control — EXCELLENT

All functions are properly annotated:
- `DSSH_PUBLIC` (`visibility("default")`) for public API (~65 symbols)
- `DSSH_PRIVATE` (`visibility("hidden")`) for library-internal
- `static` for file-scope

No unmarked non-static symbols in any library source file.
`-fvisibility=hidden` is set on the shared library target, so any
unannotated symbol defaults to hidden.

### Global variables

Only two file-scope globals exist:
- `gconf` (`ssh-trans.c`) — zero-initialized (BSS), hidden in
  production.  No public access — all manipulation through
  setter/registration functions.
- `sw_ver` (`ssh-trans.c`) — `static const char[]`, embedded
  directly in `.rodata` (zero relocations).

No exported variables.  All state is per-instance behind opaque
`dssh_session` and `dssh_channel` handles.

## 2. Compiler/Linker Flags

| Flag | Status | Notes |
|------|--------|-------|
| `-fPIC` | Yes | Via `POSITION_INDEPENDENT_CODE ON` |
| `-fvisibility=hidden` | Yes | Shared library target only |
| `-fno-semantic-interposition` | Yes | Allows inlining across default-vis defs |
| `-Wl,-z,relro,-z,now` | Yes | Full RELRO + eager binding |
| `-Wl,--hash-style=gnu` | Yes | `.gnu.hash` for ~50% faster lookup |
| `-Wl,-Bsymbolic-functions` | Yes | Local definition preference |
| `-Wl,-O2` | Yes | String merging + tail optimization |
| Version script | No | Should be added at 1.0 for ABI stability |

ELF linker flags applied on `UNIX AND NOT APPLE` (macOS uses Mach-O).
Separate static and shared library targets.

## 3. Data Layout — EXCELLENT

- No `char *str = "literal"` at file scope (would need relocation)
- No static arrays of function pointers (each element = relocation)
- No static arrays of data pointers
- Algorithm registration is dynamic (malloc + fill at runtime), not
  static initializer tables — avoids load-time relocations entirely
- All string constants are compile-time embedded in `.rodata`
- `gconf` is zero-initialized (BSS) — no file storage, no relocations
  until the application calls setter functions

## 4. Symbol Naming — EXCELLENT

All exported symbols use a consistent `dssh_` prefix:
- Core API: `dssh_session_*`, `dssh_transport_*`, `dssh_auth_*`, etc.
- Algorithm registration: `dssh_register_*`
- Key management: `dssh_ed25519_*`, `dssh_rsa_sha2_256_*`
- Error codes: `DSSH_ERROR_*`
- Flags: `DSSH_*`

## 5. Text Relocations — NONE

- All code compiled with `-fPIC`
- No inline assembly with absolute addresses
- No non-PIC object files linked into the shared library

Verify: `readelf -d libdeucessh.so | grep TEXTREL` (no output)

## 6. Dependency Isolation — EXCELLENT

- OpenSSL linked `PRIVATE` (not propagated to consumers)
- C11 threads linked via `INTERFACE` on the static lib only
- No OpenSSL types in public headers
- No `<threads.h>` or `<stdatomic.h>` in public headers

## 7. Summary

| Criterion | Status |
|-----------|--------|
| Export control (visibility) | EXCELLENT |
| No exported variables | EXCELLENT |
| Compiler flags (PIC, visibility, interposition) | COMPLETE |
| Linker hardening (RELRO, gnu hash, Bsymbolic) | COMPLETE |
| Version script | MISSING (pre-1.0) |
| Data layout (no pointer arrays) | EXCELLENT |
| String constants in rodata | EXCELLENT |
| Zero-init globals (BSS) | EXCELLENT |
| Symbol naming (`dssh_` prefix) | EXCELLENT |
| Text relocations | NONE |
| Dependency isolation | EXCELLENT |

## Remaining

1. Review and implement the symbol-versioning plan below before the v1.0 release.

## Symbol-versioning plan

Status: **proposed for review; not implemented**. This section specifies the
policy to implement. It does not authorize changing exports or public contracts
before review.

### Initial v1.0 assignment

- Give every public, externally linked DeuceSSH function the ELF symbol version
  `DEUCESSH_1.0`. This includes the consumer APIs, crypto/result utilities,
  algorithm registration/key helpers and exported module-support APIs from all
  installed public headers.
- Keep the C names unchanged. A default ELF export will appear as, for example,
  `dssh_session_init@@DEUCESSH_1.0`; ordinary C callers continue to call
  `dssh_session_init()`.
- Use one checked-in linker version map with explicit symbol names. Do not use
  a broad `dssh_*` export wildcard, which would silently assign future additions
  to the original version. Keep every other definition local with `local: *;`,
  including private functions, bundled primitives and embedded-provider symbols.
- Keep imported dependency symbols under their providers' versioning. Public
  macros, constants, inline functions, typedefs and struct layouts have no dynamic
  symbol entry; their compatibility is part of the overall public ABI contract.
- Start with one current v1.0 definition per public function. No pre-1.0 symbol
  versions or compatibility aliases are introduced.

### Subsequent releases

| Change | Required treatment |
| --- | --- |
| Implementation fix preserving the public ABI | Keep the existing symbol version and library ABI major. |
| New public function in a minor release | Add its explicit name to a node such as `DEUCESSH_1.1`, inheriting from the preceding node. Existing symbols keep their original assignments. |
| Later patch release | Keep symbol assignments unchanged; version nodes do not follow patch numbers. |
| Incompatible signature, calling convention, exposed struct layout or public contract | Require API review and a new library ABI major. The next major starts its own baseline, such as `DEUCESSH_2.0`; symbol versioning alone does not make an incompatible public struct usable. |

For ABI major 1, retain ELF SONAME `libdeucessh.so.1` across compatible minor and
patch releases while the full library filename follows the release version.
Adding a minor version node lets the linker record which new interface a
consumer actually uses. Do not reassign old functions merely because their
implementation changed. A symbol-version node does not describe SSH wire
protocol or negotiated algorithm versions.

### Platform and build scope

| Build | Mechanism |
| --- | --- |
| ELF shared libraries, including Linux and FreeBSD | Apply the explicit version map through the actual linker driver. Versioning is required for these shared builds; an unsupported linker must produce a clear configuration failure rather than silently omit it. |
| macOS shared libraries | Apply the same public ABI policy through the dylib identity, compatibility/current versions and controlled exports. Mach-O exports do not carry GNU ELF version nodes. |
| Windows DLLs | Keep the public C export names and explicit export annotations. A future incompatible ABI major must use a distinct DLL/import-library identity. PE exports do not carry GNU ELF version nodes. |
| Static libraries | Keep ordinary C symbol names. There is no dynamic-loader version table; applications and external modules must use compatible headers, library and provider ABIs. |

This proposal does not add version suffixes to public C identifiers. The native
mechanism differs by object format; ELF symbol versioning is not presented as
available on every platform.

### Implementation and acceptance

1. Reconcile the explicit map with the public header declarations and actual
   shared-library definitions. Make the map a linker dependency so an edit
   triggers relinking. Preserve existing visibility and dependency isolation.
2. Check the built ELF library: every expected public definition has the
   `DEUCESSH_1.0` default version, none is missing or unversioned, and no private
   definition is exported. Exclude undefined dependency imports from that check.
3. Build and run a normal installed C17 consumer against the versioned shared
   library. Inspect its recorded DeuceSSH version requirements. Retain the
   existing static-consumer and applicable native export checks.
4. Run the affected existing consumer tests on both crypto backends and the
   applicable Linux/FreeBSD builds. Keep native macOS/Windows export acceptance
   distinct from ELF version-table checks. Add later-node acceptance when a
   release first introduces such a node.

The linker syntax and node-inheritance behavior follow the
[GNU linker VERSION documentation](https://sourceware.org/binutils/docs/ld/VERSION.html).

# CLAUDE.md — C library (`libwabisabi`)

Guidance for Claude Code working in `c/`. See the root `CLAUDE.md` for the project goal: **this C library must be byte-for-byte wire-compatible with the managed C# library, which is the source of truth.** When C and C# disagree, fix the C side.

## Layout

- `include/wabisabi_ffi.h` — the **public FFI and the authoritative wire-format spec** (header comment + `WABISABI_*_SIZE` constants with `_Static_assert` checks). Treat this file as the contract.
- `src/` — protocol sources, compiled in dependency order (see `CMakeLists.txt`):
  `sha256`/`strobe` → `field` → `wabisabi_types` → `generators`/`mac`/`transcript` → `proof` → `credential` → `issuer`/`client` → `ffi` (the exported boundary).
- `tests/test_main.c` + `tests/test_compat.c` — the real suite (`wabisabi_test`). `test_compat.c` ports the C# crypto unit tests one-to-one and references the originating C# test file in comments.

## Build & test

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug \
  -DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR   # offline; omit to fetch v0.7.1 from GitHub
cmake --build build
./build/wabisabi_test
```

The shared library lands at `build/libwabisabi.so`. Rebuild it before running the interop tests, which load it via `LD_LIBRARY_PATH`.

## Wire-format conventions (must match C#)

- **Scalar**: 32 bytes, **big-endian** (standard secp256k1).
- **GroupElement**: 33 bytes, **compressed**; `0x00...` encodes infinity.
- **Amount**: 8 bytes, **little-endian**.
- The exact byte layout of every message (`ZeroRequest`, `RealRequest`, `Response`, `Credential`, `ValidationState`, `MutableIssuerState`, etc.) is spelled out in the `wabisabi_ffi.h` header comment. Any change here must be mirrored in `csharp/WabiSabi/Native/WireFormat.cs` and validated by the interop suite.

## Statelessness

The C library holds **no** mutable state between calls. The issuer's balance (`MutableIssuerState`, now just an 8-byte LE balance) and the client's request-validation data (`ValidationState`, fixed 353 bytes including a serialized STROBE transcript) are serialized out and passed back in on each call. This is deliberate, to make the FFI embeddable from any host.

The C library does **not** track serial numbers: double-spend prevention (rejecting duplicated/reused serials) is left to the caller. The managed `WabiSabi.Native.CredentialIssuer` wrapper implements it with a `HashSet<GroupElement>`, mirroring the managed reference. The library performs only cryptographic verification and balance bookkeeping.

## Known divergence (the open problem)

The C library's own unit tests pass, and so do C#'s — but **proofs produced by C do not verify in C#, and vice-versa**, while issuer params match exactly. The bug is therefore in the **Fiat-Shamir challenge**: the STROBE transcript construction (`transcript.c`) or proof (de)serialization (`proof.c`, `ffi.c`) diverges from the C# `Transcript`/`ProofSystem`. To debug, dump the STROBE state and the absorbed/squeezed bytes right before the challenge scalar is derived on the zero-bootstrap proof, and compare byte-for-byte against the C# side. Fix C to match C#.

## Housekeeping

Stray `test_*.c` / built binaries at the repo root (`c/test_compat_only`, `c/test_debug`, `c/test_ge_inf`, …) are ad-hoc scratch debugging files, **not** part of the CMake build. Don't treat them as the test suite.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Goal of this project

This repository contains **two implementations of the WabiSabi anonymous-credential (KVAC over secp256k1) protocol**, and the overarching goal is to make them **fully wire-compatible**:

- `csharp/WabiSabi/` — the pure managed C# implementation. **This is the source of truth.** When the two implementations disagree, the C side is wrong, not the C# side.
- `c/` — a C shared library (`libwabisabi`) that must reproduce the C# behaviour **byte-for-byte** on the wire, plus thin C# P/Invoke wrappers in `csharp/WabiSabi/Native/` (the `WabiSabi.Native` namespace) that expose an identical API.

The two C# namespaces (`WabiSabi` managed + `WabiSabi.Native` P/Invoke) ship in **one assembly and one NuGet package, `WabiSabi`** (`csharp/WabiSabi/WabiSabi.csproj`), which also bundles per-RID native binaries under `runtimes/`. The package is built/published by `.github/workflows/nuget-publish.yml` (matrix-builds the native lib for linux-x64/arm64, win-x64, osx-x64/arm64, then packs).

"Fully compatible" means: a protocol message (issuer params, requests, responses, credentials, proofs) produced by either implementation must be accepted and correctly processed by the other. The `interop/` test suite is the arbiter of this.

## Current status (read before assuming things work)

- C unit tests (`c/build/wabisabi_test`): **pass** (127 ported C# crypto tests + integration).
- Managed unit tests (`csharp/WabiSabi.Tests`): **pass** (125).
- **Interop tests (`interop/WabiSabiInterop.Tests`): the real compatibility gate — currently 18/18 passing (verified 2026-06-30).**
  - The two implementations are now **wire-compatible**, including zero-knowledge proofs. The previously-divergent Fiat-Shamir / STROBE transcript construction has been reconciled.
  - Cross-implementation proof verification works in **both directions**: the native issuer accepts and verifies C# client proofs, and the C# issuer accepts and verifies native client proofs (`FullProtocol_CSharpClient_NativeIssuer_*`, `FullProtocol_NativeClient_CSharpIssuer_*`, plus the zero-bootstrap and real-RNG repro tests). Issuer params still match byte-for-byte.
  - **Presentation-only requests** (output registration: `Delta < 0`, zero requested credentials) are supported. The FFI real-request format carries an explicit `n_requested` count (0 or `CREDENTIAL_COUNT`) and the response carries `n_issued`, so the native issuer can verify a request that issues no credentials and return an empty response (`PresentationOnly_CSharpClient_NativeIssuer`). The native `CredentialIssuer` wrapper also maps C error codes (`WABISABI_ERR_*`) to the matching `WabiSabiCryptoErrorCode` so callers branching on `SerialNumberAlreadyUsed` etc. keep working.
  - Keep this gate green: any change to transcript construction or proof serialization on either side must keep all 18 interop tests passing.

## Build & test (essentials)

**Run all suites with `./scripts/test.sh`** — it builds the native library and runs the C, managed C#, interop, **and Python binding** tests in order. This is the canonical local test command; always use it (or at least include the Python tests) rather than running suites piecemeal, because the Python bindings are the only consumer of the FFI that nothing else in the build catches when the wire format drifts. CI runs the same four suites (`.github/workflows/{c-test,dotnet-test,python-test}.yml`).

The individual commands, if you need to run one suite in isolation:

```sh
# Managed C# library + its unit tests
dotnet build csharp/WabiSabi.sln
dotnet test  csharp/WabiSabi.Tests/WabiSabi.Tests.csproj

# C library (FetchContent pulls secp256k1 v0.7.1; pass -DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR offline)
cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release
cmake --build c/build
./c/build/wabisabi_test

# Interop compatibility tests — the compatibility gate. Needs libwabisabi.so on the loader path.
LD_LIBRARY_PATH=$PWD/c/build dotnet test interop/WabiSabiInterop.Tests/WabiSabiInterop.Tests.csproj

# Python binding tests — the Python <-> C gate. Needs libwabisabi.so + the package on PYTHONPATH.
LD_LIBRARY_PATH=$PWD/c/build PYTHONPATH=$PWD/bindings/python python3 -m pytest bindings/python/tests
```

Nix is the supported environment: `nix develop` (full C + .NET, sets `LD_LIBRARY_PATH` and `SECP256K1_SOURCE_DIR`), `nix develop .#c`, `nix develop .#dotnet`. See README for `nix build` outputs and the NuGet packing/lockfile workflow.

## Working principle

When fixing a compatibility failure, **change the C side to match C#** unless you have proven the C# behaviour itself is wrong (rare — it is the reference and is covered by 125 passing tests). The wire format is documented authoritatively in `c/include/wabisabi_ffi.h`. Per-directory CLAUDE.md files (`c/`, `csharp/`, `interop/`) hold the specifics.

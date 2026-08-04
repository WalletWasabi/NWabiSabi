# CLAUDE.md — Interop compatibility suite

Guidance for Claude Code working in `interop/`. See the root `CLAUDE.md` for the project goal. **This directory is the arbiter of C↔C# wire compatibility** — the managed and C unit suites only test each implementation against itself.

## Contents

- `Program.cs` — a non-test interop smoke-test executable (`dotnet run --project interop/WabiSabiInterop.csproj`).
- `Sha256ChainRandom.cs` — a deterministic RNG (SHA-256 chained from a seed) so reference byte vectors are stable across runs. Shared into the test project via a linked `<Compile Include>`.
- `WabiSabiInterop.Tests/BinaryCompatibilityTests.cs` — the xUnit suite. Drives the protocol with the C# client against the native issuer and vice-versa, plus an exact issuer-params byte-equality test and a credential round-trip test.
- `WabiSabiInterop.Tests/NativeLibraryFixture.cs` — xUnit collection fixture that calls `NativeWabi.Init()`/`Cleanup()` once around the collection.

## Running

```sh
# libwabisabi.so must exist (build it first) and be on the loader path:
cmake --build ../c/build
LD_LIBRARY_PATH=$PWD/../c/build dotnet test WabiSabiInterop.Tests/WabiSabiInterop.Tests.csproj
```

If the native lib is missing the csproj emits a warning at build time and the `DllImport` throws at runtime (intentional failure).

## Things learned / gotchas

- The native wrapper types live in namespace **`WabiSabi.Native`** (`CredentialIssuer`, `WabiSabiClient`, `NativeWabi`, `WireFormat`), not `WabiSabiInterop`. Tests alias them (`using NativeIssuer = WabiSabi.Native.CredentialIssuer;`) and must `using WabiSabi.Native;`. These tests had stale `WabiSabiInterop.*` references from before the wrappers were moved out of this project — watch for that drift if the wrappers move again.
- Test taxonomy in `BinaryCompatibilityTests.cs`: (1) issuer-params **exact byte equality**, (2/3) zero-bootstrap in both directions, (4/5) full two-round protocol in both directions, (6) native credential bytes survive a C# `WireFormat` parse/re-serialize unchanged.
- Interpreting failures: error code 4 from the native side is `WABISABI_ERR_INVALID_PROOF`; on the C# side, `CoordinatorReceivedInvalidProofs` (CredentialIssuer.cs) is the equivalent. Both mean the Fiat-Shamir challenge differs between implementations.

## Current state

1/6 passing — only the deterministic issuer-params byte-equality test. The other 5 fail on cross-language proof verification (the open problem; see root and `c/CLAUDE.md`). When that transcript/proof divergence is fixed on the C side, this whole suite should go green; it is the definition of "done" for compatibility.

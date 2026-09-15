# CLAUDE.md — C# projects

Guidance for Claude Code working in `csharp/`. See the root `CLAUDE.md` for the project goal.

## Projects

- `WabiSabi/` — **the source-of-truth managed reference implementation, plus the native P/Invoke wrappers, in one assembly and one NuGet package (`WabiSabi`).**
  - Managed (namespace `WabiSabi`, the reference): entry points `CredentialIssuer.cs` (coordinator) and `WabiSabiClient.cs` (client) at the project root; crypto under `Crypto/` (`Groups/`, `ZeroKnowledge/` with `ProofSystem`/`Transcript`/`LinearRelation`, `StrobeProtocol/`, `Randomness/`). This code itself has **no native dependency** — the native lib is only loaded if you touch a `WabiSabi.Native` type.
  - Native (namespace `WabiSabi.Native`) under `Native/`: thin P/Invoke wrappers over `libwabisabi` exposing an API **identical** to the managed one, so callers can swap implementations. `WireFormat.cs` (de)serializes managed types to/from the C wire format; `NativeWabi.cs` holds the `DllImport`s and size constants; `CredentialIssuer.cs`/`WabiSabiClient.cs` are the wrappers. (`Native/` also holds `NativeInterface.cs` + the `RuntimeExport`/`NativeCallable` attribute polyfills, used to export the managed lib *as* a native lib — a separate concern.)
  - Packaging: `WabiSabi.csproj` is the single package; it bundles per-RID native binaries under `runtimes/<rid>/native/` (filled by CI — see `.github/workflows/nuget-publish.yml`) and keeps `NBitcoin.Secp256k1` as a NuGet dependency.
- `WabiSabi.Tests/` — unit tests for the managed library (xUnit).

## Build & test

```sh
dotnet build csharp/WabiSabi.sln
dotnet test  csharp/WabiSabi.Tests/WabiSabi.Tests.csproj
# single test:
dotnet test  csharp/WabiSabi.Tests/WabiSabi.Tests.csproj --filter "FullyQualifiedName~SomeTestName"
```

Multi-targets net6.0–net10.0; keep new code within the lowest target's API surface unless guarded.

## Things learned / gotchas

- **`WireFormat.cs` is the C# half of the wire contract** (the C half is `c/include/wabisabi_ffi.h`). Any layout change must be made in both, then verified by the interop suite. Conventions: scalars 32-byte big-endian, group elements 33-byte compressed (`0x00…` = infinity), amounts 8-byte little-endian.
- **`ImmutableValueSequence<T>` is a struct backed by an `ImmutableArray<T>`.** A `default`/uninitialized instance throws on enumeration ("operation cannot be performed on a default instance of ImmutableArray<T>"). `.Empty` must be constructed as `new(ImmutableArray<T>.Empty)`, never `new()` — the latter leaves the backing array `default` and blows up the first time anything enumerates it (e.g. `IsNullRequest` → `Presented.Any()` on a zero-value request). This path is only hit when the issuer handles a request, and the managed unit tests didn't cover it, so the bug was latent until the interop tests exercised the C# issuer.
- The managed unit tests do **not** by themselves prove cross-language compatibility — they only test C# against C#. The `interop/` suite is what proves C↔C# compatibility.

## Open problem

Cross-language proof verification currently fails (see root `CLAUDE.md`). The C# `Transcript`/`ProofSystem` here is the reference; the fix belongs on the C side. Do not "fix" the managed proof/transcript code to chase compatibility unless you have independent evidence it is wrong — it is covered by 125 passing tests and is the agreed source of truth.

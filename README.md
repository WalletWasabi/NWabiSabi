# WabiSabi

[![CodeFactor](https://www.codefactor.io/repository/github/zksnacks/nwabisabi/badge)](https://www.codefactor.io/repository/github/zksnacks/nwabisabi)
[![.NET](https://github.com/zkSNACKs/NWabiSabi/actions/workflows/dotnet-test.yml/badge.svg)](https://github.com/zkSNACKs/NWabiSabi/actions/workflows/dotnet-test.yml)
[![NuGet](https://github.com/zkSNACKs/NWabiSabi/actions/workflows/nuget-publish.yml/badge.svg)](https://github.com/zkSNACKs/NWabiSabi/actions/workflows/nuget-publish.yml)

WabiSabi is an anonymous credential scheme used in [CoinJoin](https://en.wikipedia.org/wiki/CoinJoin) to let participants register inputs and outputs without the coordinator learning which inputs correspond to which outputs. It is based on keyed-verification anonymous credentials (KVAC) over secp256k1 and zero-knowledge proofs.

This repository contains two independent implementations of the protocol that are fully wire-compatible with each other:

| Project | Language | NuGet package |
|---|---|---|
| `csharp/WabiSabi` | C# (managed) | [`WabiSabi`](https://www.nuget.org/packages/WabiSabi) |
| `csharp/WabiSabi.Native` | C# wrappers over a C shared library | `WabiSabi.Native` |

The `interop/` directory contains an executable and test suite that verify the two implementations are binary-compatible: a request produced by one is correctly processed by the other.

---

## Repository layout

```
WabiSabi/
├── c/                          C implementation (libwabisabi)
│   ├── src/                    Protocol sources
│   ├── include/wabisabi_ffi.h  Public C API
│   ├── tests/                  C test suite
│   └── CMakeLists.txt
├── csharp/
│   ├── WabiSabi/               Managed C# library
│   ├── WabiSabi.Native/        C# wrappers over libwabisabi (P/Invoke)
│   ├── WabiSabi.Tests/         Unit tests for the managed library
│   └── WabiSabi.sln
├── interop/
│   ├── Program.cs              Cross-language interop smoke test
│   ├── WabiSabiInterop.csproj
│   └── WabiSabiInterop.Tests/  xUnit interop compatibility tests
├── benchmarks/
│   └── WabiSabiBenchmarks/     BenchmarkDotNet managed-vs-native comparison
├── flake.nix                   Root Nix flake (C + .NET + NuGet)
└── c/flake.nix                 Standalone C-only Nix flake
```

---

## The managed library — `WabiSabi`

A pure C# implementation with no native dependencies. It provides:

- `CredentialIssuer` — coordinator-side: validates requests, issues MACs, tracks serial numbers
- `WabiSabiClient` — client-side: builds zero and real credential requests, validates responses
- The full zero-knowledge proof system (range proofs, balance proofs, show-credential proofs)

### Build and test

```sh
dotnet build  csharp/WabiSabi.sln
dotnet test   csharp/WabiSabi.Tests/WabiSabi.Tests.csproj
```

### Use as a NuGet dependency

```sh
dotnet add package WabiSabi
```

```csharp
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;

var sk      = new CredentialIssuerSecretKey(SecureRandom.Instance);
var iparams = sk.ComputeCredentialIssuerParameters();

var issuer = new CredentialIssuer(sk, SecureRandom.Instance, maxAmount: 100_000_000);
var client = new WabiSabiClient(iparams, SecureRandom.Instance, rangeProofUpperBound: 100_000_000);

// Round 1 — bootstrap zero-value credentials
var zeroData = client.CreateRequestForZeroAmount();
var zeroResp = issuer.HandleRequest(zeroData.CredentialsRequest);
var zeroCreds = client.HandleResponse(zeroResp, zeroData.CredentialsResponseValidation);

// Round 2 — register an input of 500 000 satoshis
var realData  = client.CreateRequest(new[] { 500_000L }, zeroCreds, CancellationToken.None);
var realResp  = issuer.HandleRequest(realData.CredentialsRequest);
var valueCreds = client.HandleResponse(realResp, realData.CredentialsResponseValidation);
```

---

## The native library — `WabiSabi.Native`

A C shared library (`libwabisabi.so` / `wabisabi.dll` / `libwabisabi.dylib`) that implements the same protocol in C, plus thin C# P/Invoke wrappers that expose an identical API to the managed library. This lets you swap `WabiSabi.Native` in for `WabiSabi` without changing any calling code.

The C library is **stateless**: all mutable state (issuer serial-number set, balance) is serialized to a byte array and passed back in on each call, making it straightforward to embed in any language.

### Build the C library

Prerequisites: `cmake`, a C11 compiler, and an internet connection (or a local secp256k1 checkout).

```sh
cmake -B c/build -S c \
  -DCMAKE_BUILD_TYPE=Release \
  [-DFETCHCONTENT_SOURCE_DIR_SECP256K1=/path/to/secp256k1]
cmake --build c/build
```

The shared library is written to `c/build/libwabisabi.so` (Linux), `c/build/wabisabi.dll` (Windows), or `c/build/libwabisabi.dylib` (macOS).

### Build and test the C# wrappers

```sh
dotnet build csharp/WabiSabi.Native/WabiSabi.Native.csproj
```

The interop tests require `libwabisabi.so` to be on `LD_LIBRARY_PATH`:

```sh
LD_LIBRARY_PATH=$PWD/c/build \
  dotnet test interop/WabiSabiInterop.Tests/WabiSabiInterop.Tests.csproj
```

---

## Performance — managed vs. native

`benchmarks/WabiSabiBenchmarks` is a [BenchmarkDotNet](https://benchmarkdotnet.org/)
project that runs a complete client⇄coordinator exchange against each
implementation: a zero-credential **bootstrap**, a real-value **issuance**
round, and then one or more **reissuance** rounds where real credentials are
presented to obtain new real credentials (balance-neutral). Issuer key/parameter
generation is excluded from the measured work; every measured round performs
proof generation, proof verification + MAC issuance, and issuance-proof
verification.

| Implementation | Reissuance rounds | Mean | Ratio | Allocated |
|---|--:|--:|--:|--:|
| Managed C# | 1 | 198.9 ms | 1.00 | 13.03 MB |
| Native C   | 1 |  56.8 ms | 0.29 |  2.63 MB |
| Managed C# | 3 | 389.8 ms | 1.00 | 25.87 MB |
| Native C   | 3 | 108.6 ms | 0.28 |  3.13 MB |

The native library runs the full protocol roughly **3.4× faster** while
allocating **5–8× less** managed memory. Numbers are hardware-dependent — treat
the ratio between the two rows as the comparable result, not the absolute
milliseconds.

```sh
cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build
LD_LIBRARY_PATH=$PWD/c/build \
  dotnet run -c Release --project benchmarks/WabiSabiBenchmarks
```

See `benchmarks/README.md` for details and flags.

---

## Nix flake

The root `flake.nix` automates building both the C library and the NuGet package, including cross-compilation for all supported platforms.

### Available outputs

| Command | Description |
|---|---|
| `nix build` | Build the C library and run the C test suite |
| `nix build .#wabisabi-c` | Same as above (explicit) |
| `nix build .#wabisabi-nuget` | Pack `WabiSabi.Native.nupkg` with binaries for linux-x64, linux-arm64, and win-x64 |
| `nix run .#test` | Execute the C test binary |
| `nix develop` | Combined C + .NET dev shell |
| `nix develop .#c` | C-only dev shell (cmake, ninja, clangd, gdb) |
| `nix develop .#dotnet` | .NET-only dev shell |

> **macOS binaries**: cross-compilation from Linux requires the macOS SDK, which is not available in nixpkgs. To include an `osx-x64` binary in the package, build on a macOS host — the flake detects the Darwin host and includes the binary automatically.

### Regenerate the NuGet lock file

If you add or update NuGet dependencies in `WabiSabi.Native.csproj`, regenerate the lock file used by Nix:

```sh
nix build .#packages.x86_64-linux.wabisabi-nuget.passthru.fetch-deps
./result csharp/WabiSabi.Native/nuget-deps.nix
```

### Dev shells

```sh
# C development (auto-generates compile_commands.json for clangd)
nix develop .#c

# .NET development
nix develop .#dotnet

# Full interop development (C + .NET, sets LD_LIBRARY_PATH and SECP256K1_SOURCE_DIR)
nix develop
```

Inside the default dev shell you can run the full build and test cycle:

```sh
# Build the C library
cmake -B c/build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR -S c
cmake --build c/build

# C tests
./c/build/wabisabi_test

# .NET tests
dotnet test csharp/WabiSabi.Tests/WabiSabi.Tests.csproj

# Interop tests
dotnet test interop/WabiSabiInterop.Tests/WabiSabiInterop.Tests.csproj

# Interop smoke test
dotnet run --project interop/WabiSabiInterop.csproj
```

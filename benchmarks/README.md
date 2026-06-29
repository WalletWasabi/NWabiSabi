# WabiSabi benchmarks

BenchmarkDotNet comparison of the **managed C#** reference implementation
(`csharp/WabiSabi`) against the **native C** library (`c/`, via the
`WabiSabi.Native` P/Invoke wrappers).

## What is measured

`ProtocolBenchmarks` runs a complete client⇄coordinator credential exchange,
not just a zero→real bootstrap. Each measured operation performs:

1. **Bootstrap** — client requests `k` zero-value credentials.
2. **Issuance** — client presents the zero credentials and obtains `k`
   real-value credentials (amounts summing to `S`).
3. **Reissuance ×N** — client presents its **real** credentials and requests
   `k` new **real** credentials whose amounts again sum to `S` (balance-neutral).
   This is the "send real credentials, get more real credentials" round, and at
   least one always runs. The `ReissuanceRounds` parameter (`1`, `3`) controls
   how many.

Every round exercises proof generation, proof verification + MAC issuance, and
issuance-proof verification, so the figures reflect the end-to-end
cryptographic cost of the protocol. Issuer key/parameter generation happens in
`[GlobalSetup]` and is excluded from the measured work.

The same workload is run twice per parameter set — once entirely against the
managed implementation (`Managed C#`, the baseline) and once entirely against
the native one (`Native C`).

## Running

The native shared library must be built first and on the loader path:

```sh
cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release
cmake --build c/build

LD_LIBRARY_PATH=$PWD/c/build \
  dotnet run -c Release --project benchmarks/WabiSabiBenchmarks
```

Inside `nix develop`, `LD_LIBRARY_PATH` is already set, so the prefix can be
dropped. The csproj also copies `libwabisabi.so` next to the benchmark
assembly, so a plain `dotnet run -c Release --project benchmarks/WabiSabiBenchmarks`
generally resolves the library too.

Useful flags:

```sh
# A quick, lower-fidelity pass while iterating.
dotnet run -c Release --project benchmarks/WabiSabiBenchmarks -- --job short

# Only one of the two implementations.
dotnet run -c Release --project benchmarks/WabiSabiBenchmarks -- --filter '*Native*'
```

## Notes

- Both paths run each implementation **against itself** (managed client ↔
  managed issuer, native client ↔ native issuer), so the cross-language proof
  divergence tracked in the root `CLAUDE.md` does not affect these runs.
- Numbers are hardware-dependent; treat the **ratio** between the two rows as
  the comparable result, not the absolute milliseconds.

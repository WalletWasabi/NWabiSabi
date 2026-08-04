# CLAUDE.md — Python bindings (`wabisabi`)

Guidance for Claude Code working in `bindings/python/`. See the root `CLAUDE.md`
for the project goal and `bindings/CLAUDE.md` for rules common to all bindings.
These bindings are a **`ctypes` wrapper over `libwabisabi`** — the
same shared library the C# `WabiSabi.Native` P/Invoke layer wraps. They add no
crypto of their own; they marshal bytes to/from the C FFI.

## Layout

- `wabisabi/_native.py` — the `ctypes` boundary: library loading,
  `argtypes`/`restype` for every exported `wabisabi_*` function, the
  `WABISABI_*_SIZE` constants, `WabiSabiError`, and byte-oriented wrappers that
  map 1:1 to `c/include/wabisabi_ffi.h`. **This is the file to change when the
  FFI signature or wire layout changes.**
- `wabisabi/__init__.py` — the **public API**, deliberately small:
  `CredentialIssuer`, `Client`, `Credential`, `OwnershipProof` (+
  `OwnershipScriptPubKeyType`), `WabiSabiError`. It calls into `_native` but does
  not re-export the low-level functions, constants, or the runtime lifecycle
  (`init`/`cleanup`) — those stay private.
- `examples/roundtrip.py` — runnable end-to-end zero + real round.
- `examples/ownership_proof.py` — runnable ownership-proof generate + verify.
- `tests/test_roundtrip.py` — KVAC smoke tests; run standalone or under pytest.
- `tests/test_ownership_proof.py` — ownership-proof smoke tests (SLIP-0019 /
  BIP-322). The scriptPubKey vectors are derived from a fixed private key (the
  same fixture the C# interop suite uses), so the test is self-contained.

## Source of truth

`c/include/wabisabi_ffi.h` is the wire-format contract. The constants and
function prototypes in `_native.py` must match it exactly, just as
`csharp/WabiSabi.Native/NativeWabi.cs` does. If the C header changes, mirror it
here. Do not invent a different layout.

## Build & run

The bindings need a built shared library; they do **not** build it.

```sh
# build the C library first (from repo root)
cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build

# run tests / example (python is provided via nix-shell in this environment)
LD_LIBRARY_PATH=$PWD/c/build PYTHONPATH=$PWD/bindings/python \
  nix-shell -p python3 --run "python3 bindings/python/tests/test_roundtrip.py"
```

`_native.py` auto-discovers `c/build/libwabisabi.so` from a developer checkout,
so `LD_LIBRARY_PATH` is often optional; `$WABISABI_LIB` overrides the search.

## Gotchas

- `python3` is not on the bare PATH in this environment — use `nix-shell -p python3`.
- The runtime is initialized once on import (`_native` calls `wabisabi_init()`).
  Don't call `cleanup()` and then keep using the library without `init()`.
- The library is **stateless**: the issuer's `mstate` and the client's
  per-request `validation_state` are serialized bytes the caller must thread
  through. The high-level classes do this; the low-level functions hand it back
  to you.
- Scalars are 32-byte big-endian, group elements 33-byte compressed, amounts
  8-byte little-endian — matching the C and C# sides.
- These tests prove the **Python ↔ C** path. Cross-language C ↔ C# proof
  verification is a separate open problem tracked in the root `CLAUDE.md`; it is
  unrelated to and unaffected by these bindings.

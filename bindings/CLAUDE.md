# CLAUDE.md — language bindings (`bindings/`)

Guidance for Claude Code working in `bindings/`. See the root `CLAUDE.md` for
the overall project goal. This directory holds **thin foreign-language wrappers
over the C shared library** (`c/libwabisabi`). Each subdirectory is one
language's binding (`bindings/python/`, and more to come).

## What a binding is — and is not

- It **is** a marshalling layer: it calls the exported `wabisabi_*` functions
  declared in `c/include/wabisabi_ffi.h`, converting that language's types
  to/from the C wire bytes.
- It is **not** a reimplementation of the protocol. No binding contains crypto.
  If a binding and the C library disagree, the binding is wrong — fix the
  binding, never the C/C# reference. (The C library itself tracks the C#
  source of truth; see the root and `c/` CLAUDE.md.)

## Rules for every binding

- **Mirror the FFI exactly.** Function signatures, the `WABISABI_*_SIZE`
  constants, error codes, and the byte layout of each message must match
  `c/include/wabisabi_ffi.h`. When that header changes, update every binding
  **and run the binding tests** — they are the only thing that catches a binding
  drifting from the wire format. Bindings are not in the C↔C# interop gate, so a
  layout change (e.g. the `n_presented` byte added to `RealRequest`) can silently
  break a binding otherwise. Run `./scripts/test.sh` from the repo root (it runs
  every suite, bindings included) or at least the affected binding's tests.
  CI runs the Python suite on every push/PR (`.github/workflows/python-test.yml`).
- **Keep the public surface small.** Expose the high-level, stateful API
  (issuer / client / credential / error type). Keep the raw FFI, size
  constants, and runtime lifecycle (`init`/`cleanup`) private — the library is
  initialized on load and needs no caller setup.
- **Don't build the C library.** Bindings load a prebuilt
  `libwabisabi.{so,dylib,dll}`. Locate it via an env override, a co-located
  copy, the in-repo `c/build/` output, then the system loader path.
- **Wire conventions** (same across all bindings): scalars 32-byte big-endian,
  group elements 33-byte compressed (`0x00…` = infinity), amounts 8-byte
  little-endian; the issuer's `mstate` and the client's per-request
  `validation_state` are opaque `bytes` the caller threads through.

## Adding a new binding

Put it in `bindings/<lang>/`, give it its own `README.md` and `CLAUDE.md`,
mirror the three protocol steps (issuer params → request/handle → response),
and add a round-trip test that exercises a zero bootstrap followed by a real
round against `c/build/libwabisabi`. Then list it in `bindings/README.md`.

## Per-binding notes

- `python/` — `ctypes`, no build step. `python3` is not on the bare PATH in
  this environment; run it via `nix-shell -p python3`. See `python/CLAUDE.md`.

#!/usr/bin/env bash
#
# Canonical test runner for the WabiSabi repo.
#
# Runs *every* test suite, in dependency order, against a freshly built native
# library:
#   1. C unit tests            (c/build/wabisabi_test)
#   2. Managed C# unit tests   (csharp/WabiSabi.Tests)
#   3. Interop compatibility   (interop/WabiSabiInterop.Tests) — the C <-> C# gate
#   4. Python binding tests    (bindings/python/tests) — the Python <-> C gate
#
# The Python suite is a first-class part of the local test run: the bindings are
# a thin ctypes wrapper over the same libwabisabi.so, and nothing else catches
# them drifting from the FFI wire format (see bindings/CLAUDE.md).
#
# Usage:  ./scripts/test.sh
# Inside `nix develop` all toolchains (cmake, dotnet, python3+pytest) are on PATH.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BUILD_DIR="$ROOT/c/build"
GREEN=$'\033[32m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
section() { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$RESET"; }

# ---------------------------------------------------------------------------
# 1. Build the native library + C test binary
# ---------------------------------------------------------------------------
section "Building native library (c/build)"
if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  # Fresh configure. Use the offline secp256k1 source when the dev shell exports
  # it; otherwise CMake FetchContent pulls v0.7.1 from GitHub.
  cmake_args=(-B "$BUILD_DIR" -S "$ROOT/c" -DCMAKE_BUILD_TYPE=Release)
  if [ -n "${SECP256K1_SOURCE_DIR:-}" ]; then
    cmake_args+=(-DFETCHCONTENT_FULLY_DISCONNECTED=ON
                 "-DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR")
  fi
  cmake "${cmake_args[@]}"
fi
cmake --build "$BUILD_DIR"

export LD_LIBRARY_PATH="$BUILD_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# ---------------------------------------------------------------------------
# 2. C unit tests
# ---------------------------------------------------------------------------
section "C unit tests (wabisabi_test)"
"$BUILD_DIR/wabisabi_test"

# ---------------------------------------------------------------------------
# 3. Managed C# unit tests
# ---------------------------------------------------------------------------
if command -v dotnet >/dev/null 2>&1; then
  section "Managed C# unit tests (WabiSabi.Tests)"
  dotnet test "$ROOT/csharp/WabiSabi.Tests/WabiSabi.Tests.csproj"

  section "Interop compatibility tests (C <-> C#)"
  dotnet test "$ROOT/interop/WabiSabiInterop.Tests/WabiSabiInterop.Tests.csproj"
else
  echo "WARNING: dotnet not found — skipping C# unit + interop tests." >&2
fi

# ---------------------------------------------------------------------------
# 4. Python binding tests (Python <-> C)
# ---------------------------------------------------------------------------
section "Python binding tests (bindings/python)"
if command -v python3 >/dev/null 2>&1; then
  export PYTHONPATH="$ROOT/bindings/python${PYTHONPATH:+:$PYTHONPATH}"
  if python3 -c 'import pytest' >/dev/null 2>&1; then
    python3 -m pytest "$ROOT/bindings/python/tests" -q
  else
    # No pytest — the suites also run standalone.
    for t in "$ROOT"/bindings/python/tests/test_*.py; do
      echo "  running $(basename "$t")"
      python3 "$t"
    done
  fi
else
  echo "ERROR: python3 not found — the Python binding tests are required." >&2
  echo "       Enter 'nix develop' (or install python3) and re-run." >&2
  exit 1
fi

printf '\n%s%sAll test suites passed.%s\n' "$GREEN" "$BOLD" "$RESET"

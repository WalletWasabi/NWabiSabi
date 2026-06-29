"""Low-level ctypes bindings for ``libwabisabi``.

This module is a faithful, byte-oriented mirror of the C FFI declared in
``c/include/wabisabi_ffi.h`` (and of the C# ``WabiSabi.Native.NativeWabi``
P/Invoke layer). Every function operates on raw wire-format ``bytes`` and
raises :class:`WabiSabiError` on a non-zero native error code.

The C library is *stateless*: all mutable state (the issuer's serial-number
set + balance, the client's per-request validation state) is serialized to
``bytes`` and passed back in explicitly. The higher-level helpers in
:mod:`wabisabi` wrap that state for you.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes.util import find_library

# ---- Wire-format sizes (mirror of the C WABISABI_*_SIZE constants) ----
SCALAR_SIZE = 32           # secp256k1 scalar, big-endian
GE_SIZE = 33               # compressed secp256k1 point (0x00... = infinity)
VALUE_SIZE = 8             # 8-byte little-endian amount
RAND_SIZE = SCALAR_SIZE
SK_SIZE = 5 * SCALAR_SIZE          # w + wp + x0 + x1 + ya = 160
IPARAMS_SIZE = 2 * GE_SIZE         # Cw + I = 66
MAC_SIZE = SCALAR_SIZE + GE_SIZE   # 65
PRESENTATION_SIZE = 5 * GE_SIZE    # Ca Cx0 Cx1 CV S = 165
CREDENTIAL_SIZE = VALUE_SIZE + SCALAR_SIZE + MAC_SIZE   # 105
CREDENTIAL_COUNT = 2

# Fixed serialized client validation-state size:
#   strobe(203) + n_requested(4) + 2*(value(8)+randomness(32)+ma(33)) = 353
VALIDATION_SIZE = 353

# Mutable issuer state: balance(8) + count(4) + count*GE_SIZE
ISSUER_MAX_SERIALS = 65536
ISSUER_MSTATE_MAX_SIZE = 8 + 4 + ISSUER_MAX_SERIALS * GE_SIZE

# Output buffer the C header guarantees is always large enough for any response.
_RESP_BUF_SIZE = 16 * 1024

# ---- Error codes (mirror of wabisabi_error_t) ----
WABISABI_OK = 0
_ERROR_NAMES = {
    0: "WABISABI_OK",
    1: "WABISABI_ERR_NULL_PTR",
    2: "WABISABI_ERR_INVALID_LENGTH",
    3: "WABISABI_ERR_PARSE",
    4: "WABISABI_ERR_INVALID_PROOF",
    5: "WABISABI_ERR_INVALID_CRED_COUNT",
    6: "WABISABI_ERR_INVALID_BIT_COMMITMENT",
    7: "WABISABI_ERR_SERIAL_DUPLICATED",
    8: "WABISABI_ERR_SERIAL_REUSED",
    9: "WABISABI_ERR_NEGATIVE_BALANCE",
    10: "WABISABI_ERR_SERIAL_SET_FULL",
}


class WabiSabiError(Exception):
    """Raised when a native ``wabisabi_*`` call returns a non-zero error code."""

    def __init__(self, code: int, func: str = ""):
        self.code = code
        self.name = _ERROR_NAMES.get(code, f"WABISABI_ERR_UNKNOWN({code})")
        where = f" in {func}" if func else ""
        super().__init__(f"{self.name} (code {code}){where}")


# --------------------------------------------------------------------------
# Library loading
# --------------------------------------------------------------------------

def _candidate_paths() -> list[str]:
    """Build an ordered list of places to look for the shared library."""
    if sys.platform == "darwin":
        names = ["libwabisabi.dylib", "wabisabi.dylib"]
    elif sys.platform.startswith("win"):
        names = ["wabisabi.dll", "libwabisabi.dll"]
    else:
        names = ["libwabisabi.so", "wabisabi.so"]

    paths: list[str] = []

    # 1. Explicit override.
    env = os.environ.get("WABISABI_LIB")
    if env:
        paths.append(env)

    # 2. Alongside this package (e.g. a bundled wheel).
    here = os.path.dirname(os.path.abspath(__file__))
    for name in names:
        paths.append(os.path.join(here, name))

    # 3. The in-repo CMake build output (developer checkout): walk up from this
    #    package looking for a sibling c/build/<lib>, wherever the bindings live.
    cur = here
    for _ in range(6):
        cur = os.path.dirname(cur)
        for name in names:
            paths.append(os.path.join(cur, "c", "build", name))

    # 4. Bare names — let the dynamic loader use LD_LIBRARY_PATH / system paths.
    paths.extend(names)

    return paths


def _load_library() -> ctypes.CDLL:
    errors = []
    for path in _candidate_paths():
        try:
            return ctypes.CDLL(path)
        except OSError as exc:  # noqa: PERF203 - tolerant probing is intentional
            errors.append(f"  {path}: {exc}")

    # Last resort: ctypes.util.find_library by soname.
    located = find_library("wabisabi")
    if located:
        try:
            return ctypes.CDLL(located)
        except OSError as exc:
            errors.append(f"  {located}: {exc}")

    raise OSError(
        "Could not load libwabisabi. Build it with\n"
        "    cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build\n"
        "and either set WABISABI_LIB=/path/to/libwabisabi.so, add its directory to\n"
        "LD_LIBRARY_PATH, or copy it next to the wabisabi package.\n"
        "Tried:\n" + "\n".join(errors)
    )


_lib = _load_library()

# --------------------------------------------------------------------------
# Function prototypes
# --------------------------------------------------------------------------

_c_intp = ctypes.POINTER(ctypes.c_int)

_lib.wabisabi_init.restype = None
_lib.wabisabi_init.argtypes = []

_lib.wabisabi_cleanup.restype = None
_lib.wabisabi_cleanup.argtypes = []

_lib.wabisabi_iparams_from_sk.restype = ctypes.c_int
_lib.wabisabi_iparams_from_sk.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

_lib.wabisabi_issuer_handle_zero.restype = ctypes.c_int
_lib.wabisabi_issuer_handle_zero.argtypes = [
    ctypes.c_char_p,                 # sk_bytes
    ctypes.c_int64,                  # max_amount
    ctypes.c_char_p, ctypes.c_int,   # mstate_in, mstate_in_len
    ctypes.c_char_p, ctypes.c_int,   # req_bytes, req_len
    ctypes.c_char_p,                 # rand_bytes
    ctypes.c_char_p, _c_intp,        # resp_out, resp_len_out
    ctypes.c_char_p, _c_intp,        # mstate_out, mstate_out_len
]

_lib.wabisabi_issuer_handle_real.restype = ctypes.c_int
_lib.wabisabi_issuer_handle_real.argtypes = _lib.wabisabi_issuer_handle_zero.argtypes

_lib.wabisabi_client_create_zero_request.restype = ctypes.c_int
_lib.wabisabi_client_create_zero_request.argtypes = [
    ctypes.c_char_p,                 # rand_bytes
    ctypes.c_char_p, _c_intp,        # req_out, req_len_out
    ctypes.c_char_p,                 # val_out[VALIDATION_SIZE]
]

_lib.wabisabi_client_create_real_request.restype = ctypes.c_int
_lib.wabisabi_client_create_real_request.argtypes = [
    ctypes.c_char_p,                       # iparams_bytes
    ctypes.c_int64,                        # max_amount
    ctypes.POINTER(ctypes.c_int64), ctypes.c_int,  # amounts, n_amounts
    ctypes.c_char_p, ctypes.c_int,         # creds_bytes, n_creds
    ctypes.c_char_p,                       # rand_bytes
    ctypes.c_char_p, _c_intp,              # req_out, req_len_out
    ctypes.c_char_p,                       # val_out[VALIDATION_SIZE]
]

_lib.wabisabi_client_handle_response.restype = ctypes.c_int
_lib.wabisabi_client_handle_response.argtypes = [
    ctypes.c_char_p,                 # iparams_bytes
    ctypes.c_char_p, ctypes.c_int,   # resp_bytes, resp_len
    ctypes.c_char_p,                 # val_bytes[VALIDATION_SIZE]
    ctypes.c_char_p, _c_intp,        # creds_out, n_creds_out
]


# Initialize the runtime exactly once on import (context + generators).
# This is internal: callers use the high-level wrappers and never manage the
# runtime lifecycle themselves.
_lib.wabisabi_init()


def _check(code: int, func: str) -> None:
    if code != WABISABI_OK:
        raise WabiSabiError(code, func)


# --------------------------------------------------------------------------
# Pythonic, byte-oriented wrappers
# --------------------------------------------------------------------------

def iparams_from_sk(sk_bytes: bytes) -> bytes:
    """Compute issuer parameters ``Cw || I`` (66 bytes) from a 160-byte secret key."""
    if len(sk_bytes) != SK_SIZE:
        raise ValueError(f"sk_bytes must be {SK_SIZE} bytes, got {len(sk_bytes)}")
    out = ctypes.create_string_buffer(IPARAMS_SIZE)
    _check(_lib.wabisabi_iparams_from_sk(bytes(sk_bytes), out), "iparams_from_sk")
    return out.raw[:IPARAMS_SIZE]


def _issuer_handle(func, fname: str, sk_bytes, max_amount, mstate_in, req_bytes, rand_bytes):
    if len(sk_bytes) != SK_SIZE:
        raise ValueError(f"sk_bytes must be {SK_SIZE} bytes, got {len(sk_bytes)}")
    if len(rand_bytes) != RAND_SIZE:
        raise ValueError(f"rand_bytes must be {RAND_SIZE} bytes, got {len(rand_bytes)}")
    mstate_in = mstate_in or b""

    resp_out = ctypes.create_string_buffer(_RESP_BUF_SIZE)
    resp_len = ctypes.c_int(0)
    mstate_out = ctypes.create_string_buffer(ISSUER_MSTATE_MAX_SIZE)
    mstate_len = ctypes.c_int(0)

    code = func(
        bytes(sk_bytes),
        ctypes.c_int64(max_amount),
        bytes(mstate_in), len(mstate_in),
        bytes(req_bytes), len(req_bytes),
        bytes(rand_bytes),
        resp_out, ctypes.byref(resp_len),
        mstate_out, ctypes.byref(mstate_len),
    )
    _check(code, fname)
    return resp_out.raw[:resp_len.value], mstate_out.raw[:mstate_len.value]


def issuer_handle_zero(sk_bytes, max_amount, mstate_in, req_bytes, rand_bytes):
    """Handle a zero (bootstrap) request. Returns ``(response_bytes, new_mstate)``."""
    return _issuer_handle(
        _lib.wabisabi_issuer_handle_zero, "issuer_handle_zero",
        sk_bytes, max_amount, mstate_in, req_bytes, rand_bytes)


def issuer_handle_real(sk_bytes, max_amount, mstate_in, req_bytes, rand_bytes):
    """Handle a real request. Returns ``(response_bytes, new_mstate)``."""
    return _issuer_handle(
        _lib.wabisabi_issuer_handle_real, "issuer_handle_real",
        sk_bytes, max_amount, mstate_in, req_bytes, rand_bytes)


def client_create_zero_request(rand_bytes: bytes):
    """Create a zero (bootstrap) request. Returns ``(request_bytes, validation_state)``."""
    if len(rand_bytes) != RAND_SIZE:
        raise ValueError(f"rand_bytes must be {RAND_SIZE} bytes, got {len(rand_bytes)}")
    req_out = ctypes.create_string_buffer(_RESP_BUF_SIZE)
    req_len = ctypes.c_int(0)
    val_out = ctypes.create_string_buffer(VALIDATION_SIZE)
    _check(
        _lib.wabisabi_client_create_zero_request(
            bytes(rand_bytes), req_out, ctypes.byref(req_len), val_out),
        "client_create_zero_request")
    return req_out.raw[:req_len.value], val_out.raw[:VALIDATION_SIZE]


def client_create_real_request(iparams_bytes, max_amount, amounts, creds_bytes, n_creds, rand_bytes):
    """Create a real request.

    ``amounts`` is a sequence of ints; ``creds_bytes`` is ``n_creds`` packed
    credentials (each :data:`CREDENTIAL_SIZE` bytes). Returns
    ``(request_bytes, validation_state)``.
    """
    if len(iparams_bytes) != IPARAMS_SIZE:
        raise ValueError(f"iparams_bytes must be {IPARAMS_SIZE} bytes, got {len(iparams_bytes)}")
    if len(rand_bytes) != RAND_SIZE:
        raise ValueError(f"rand_bytes must be {RAND_SIZE} bytes, got {len(rand_bytes)}")
    creds_bytes = creds_bytes or b""

    amounts = list(amounts)
    n_amounts = len(amounts)
    amounts_arr = (ctypes.c_int64 * n_amounts)(*amounts) if n_amounts else None

    req_out = ctypes.create_string_buffer(_RESP_BUF_SIZE)
    req_len = ctypes.c_int(0)
    val_out = ctypes.create_string_buffer(VALIDATION_SIZE)

    code = _lib.wabisabi_client_create_real_request(
        bytes(iparams_bytes),
        ctypes.c_int64(max_amount),
        amounts_arr, n_amounts,
        bytes(creds_bytes), n_creds,
        bytes(rand_bytes),
        req_out, ctypes.byref(req_len),
        val_out,
    )
    _check(code, "client_create_real_request")
    return req_out.raw[:req_len.value], val_out.raw[:VALIDATION_SIZE]


def client_handle_response(iparams_bytes, resp_bytes, val_bytes):
    """Process an issuer response and return packed issued credentials (bytes)."""
    if len(iparams_bytes) != IPARAMS_SIZE:
        raise ValueError(f"iparams_bytes must be {IPARAMS_SIZE} bytes, got {len(iparams_bytes)}")
    if len(val_bytes) != VALIDATION_SIZE:
        raise ValueError(f"val_bytes must be {VALIDATION_SIZE} bytes, got {len(val_bytes)}")

    creds_out = ctypes.create_string_buffer(CREDENTIAL_COUNT * CREDENTIAL_SIZE)
    n_creds = ctypes.c_int(0)
    code = _lib.wabisabi_client_handle_response(
        bytes(iparams_bytes),
        bytes(resp_bytes), len(resp_bytes),
        bytes(val_bytes),
        creds_out, ctypes.byref(n_creds),
    )
    _check(code, "client_handle_response")
    return creds_out.raw[:n_creds.value * CREDENTIAL_SIZE]

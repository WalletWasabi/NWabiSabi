"""Smoke tests for the Python bindings.

These exercise the FFI through the high-level wrappers. They run under any
test runner (pytest) or standalone (`python3 test_roundtrip.py`). The shared
library must be loadable (built into c/build, or WABISABI_LIB / LD_LIBRARY_PATH
pointing at it).
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Public API only — the FFI plumbing in wabisabi._native is intentionally private.
from wabisabi import Client, Credential, CredentialIssuer, WabiSabiError  # noqa: E402

MAX_AMOUNT = 1 << 32
CREDENTIAL_COUNT = 2
CREDENTIAL_SIZE = 105
IPARAMS_SIZE = 66
VALIDATION_SIZE = 353


def test_iparams_deterministic():
    sk = os.urandom(160)
    a = CredentialIssuer(sk, MAX_AMOUNT).iparams
    b = CredentialIssuer(sk, MAX_AMOUNT).iparams
    assert a == b
    assert len(a) == IPARAMS_SIZE


def test_credential_roundtrip_bytes():
    c = Credential(
        value=1234,
        randomness=os.urandom(32),
        mac_t=os.urandom(32),
        mac_v=b"\x02" + os.urandom(32),
    )
    assert Credential.parse(c.to_bytes()) == c
    packed = Credential.pack([c, c])
    assert len(packed) == 2 * CREDENTIAL_SIZE
    assert Credential.unpack(packed) == [c, c]


def test_full_roundtrip():
    sk = os.urandom(160)
    issuer = CredentialIssuer(sk, MAX_AMOUNT)
    client = Client(issuer.iparams, MAX_AMOUNT)

    # bootstrap
    zero_req, zero_val = client.create_zero_request()
    assert len(zero_val) == VALIDATION_SIZE
    zero_resp = issuer.handle_zero(zero_req)
    creds = client.handle_response(zero_resp, zero_val)
    assert len(creds) == CREDENTIAL_COUNT

    # real round
    real_req, real_val = client.create_real_request([1000, 0], creds)
    real_resp = issuer.handle_real(real_req)
    new_creds = client.handle_response(real_resp, real_val)
    assert len(new_creds) == CREDENTIAL_COUNT
    assert sorted(c.value for c in new_creds) == [0, 1000]


def test_invalid_response_raises():
    sk = os.urandom(160)
    issuer = CredentialIssuer(sk, MAX_AMOUNT)
    client = Client(issuer.iparams, MAX_AMOUNT)
    _, zero_val = client.create_zero_request()
    try:
        client.handle_response(b"\x00" * 200, zero_val)
    except (WabiSabiError, ValueError):
        pass
    else:
        raise AssertionError("expected an error for a garbage response")


def _run_standalone():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"FAIL {fn.__name__}: {exc!r}")
    if failed:
        print(f"\n{failed}/{len(fns)} tests failed")
        sys.exit(1)
    print(f"\nall {len(fns)} tests passed")


if __name__ == "__main__":
    _run_standalone()

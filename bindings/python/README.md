# wabisabi — Python bindings

Python bindings for `libwabisabi`, the C implementation of the WabiSabi KVAC
anonymous-credential protocol over secp256k1. They use `ctypes` to call the
shared library directly — no compiler or build step is needed at install time,
only a built `libwabisabi.so` (`.dylib` / `.dll`) at runtime.

The bindings are wire-compatible with the C and C# (`WabiSabi.Native`)
implementations: requests, responses, and credentials produced here are
accepted by them, and vice-versa.

## Requirements

- Python ≥ 3.8 (standard library only).
- A built `libwabisabi` shared library. From the repo root:

  ```sh
  cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build
  ```

## Locating the shared library

`wabisabi` looks for the library in this order:

1. `$WABISABI_LIB` (an explicit path to the `.so`/`.dylib`/`.dll`).
2. Next to the installed `wabisabi` package (a bundled wheel).
3. The in-repo `c/build/` output (a developer checkout) — found automatically.
4. The system loader path (`LD_LIBRARY_PATH`, `ldconfig`, etc.).

In a developer checkout, step 3 means it usually "just works". Otherwise:

```sh
export WABISABI_LIB=/path/to/libwabisabi.so
# or
export LD_LIBRARY_PATH=/path/to/dir:$LD_LIBRARY_PATH
```

## Quick start

```python
import os
from wabisabi import CredentialIssuer, Client

sk = os.urandom(160)              # 160-byte secret key (derive a real one in production)
max_amount = 1 << 32

issuer = CredentialIssuer(sk, max_amount)
client = Client(issuer.iparams, max_amount)

# Bootstrap: obtain zero-value credentials.
req, val = client.create_zero_request()
resp = issuer.handle_zero(req)
creds = client.handle_response(resp, val)

# Real round: present those credentials, request new amounts.
req, val = client.create_real_request([1000, 0], creds)
resp = issuer.handle_real(req)
new_creds = client.handle_response(resp, val)
print([c.value for c in new_creds])   # -> [1000, 0]
```

See `examples/roundtrip.py` for a runnable version.

## Ownership proofs

The bindings also expose SLIP-0019 / BIP-322 ownership proofs, byte-for-byte
compatible with WalletWasabi's managed `OwnershipProof`. Proving ownership of a
coin means demonstrating control of the private key that can spend its
scriptPubKey; the verifier only needs the scriptPubKey, not the key.

```python
from wabisabi import OwnershipProof, OwnershipScriptPubKeyType

key = bytes.fromhex("…32-byte private key…")
commitment = b"coinjoin-input-commitment"
identifiers = [bytes(range(1, 33))]        # zero or more 32-byte ids

# Prover: the scriptPubKey is derived natively from the key and script type.
proof = OwnershipProof.generate(
    key, commitment, identifiers,
    OwnershipScriptPubKeyType.SEGWIT, user_confirmation=True)

# Verifier (has the scriptPubKey, not the key):
ok = OwnershipProof.verify(proof, script_pubkey, commitment,
                           require_user_confirmation=True)
```

`generate` returns the serialized proof (identical to `OwnershipProof.ToBytes()`
on the C# side). `verify` returns `True`/`False` for a valid/invalid signature
and raises `WabiSabiError` on a malformed proof. See
`examples/ownership_proof.py`.

## API

The public surface is small:

- `CredentialIssuer(sk_bytes, max_amount)` — `.iparams`, `.balance`,
  `.mstate` (persist/restore), `.handle_zero(req)`, `.handle_real(req)`.
- `Client(iparams_bytes, max_amount)` — `.create_zero_request()`,
  `.create_real_request(amounts, creds)`, `.handle_response(resp, val)`.
- `Credential` — `value`, `randomness`, `mac_t`, `mac_v`; `.to_bytes()`,
  `.parse()`, `.pack()`, `.unpack()`.
- `OwnershipProof` — `.generate(...)`, `.verify(...)` (static); with
  `OwnershipScriptPubKeyType` (`SEGWIT` / `TAPROOT_BIP86`).
- `WabiSabiError` — raised when the native library reports an error.

The raw `ctypes` FFI (1:1 with `c/include/wabisabi_ffi.h`) and the runtime
lifecycle live in the private `wabisabi._native` module — the library is
initialized automatically on import, so there is nothing to set up or tear down.

### Statelessness

The C library holds no state between calls. The high-level classes serialize
that state for you: the issuer's `mstate` (serial-number set + balance) and the
client's per-request `validation_state` (returned from every `create_*` call
and required by `handle_response`). To resume an issuer later, persist
`issuer.mstate` and assign it back.

### Wire format

All sizes and the byte layout of every message are the constants exported from
the package (`SCALAR_SIZE`, `GE_SIZE`, `CREDENTIAL_SIZE`, `VALIDATION_SIZE`, …),
mirroring the `WABISABI_*_SIZE` macros. Conventions: scalars are 32-byte
big-endian, group elements 33-byte compressed (`0x00…` = infinity), amounts
8-byte little-endian.

## Running the tests

```sh
LD_LIBRARY_PATH=$PWD/c/build python3 bindings/python/tests/test_roundtrip.py
# or, with pytest:
LD_LIBRARY_PATH=$PWD/c/build pytest bindings/python/tests
```

# WabiSabi language bindings

Bindings that let other languages drive the WabiSabi KVAC anonymous-credential
protocol through the C shared library, [`libwabisabi`](../c). Every binding is a
thin marshalling layer over the **same** FFI declared in
[`c/include/wabisabi_ffi.h`](../c/include/wabisabi_ffi.h) — they add no crypto
of their own — so messages produced by one binding are wire-compatible with the
C, the C# (`WabiSabi.Native`), and every other binding here.

## Available bindings

| Language | Directory          | Mechanism      | Status |
|----------|--------------------|----------------|--------|
| Python   | [`python/`](python) | `ctypes`       | ✅ round-trip tested |

More languages are intended to live alongside these (e.g. `bindings/<lang>/`),
each following the same principle below.

## Principle for all bindings

- **One source of truth.** `c/include/wabisabi_ffi.h` is the wire-format and FFI
  contract. A binding mirrors its function signatures, size constants, and byte
  layout exactly. It does not reimplement or "fix" the protocol — when in doubt
  the C library (which tracks the C# reference) wins.
- **Stateless core, stateful sugar.** The C library keeps no state between
  calls: the issuer's mutable state (serial-number set + balance) and the
  client's per-request validation state are serialized `bytes` the caller
  threads through. Bindings expose convenience objects that carry that state,
  but the wire bytes stay identical.
- **Bring your own library.** Bindings load a prebuilt `libwabisabi`
  (`.so`/`.dylib`/`.dll`); they don't compile it. Build it first:

  ```sh
  cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build
  ```

## The protocol in one minute

The same three steps appear in every binding's API:

1. The **issuer** (coordinator) holds a 160-byte secret key and derives 66-byte
   public issuer parameters (`iparams`).
2. A **client** bootstraps by requesting zero-value credentials, then runs
   "real" rounds: it presents credentials it holds and requests new amounts.
   Each create call returns a request plus an opaque *validation state*.
3. The issuer handles each request and returns a response; the client feeds the
   response and the matching validation state back in to recover its new
   credentials. The issuer's running **balance** must stay non-negative.

## Examples

### Python

Full zero-bootstrap + real round (see [`python/examples/roundtrip.py`](python/examples/roundtrip.py)):

```python
import os
from wabisabi import CredentialIssuer, Client

sk = os.urandom(160)              # 160-byte secret key (derive a real one in production)
max_amount = 1 << 32

issuer = CredentialIssuer(sk, max_amount)
client = Client(issuer.iparams, max_amount)

# 1. Bootstrap: obtain zero-value credentials.
req, val = client.create_zero_request()
resp = issuer.handle_zero(req)
creds = client.handle_response(resp, val)

# 2. Real round: present those credentials, request new amounts.
req, val = client.create_real_request([1000, 0], creds)
resp = issuer.handle_real(req)
new_creds = client.handle_response(resp, val)

print([c.value for c in new_creds])   # -> [1000, 0]
print(issuer.balance)                 # -> 1000
```

Run it (Python is provided via `nix-shell` in this environment):

```sh
cmake -B c/build -S c -DCMAKE_BUILD_TYPE=Release && cmake --build c/build
LD_LIBRARY_PATH=$PWD/c/build PYTHONPATH=$PWD/bindings/python \
  nix-shell -p python3 --run "python3 bindings/python/examples/roundtrip.py"
```

See each binding's own `README.md` for installation and API details.

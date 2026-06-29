"""End-to-end WabiSabi credential round-trip using the Python bindings.

Run (from the repo root, with the shared library built into c/build):

    LD_LIBRARY_PATH=$PWD/c/build PYTHONPATH=$PWD/bindings/python \
      nix-shell -p python3 --run "python3 bindings/python/examples/roundtrip.py"

The package also auto-discovers c/build/libwabisabi.so from a developer
checkout, so LD_LIBRARY_PATH is usually optional.
"""

import os

from wabisabi import CredentialIssuer, Client

MAX_AMOUNT = 1 << 32


def main() -> None:
    # In production, derive the secret key deterministically and keep it secret.
    sk = os.urandom(160)

    issuer = CredentialIssuer(sk, MAX_AMOUNT)
    client = Client(issuer.iparams, MAX_AMOUNT)

    # 1. Bootstrap: get zero-value credentials.
    zero_req, zero_val = client.create_zero_request()
    zero_resp = issuer.handle_zero(zero_req)
    creds = client.handle_response(zero_resp, zero_val)
    print(f"bootstrapped {len(creds)} credentials; issuer balance = {issuer.balance}")

    # 2. Real round: present the bootstrap credentials, request new amounts.
    amounts = [1000, 0]
    real_req, real_val = client.create_real_request(amounts, creds)
    real_resp = issuer.handle_real(real_req)
    new_creds = client.handle_response(real_resp, real_val)

    print(f"issued credentials with values: {[c.value for c in new_creds]}")
    print(f"issuer balance after real round = {issuer.balance}")


if __name__ == "__main__":
    main()

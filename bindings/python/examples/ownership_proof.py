"""Create and verify a SLIP-0019 / BIP-322 ownership proof with the Python bindings.

Run (from the repo root, with the shared library built into c/build):

    LD_LIBRARY_PATH=$PWD/c/build PYTHONPATH=$PWD/bindings/python \
      nix-shell -p python3 --run "python3 bindings/python/examples/ownership_proof.py"

The package also auto-discovers c/build/libwabisabi.so from a developer
checkout, so LD_LIBRARY_PATH is usually optional.

Proving ownership of a coin means demonstrating control of the private key that
can spend its scriptPubKey. The prover generates the proof from the key; a
verifier who only knows the coin's scriptPubKey (not the key) checks it.
"""

from wabisabi import OwnershipProof, OwnershipScriptPubKeyType

# A deterministic key so this example is reproducible. In production, keep the
# private key secret and derive it from your wallet.
KEY = bytes.fromhex("1122334455667788990011223344556677889900112233445566778899001122")

# Commitment data bound into the proof (e.g. a CoinJoin round's input commitment).
COMMITMENT = bytes([0xDE, 0xAD, 0xBE, 0xEF])

# Zero or more 32-byte ownership identifiers (HMAC-SHA256 outputs).
IDENTIFIERS = [bytes(range(1, 33))]

# The scriptPubKey the owner of KEY spends from (P2WPKH here). A verifier would
# already have this from the coin/UTXO being proven.
SCRIPT_PUBKEY = bytes.fromhex("00143273dd7061fe87103921b09bf8dbe85a9fc55032")


def main() -> None:
    # Prover: build the proof from the private key. The scriptPubKey is derived
    # natively from the key and the chosen script type.
    proof = OwnershipProof.generate(
        KEY,
        commitment_data=COMMITMENT,
        ownership_identifiers=IDENTIFIERS,
        script_pubkey_type=OwnershipScriptPubKeyType.SEGWIT,
        user_confirmation=True,
    )
    print(f"generated ownership proof: {len(proof)} bytes")
    print(f"  {proof.hex()}")

    # Verifier: check the proof against the coin's scriptPubKey and commitment,
    # without ever seeing the private key.
    ok = OwnershipProof.verify(
        proof, SCRIPT_PUBKEY, COMMITMENT, require_user_confirmation=True)
    print(f"verifies against the scriptPubKey: {ok}")

    # A different commitment must not verify.
    tampered = OwnershipProof.verify(proof, SCRIPT_PUBKEY, b"other", require_user_confirmation=True)
    print(f"verifies against a wrong commitment: {tampered}")


if __name__ == "__main__":
    main()

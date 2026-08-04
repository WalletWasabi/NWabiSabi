using System;

namespace WabiSabi.Native;

/// <summary>
/// The scriptPubKey type an ownership proof is generated for. Kept independent
/// of NBitcoin so the WabiSabi package carries no NBitcoin dependency; a caller
/// that has NBitcoin maps its own <c>ScriptPubKeyType</c> onto these values.
/// </summary>
public enum OwnershipScriptPubKeyType
{
    /// <summary>Segwit v0 (P2WPKH).</summary>
    Segwit = NativeWabi.SpkP2Wpkh,

    /// <summary>Taproot key-path, BIP-86 (P2TR).</summary>
    TaprootBIP86 = NativeWabi.SpkP2Tr,
}

/// <summary>
/// Native-backed SLIP-0019 / BIP-322 ownership proofs, byte-for-byte compatible
/// with WalletWasabi's managed <c>OwnershipProof</c>. Proving ownership of a coin
/// means demonstrating control of the private key that can spend its scriptPubKey.
///
/// This is a thin, byte-oriented facade over the libwabisabi entry points
/// (<c>wabisabi_ownership_proof_generate</c> / <c>_verify</c>). Generation derives
/// the scriptPubKey natively from the key and type; verification is done by a party
/// that only has the coin's scriptPubKey (not the key).
/// </summary>
public static class OwnershipProof
{
    /// <summary>Length in bytes of a single ownership identifier (HMAC-SHA256 output).</summary>
    public const int OwnershipIdLength = 32;

    private const int PrivKeyLength = 32;

    /// <summary>
    /// Generate a serialized ownership proof for the coin owned by <paramref name="key"/>.
    /// The scriptPubKey is derived natively from the key and <paramref name="scriptPubKeyType"/>.
    /// </summary>
    /// <param name="key">32-byte private key.</param>
    /// <param name="commitmentData">Commitment data bound into the signature hash (e.g. the CoinJoin input commitment). May be empty.</param>
    /// <param name="ownershipIdentifiers">Zero or more 32-byte ownership identifiers.</param>
    /// <param name="scriptPubKeyType">Segwit (P2WPKH) or TaprootBIP86 (P2TR).</param>
    /// <param name="userConfirmation">Sets the UserConfirmation flag in the proof body (true for CoinJoin input proofs).</param>
    /// <returns>The serialized ownership proof, identical to WalletWasabi's <c>OwnershipProof.ToBytes()</c>.</returns>
    public static byte[] Generate(
        byte[] key,
        byte[] commitmentData,
        byte[][] ownershipIdentifiers,
        OwnershipScriptPubKeyType scriptPubKeyType,
        bool userConfirmation = true)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(ownershipIdentifiers);
        if (key.Length != PrivKeyLength)
        {
            throw new ArgumentException($"Private key must be {PrivKeyLength} bytes long.", nameof(key));
        }

        commitmentData ??= Array.Empty<byte>();
        var identifiers = FlattenIdentifiers(ownershipIdentifiers);

        var outBytes = new byte[NativeWabi.MaxOwnershipProofSize];
        int rc = NativeWabi.OwnershipProofGenerate(
            key,
            (int)scriptPubKeyType,
            identifiers, ownershipIdentifiers.Length,
            commitmentData, commitmentData.Length,
            userConfirmation ? 1 : 0,
            outBytes, outBytes.Length, out int outLen);

        if (rc != 0)
        {
            throw new InvalidOperationException($"Native ownership proof generation failed (error {rc}).");
        }

        var proof = new byte[outLen];
        Array.Copy(outBytes, proof, outLen);
        return proof;
    }

    /// <summary>
    /// Verify a serialized ownership proof against a coin's scriptPubKey and commitment.
    /// The verifier does not need the private key.
    /// </summary>
    /// <param name="proof">Serialized ownership proof (as produced by <see cref="Generate"/>).</param>
    /// <param name="scriptPubKey">The coin's scriptPubKey bytes (P2WPKH or P2TR).</param>
    /// <param name="commitmentData">Commitment data the proof was bound to. May be empty.</param>
    /// <param name="requireUserConfirmation">Reject proofs lacking the UserConfirmation flag.</param>
    /// <returns><c>true</c> if the proof is valid; <c>false</c> if the signature or flags do not verify.</returns>
    /// <exception cref="ArgumentException">Thrown when the proof is malformed.</exception>
    public static bool Verify(
        byte[] proof,
        byte[] scriptPubKey,
        byte[] commitmentData,
        bool requireUserConfirmation)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(scriptPubKey);
        commitmentData ??= Array.Empty<byte>();

        int rc = NativeWabi.OwnershipProofVerify(
            proof, proof.Length,
            scriptPubKey, scriptPubKey.Length,
            commitmentData, commitmentData.Length,
            requireUserConfirmation ? 1 : 0);

        return rc switch
        {
            0 => true,                                        // WABISABI_OK
            (int)WabiSabiNativeError.InvalidProof => false,   // signature/flags did not verify
            _ => throw new ArgumentException($"Malformed ownership proof (native error {rc})."),
        };
    }

    private static byte[] FlattenIdentifiers(byte[][] ownershipIdentifiers)
    {
        if (ownershipIdentifiers.Length == 0)
        {
            return Array.Empty<byte>();
        }

        var flat = new byte[ownershipIdentifiers.Length * OwnershipIdLength];
        for (int i = 0; i < ownershipIdentifiers.Length; i++)
        {
            var id = ownershipIdentifiers[i];
            if (id is null || id.Length != OwnershipIdLength)
            {
                throw new ArgumentException($"Each ownership identifier must be {OwnershipIdLength} bytes long.", nameof(ownershipIdentifiers));
            }
            Array.Copy(id, 0, flat, i * OwnershipIdLength, OwnershipIdLength);
        }
        return flat;
    }
}

/// <summary>Subset of the C <c>wabisabi_error_t</c> codes the ownership-proof facade branches on.</summary>
internal enum WabiSabiNativeError
{
    Ok = 0,
    InvalidProof = 4,
}

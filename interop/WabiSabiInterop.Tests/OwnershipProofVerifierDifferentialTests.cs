using System;
using System.Linq;
using System.Numerics;
using NBitcoin;
using NBitcoin.Crypto;
using WalletWasabi.Crypto;
using WalletWasabi.Extensions;
using Xunit;
using NativeOwnershipProof = WabiSabi.Native.OwnershipProof;
using NativeSpkType = WabiSabi.Native.OwnershipScriptPubKeyType;

namespace WabiSabiInterop.Tests;

/// <summary>
/// Differential tests for the native (libsecp256k1) vs managed (NBitcoin) ownership-proof
/// verifiers, covering the signature-encoding edge cases flagged on WalletWasabi#15101 where
/// the native verifier was suspected of being stricter than NBitcoin: high-S ECDSA, non-strict
/// (non-minimal) DER, uncompressed pubkeys and a Taproot annex.
///
/// The contract these pin down is simply: <b>the two verifiers must return the same verdict</b>.
/// A coordinator running one verifier while clients run the other must not accept an input the
/// others reject (or vice versa) — either disagreement is a round-failure / DoS vector. These are
/// the tests the review asked to "lock in" before the client-side ownership check is moved to the
/// native implementation.
///
/// Each test hand-builds a proof whose 64/DER signature is cryptographically valid for the key, but
/// whose encoding exercises one edge case, then asserts the managed and native verifiers agree.
/// </summary>
public class OwnershipProofVerifierDifferentialTests
{
	private static readonly byte[] CommitmentData = { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };

	// secp256k1 group order N.
	private static readonly BigInteger N = BigInteger.Parse(
		"00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
		System.Globalization.NumberStyles.HexNumber);

	private static (Key key, OwnershipIdentifier id) MakeFixture()
	{
		var key = new Key(Convert.FromHexString("1122334455667788990011223344556677889900112233445566778899001122"));
		var idBytes = new byte[OwnershipIdentifier.OwnershipIdLength];
		for (int i = 0; i < idBytes.Length; i++)
		{
			idBytes[i] = (byte)(i + 1);
		}
		return (key, new OwnershipIdentifier(idBytes));
	}

	private static ProofBody MakeBody(OwnershipIdentifier id) =>
		new(ProofBodyFlags.UserConfirmation, id);

	private static byte[] Assemble(ProofBody body, WitScript witness) =>
		new OwnershipProof(body, new Bip322Signature(Script.Empty, witness)).ToBytes();

	private static bool ManagedVerifies(byte[] proof, Script spk) =>
		OwnershipProof.FromBytes(proof).VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true);

	private static bool NativeVerifies(byte[] proof, Script spk, NativeSpkType type) =>
		NativeOwnershipProof.Verify(proof, spk.ToBytes(), CommitmentData, requireUserConfirmation: true);

	// --- DER helpers ------------------------------------------------------------------------------

	// Minimal DER integer content for a 32-byte big-endian value: strip leading zeros, then prepend
	// a single 0x00 if the high bit is set (so the integer stays positive).
	private static byte[] MinimalDerInt(byte[] be32)
	{
		int i = 0;
		while (i < be32.Length - 1 && be32[i] == 0)
		{
			i++;
		}
		var trimmed = be32[i..];
		if ((trimmed[0] & 0x80) != 0)
		{
			trimmed = new byte[] { 0x00 }.Concat(trimmed).ToArray();
		}
		return trimmed;
	}

	// Wrap already-formed integer contents into a DER SEQUENCE of two INTEGERs.
	private static byte[] DerSequence(byte[] rInt, byte[] sInt)
	{
		var r = new byte[] { 0x02, (byte)rInt.Length }.Concat(rInt);
		var s = new byte[] { 0x02, (byte)sInt.Length }.Concat(sInt);
		var body = r.Concat(s).ToArray();
		return new byte[] { 0x30, (byte)body.Length }.Concat(body).ToArray();
	}

	private static byte[] To32BE(BigInteger value)
	{
		var be = value.ToByteArray(isUnsigned: true, isBigEndian: true);
		if (be.Length > 32)
		{
			throw new InvalidOperationException("value exceeds 32 bytes");
		}
		var padded = new byte[32];
		Array.Copy(be, 0, padded, 32 - be.Length, be.Length);
		return padded;
	}

	// (r, s) big-endian halves of a compact ECDSA signature.
	private static (byte[] r, byte[] s) SignCompact(Key key, uint256 hash)
	{
		var compact = key.Sign(hash).ToCompact();
		return (compact[..32], compact[32..]);
	}

	private static WitScript P2wpkhWitness(byte[] derSig, byte[] pubkey) =>
		new(new[] { derSig.Concat(new byte[] { 0x01 }).ToArray(), pubkey }); // SIGHASH_ALL

	// --- Tests ------------------------------------------------------------------------------------

	// High-S: s' = N - s is a valid-but-malleated ECDSA signature. libsecp256k1's verify rejects
	// non-low-S; NBitcoin's managed secp verify does too (ECPubKey.SigVerify gates on !s.IsHigh).
	// Expectation: both reject -> they agree.
	[Fact]
	public void HighS_Ecdsa_VerifiersAgree()
	{
		var (key, id) = MakeFixture();
		var body = MakeBody(id);
		var spk = key.PubKey.GetScriptPubKey(ScriptPubKeyType.Segwit);
		var hash = body.SignatureHash(spk, CommitmentData);

		var (r, s) = SignCompact(key, hash);
		var highS = To32BE(N - new BigInteger(s, isUnsigned: true, isBigEndian: true));
		var der = DerSequence(MinimalDerInt(r), MinimalDerInt(highS));

		var proof = Assemble(body, P2wpkhWitness(der, key.PubKey.ToBytes()));

		Assert.Equal(ManagedVerifies(proof, spk), NativeVerifies(proof, spk, NativeSpkType.Segwit));
	}

	// Non-minimal (BER, not strict DER) encoding: prepend a redundant 0x00 to the R integer. The
	// underlying (r, s) is a valid low-S signature. libsecp256k1's parse_der is strict and rejects
	// the non-minimal integer; NBitcoin parses it with a lax DER parser and accepts.
	[Fact]
	public void NonStrictDer_Ecdsa_VerifiersAgree()
	{
		var (key, id) = MakeFixture();
		var body = MakeBody(id);
		var spk = key.PubKey.GetScriptPubKey(ScriptPubKeyType.Segwit);
		var hash = body.SignatureHash(spk, CommitmentData);

		var (r, s) = SignCompact(key, hash);
		var nonMinimalR = new byte[] { 0x00 }.Concat(MinimalDerInt(r)).ToArray(); // redundant leading zero
		var der = DerSequence(nonMinimalR, MinimalDerInt(s));

		var proof = Assemble(body, P2wpkhWitness(der, key.PubKey.ToBytes()));

		Assert.Equal(ManagedVerifies(proof, spk), NativeVerifies(proof, spk, NativeSpkType.Segwit));
	}

	// Uncompressed (65-byte) pubkey in a P2WPKH witness. The scriptPubKey commits to hash160 of the
	// uncompressed encoding so the managed verifier accepts; the native verifier requires a 33-byte
	// compressed key and rejects.
	[Fact]
	public void UncompressedPubkey_P2wpkh_VerifiersAgree()
	{
		var (key, id) = MakeFixture();
		var body = MakeBody(id);

		var uncompressed = key.PubKey.Decompress();
		var spk = uncompressed.GetScriptPubKey(ScriptPubKeyType.Segwit); // hash160 of the 65-byte key
		var hash = body.SignatureHash(spk, CommitmentData);

		var der = key.Sign(hash).ToDER();
		var proof = Assemble(body, P2wpkhWitness(der, uncompressed.ToBytes()));

		Assert.Equal(ManagedVerifies(proof, spk), NativeVerifies(proof, spk, NativeSpkType.Segwit));
	}

	// Taproot annex: a second witness item beginning with 0x50. BIP-341 strips the annex before
	// verifying, which NBitcoin does (accept); the native verifier requires exactly one witness item
	// and rejects.
	[Fact]
	public void TaprootAnnex_VerifiersAgree()
	{
		var (key, id) = MakeFixture();
		var body = MakeBody(id);
		var spk = key.PubKey.GetScriptPubKey(ScriptPubKeyType.TaprootBIP86);
		var hash = body.SignatureHash(spk, CommitmentData);

		var sig64 = key.SignTaprootKeySpend(hash, null, uint256.Zero, TaprootSigHash.Default).ToBytes();
		var annex = new byte[] { 0x50, 0xAA, 0xBB };
		var witness = new WitScript(new[] { sig64, annex });

		var proof = Assemble(body, witness);

		Assert.Equal(ManagedVerifies(proof, spk), NativeVerifies(proof, spk, NativeSpkType.TaprootBIP86));
	}
}

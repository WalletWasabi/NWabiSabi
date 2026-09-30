using System;
using NBitcoin;
using WalletWasabi.Crypto;
using Xunit;
using NativeOwnershipProof = WabiSabi.Native.OwnershipProof;
using NativeSpkType = WabiSabi.Native.OwnershipScriptPubKeyType;

namespace WabiSabiInterop.Tests;

/// <summary>
/// Compatibility gate for the native ownership-proof FFI against WalletWasabi's
/// managed OwnershipProof (vendored under Reference/). Proves both wire equality
/// (identical serialized bytes) and cross-verification in both directions, for
/// P2WPKH and P2TR.
/// </summary>
public class OwnershipProofInteropTests
{
	public static TheoryData<ScriptPubKeyType, NativeSpkType> ScriptTypes =>
		new()
		{
			{ ScriptPubKeyType.Segwit, NativeSpkType.Segwit },
			{ ScriptPubKeyType.TaprootBIP86, NativeSpkType.TaprootBIP86 },
		};

	private static readonly byte[] CommitmentData = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03 };

	private static (Key key, Script spk, OwnershipIdentifier id, byte[] idBytes) MakeFixture(ScriptPubKeyType type)
	{
		// Deterministic key so failures are reproducible.
		var key = new Key(Convert.FromHexString("1122334455667788990011223344556677889900112233445566778899001122"));
		var spk = key.PubKey.GetScriptPubKey(type);
		var idBytes = new byte[OwnershipIdentifier.OwnershipIdLength];
		for (int i = 0; i < idBytes.Length; i++)
		{
			idBytes[i] = (byte)(i + 1);
		}
		return (key, spk, new OwnershipIdentifier(idBytes), idBytes);
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void NativeProof_IsByteForByteIdenticalToManaged(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, _, id, idBytes) = MakeFixture(type);

		var managed = OwnershipProof.Generate(key, id, CommitmentData, userConfirmation: true, type).ToBytes();
		var native = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: true);

		Assert.Equal(Convert.ToHexString(managed), Convert.ToHexString(native));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void NativeProof_VerifiesUnderManaged(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, spk, _, idBytes) = MakeFixture(type);

		var nativeBytes = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: true);
		var managed = OwnershipProof.FromBytes(nativeBytes);

		Assert.True(managed.VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void ManagedProof_VerifiesUnderNative(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, spk, id, idBytes) = MakeFixture(type);

		var managedBytes = OwnershipProof.Generate(key, id, CommitmentData, userConfirmation: true, type).ToBytes();

		Assert.True(NativeOwnershipProof.Verify(managedBytes, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));

		// The native proof for the same inputs is identical, so it also verifies.
		var nativeBytes = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: true);
		Assert.True(NativeOwnershipProof.Verify(nativeBytes, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void NativeVerify_RejectsWrongCommitment(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, spk, _, idBytes) = MakeFixture(type);

		var nativeBytes = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: true);
		var tampered = (byte[])CommitmentData.Clone();
		tampered[0] ^= 0xFF;

		Assert.False(NativeOwnershipProof.Verify(nativeBytes, spk.ToBytes(), tampered, requireUserConfirmation: true));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void NativeVerify_RejectsWrongScriptPubKey(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, _, _, idBytes) = MakeFixture(type);
		var otherSpk = new Key().PubKey.GetScriptPubKey(type);

		var nativeBytes = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: true);

		Assert.False(NativeOwnershipProof.Verify(nativeBytes, otherSpk.ToBytes(), CommitmentData, requireUserConfirmation: true));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void UserConfirmationFlag_IsHonoredBothWays(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, spk, id, idBytes) = MakeFixture(type);

		// Proof generated WITHOUT user confirmation must be rejected when confirmation is required...
		var nativeNoConf = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, nativeType, userConfirmation: false);
		Assert.False(NativeOwnershipProof.Verify(nativeNoConf, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));
		Assert.True(NativeOwnershipProof.Verify(nativeNoConf, spk.ToBytes(), CommitmentData, requireUserConfirmation: false));

		// ...and the same proof must behave identically under the managed verifier.
		var managedNoConf = OwnershipProof.FromBytes(nativeNoConf);
		Assert.False(managedNoConf.VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
		Assert.True(managedNoConf.VerifyOwnership(spk, CommitmentData, requireUserConfirmation: false));

		// Sanity: the without-confirmation managed proof also matches native bytes.
		var managedBytes = OwnershipProof.Generate(key, id, CommitmentData, userConfirmation: false, type).ToBytes();
		Assert.Equal(Convert.ToHexString(managedBytes), Convert.ToHexString(nativeNoConf));
	}

	[Theory]
	[MemberData(nameof(ScriptTypes))]
	public void CoinJoinInputProof_RoundTrips(ScriptPubKeyType type, NativeSpkType nativeType)
	{
		var (key, spk, id, idBytes) = MakeFixture(type);
		var commitment = new CoinJoinInputCommitmentData("CoordinatorName", uint256.One).ToBytes();

		var managed = OwnershipProof.GenerateCoinJoinInputProof(key, id, new CoinJoinInputCommitmentData("CoordinatorName", uint256.One), type).ToBytes();
		var native = NativeOwnershipProof.Generate(key.ToBytes(), commitment, new[] { idBytes }, nativeType, userConfirmation: true);

		Assert.Equal(Convert.ToHexString(managed), Convert.ToHexString(native));
		Assert.True(NativeOwnershipProof.Verify(managed, spk.ToBytes(), commitment, requireUserConfirmation: true));
	}

	// --- P2TR sighash-byte handling ---------------------------------------------------------------
	// Regression for the DoS blocker reported on WalletWasabi/WalletWasabi#15101: the native P2TR
	// verifier accepted a 65-byte Schnorr signature regardless of the trailing sighash byte, so an
	// attacker could append 0x00 (or any undefined hash type) to a valid 64-byte signature and have
	// the native coordinator accept an input that the managed (NBitcoin) client-side check rejects.
	// BIP-341: SIGHASH_DEFAULT must use the 64-byte form; the 65-byte form must carry a sighash byte
	// in { 0x01, 0x02, 0x03, 0x81, 0x82, 0x83 } and must not be 0x00. The two verifiers must agree.

	// A proof's P2TR witness ends with: [0x00 scriptSig_len][0x01 witness_count][0x40 item_len][64-byte sig].
	// This turns the 64-byte item into a 65-byte one by bumping the length varint and appending a sighash byte.
	private static byte[] WithAppendedSighashByte(byte[] p2trProof, byte sighash)
	{
		var tampered = new byte[p2trProof.Length + 1];
		Array.Copy(p2trProof, tampered, p2trProof.Length);
		int itemLenPos = p2trProof.Length - 65; // the length varint sits right before the 64 signature bytes
		Assert.Equal(0x40, tampered[itemLenPos]); // sanity: single-byte varint encoding length 64
		tampered[itemLenPos] = 0x41; // length is now 65
		tampered[p2trProof.Length] = sighash; // appended explicit sighash byte
		return tampered;
	}

	[Theory]
	[InlineData((byte)0x00)] // SIGHASH_DEFAULT is illegal in the 65-byte form (the DoS vector)
	[InlineData((byte)0x04)] // undefined hash type
	[InlineData((byte)0x05)]
	[InlineData((byte)0x84)]
	[InlineData((byte)0xFF)]
	public void P2tr_InvalidSighashByte_RejectedByBothVerifiers(byte badSighash)
	{
		var (key, spk, _, idBytes) = MakeFixture(ScriptPubKeyType.TaprootBIP86);
		var valid = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, NativeSpkType.TaprootBIP86, userConfirmation: true);

		// Sanity: the untouched 64-byte-signature proof verifies on both sides.
		Assert.True(OwnershipProof.FromBytes(valid).VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
		Assert.True(NativeOwnershipProof.Verify(valid, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));

		var poisoned = WithAppendedSighashByte(valid, badSighash);

		// Managed (NBitcoin) rejects the malformed sighash byte...
		Assert.False(OwnershipProof.FromBytes(poisoned).VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
		// ...and the native verifier must reject it too (otherwise the coordinator accepts inputs clients reject).
		Assert.False(NativeOwnershipProof.Verify(poisoned, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));
	}

	[Theory]
	[InlineData((byte)0x01)] // SIGHASH_ALL
	[InlineData((byte)0x02)] // SIGHASH_NONE
	[InlineData((byte)0x03)] // SIGHASH_SINGLE
	[InlineData((byte)0x81)] // ALL | ANYONECANPAY
	[InlineData((byte)0x82)] // NONE | ANYONECANPAY
	[InlineData((byte)0x83)] // SINGLE | ANYONECANPAY
	public void P2tr_ValidExplicitSighashByte_AcceptedByBothVerifiers(byte goodSighash)
	{
		var (key, spk, _, idBytes) = MakeFixture(ScriptPubKeyType.TaprootBIP86);
		var valid = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, NativeSpkType.TaprootBIP86, userConfirmation: true);

		// The 64-byte Schnorr signature is untouched, so a valid explicit sighash byte is accepted by both.
		var explicitSig = WithAppendedSighashByte(valid, goodSighash);
		Assert.True(OwnershipProof.FromBytes(explicitSig).VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
		Assert.True(NativeOwnershipProof.Verify(explicitSig, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));
	}

	// A malformed (oversized) witness must make the native verifier return false, not throw. Managed
	// (NBitcoin) parses the larger witness and returns false at verification time; the native wrapper
	// used to surface WABISABI_ERR_PARSE as an ArgumentException, so a coordinator returned a generic
	// error instead of a "wrong ownership proof" rejection.
	[Fact]
	public void OversizedWitnessItem_RejectedNotThrown()
	{
		var (key, spk, _, idBytes) = MakeFixture(ScriptPubKeyType.TaprootBIP86);
		var valid = NativeOwnershipProof.Generate(key.ToBytes(), CommitmentData, new[] { idBytes }, NativeSpkType.TaprootBIP86, userConfirmation: true);

		// Drop the P2TR signature section ([0x00 scriptSig][0x01 count][0x40 len][64-byte sig] = 67 bytes)
		// and re-append a witness holding a single 600-byte item (well beyond a 64/65-byte Schnorr sig).
		var body = valid[..^67];
		var oversized = new byte[body.Length + 2 + 3 + 600];
		int p = 0;
		Array.Copy(body, 0, oversized, p, body.Length);
		p += body.Length;
		oversized[p++] = 0x00; // scriptSig length 0
		oversized[p++] = 0x01; // witness item count 1
		oversized[p++] = 0xFD; oversized[p++] = 0x58; oversized[p++] = 0x02; // varint(600), the rest stays zero

		Assert.False(OwnershipProof.FromBytes(oversized).VerifyOwnership(spk, CommitmentData, requireUserConfirmation: true));
		Assert.False(NativeOwnershipProof.Verify(oversized, spk.ToBytes(), CommitmentData, requireUserConfirmation: true));
	}
}

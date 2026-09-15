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
}

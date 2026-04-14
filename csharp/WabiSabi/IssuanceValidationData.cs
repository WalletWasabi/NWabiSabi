namespace WabiSabi;

using NBitcoin.Secp256k1;
using Crypto.Groups;

public record IssuanceValidationData
{
	internal IssuanceValidationData(long value, Scalar r, GroupElement ma)
	{
		Value = value;
		Randomness = r;
		Ma = ma;
	}

	/// <summary>
	/// Amount committed in the pedersen commitment (<see cref="Ma">Ma</see>).
	/// </summary>
	public long Value { get; }

	/// <summary>
	/// Randomness used as blinding factor in the pedersen commitment (<see cref="Ma">Ma</see>).
	/// </summary>
	public Scalar Randomness { get; }

	/// <summary>
	/// Pedersen commitment to the amount used to request the credential.
	/// </summary>
	public GroupElement Ma { get; }
}

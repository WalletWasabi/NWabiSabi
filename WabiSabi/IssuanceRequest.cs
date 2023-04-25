namespace WabiSabi;

using Crypto.Groups;

/// <summary>
/// Represents a request for issuing a new credential.
/// </summary>
public record IssuanceRequest : IEquatable<IssuanceRequest>
{
	internal IssuanceRequest(GroupElement ma, IReadOnlyCollection<GroupElement> bitCommitments)
	{
		Ma = ma;
		BitCommitments = bitCommitments;
	}

	/// <summary>
	/// Pedersen commitment to the credential amount.
	/// </summary>
	public GroupElement Ma { get; }

	/// <summary>
	/// Pedersen commitments to the credential amount's binary decomposition.
	/// </summary>
	public IReadOnlyCollection<GroupElement> BitCommitments { get; }

	public override int GetHashCode()
	{
		int hc = 0;

		foreach (var element in BitCommitments)
		{
			hc ^= element.GetHashCode();
			hc = (hc << 7) | (hc >> (32 - 7));
		}

		return HashCode.Combine(Ma.GetHashCode(), hc);
	}

	public virtual bool Equals(IssuanceRequest? other)
	{
		if (other is null)
		{
			return false;
		}

		bool isEqual = Ma == other.Ma
			&& BitCommitments.SequenceEqual(other.BitCommitments);

		return isEqual;
	}
}

namespace WabiSabi.Crypto;

using Groups;
using Helpers;

public record CredentialIssuerParameters
{
	public CredentialIssuerParameters(GroupElement cw, GroupElement i)
	{
		Cw = Guard.NotNullOrInfinity(nameof(cw), cw);
		I = Guard.NotNullOrInfinity(nameof(i), i);
	}

	public GroupElement Cw { get; }
	public GroupElement I { get; }

	public override string ToString() => $"{nameof(Cw)}: {Cw}, {nameof(I)}: {I}";
}

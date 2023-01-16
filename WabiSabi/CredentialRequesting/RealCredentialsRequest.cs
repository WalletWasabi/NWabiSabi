namespace WabiSabi.CredentialRequesting;

using Collections;
using Crypto.ZeroKnowledge;

public record RealCredentialsRequest : ICredentialsRequest
{
	public RealCredentialsRequest(
		long delta,
		IEnumerable<CredentialPresentation> presented,
		IEnumerable<IssuanceRequest> requested,
		IEnumerable<Proof> proofs)
	{
		Delta = delta;
		Presented = presented.ToImmutableValueSequence();
		Requested = requested.ToImmutableValueSequence();
		Proofs = proofs.ToImmutableValueSequence();
	}

	public long Delta { get; }

	public ImmutableValueSequence<CredentialPresentation> Presented { get; }

	public ImmutableValueSequence<IssuanceRequest> Requested { get; }

	public ImmutableValueSequence<Proof> Proofs { get; }
}

namespace WabiSabi.CredentialRequesting;

using Collections;
using Crypto.ZeroKnowledge;

public record ZeroCredentialsRequest : ICredentialsRequest
{
	public ZeroCredentialsRequest(
		IEnumerable<IssuanceRequest> requested,
		IEnumerable<Proof> proofs)
	{
		Requested = requested.ToImmutableValueSequence();
		Proofs = proofs.ToImmutableValueSequence();
	}

	public long Delta => 0;

	public ImmutableValueSequence<CredentialPresentation> Presented => ImmutableValueSequence<CredentialPresentation>.Empty;

	public ImmutableValueSequence<IssuanceRequest> Requested { get; }

	public ImmutableValueSequence<Proof> Proofs { get; }
}

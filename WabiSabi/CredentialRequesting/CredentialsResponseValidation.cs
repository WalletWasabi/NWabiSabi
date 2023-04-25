namespace WabiSabi.CredentialRequesting;

using Crypto.ZeroKnowledge;

/// <summary>
/// Maintains the state needed to validate the credentials once the coordinator
/// issues them.
/// </summary>
public record CredentialsResponseValidation
{
	internal CredentialsResponseValidation(
		Transcript transcript,
		IReadOnlyList<Credential> presented,
		IReadOnlyList<IssuanceValidationData> requested)
	{
		Transcript = transcript;
		Presented = presented;
		Requested = requested;
	}

	/// <summary>
	/// The transcript in the correct state that must be used to validate the proofs presented by the coordinator.
	/// </summary>
	internal Transcript Transcript { get; }

	/// <summary>
	/// The credentials that were presented to the coordinator.
	/// </summary>
	public IReadOnlyList<Credential> Presented { get; }

	/// <summary>
	/// The data state that has to be used to validate the issued credentials.
	/// </summary>
	public IReadOnlyList<IssuanceValidationData> Requested { get; }
}

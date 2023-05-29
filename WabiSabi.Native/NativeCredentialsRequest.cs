using WabiSabi.CredentialRequesting;

namespace WabiSabi.Native;

public struct NativeCredentialsRequest
{
	public long Delta;
	public NativeArray<NativeCredentialPresentation> Presented;
	public NativeArray<NativeIssuanceRequest> Requested;
	public NativeArray<NativeProof> Proofs;

	internal static NativeCredentialsRequest FromManaged(ICredentialsRequest managed) => new()
	{
		Delta = managed.Delta,
		Presented = NativeArray.FromManaged(managed.Presented, NativeCredentialPresentation.FromMananged),
		Requested = NativeArray.FromManaged(managed.Requested, NativeIssuanceRequest.FromManaged),
		Proofs = NativeArray.FromManaged(managed.Proofs, NativeProof.FromManaged)
	};
}
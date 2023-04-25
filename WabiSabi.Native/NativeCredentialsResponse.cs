using WabiSabi.CredentialRequesting;

namespace WabiSabi.Native;

public struct NativeCredentialsResponse
{
	public NativeArray<NativeMac> IssuedCredentials;
	public NativeArray<NativeProof> Proofs;

	internal static CredentialsResponse ToManaged(in NativeCredentialsResponse native) => new(
			NativeArray.ToManaged(native.IssuedCredentials, NativeMac.ToManaged),
			NativeArray.ToManaged(native.Proofs, NativeProof.ToManaged));
}

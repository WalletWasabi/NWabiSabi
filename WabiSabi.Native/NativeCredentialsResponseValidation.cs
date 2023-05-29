using System.Runtime.CompilerServices;
using WabiSabi.CredentialRequesting;
using WabiSabi.Crypto.ZeroKnowledge;

namespace WabiSabi.Native;

public struct NativeCredentialsResponseValidation
{
	public NativeTranscript Transcript;
	public NativeArray<NativeCredential> Presented;
	public NativeArray<NativeIssuanceValidationData> Requested;

	internal static NativeCredentialsResponseValidation FromManaged(CredentialsResponseValidation managed)
	{
		NativeCredentialsResponseValidation native;
		Unsafe.SkipInit(out native);
		
		native.Transcript.Strobe = NativeStrobe.FromManaged(managed.Transcript.Strobe);
		native.Presented = NativeArray.FromManaged(managed.Presented, NativeCredential.FromManaged);
		native.Requested = NativeArray.FromManaged(managed.Requested, NativeIssuanceValidationData.FromManaged);

		return native;
	}

	internal static CredentialsResponseValidation ToManaged(in NativeCredentialsResponseValidation native) => new(
		new Transcript(NativeStrobe.ToManaged(native.Transcript.Strobe)),
		NativeArray.ToManaged(native.Presented, NativeCredential.ToManaged),
		NativeArray.ToManaged(native.Requested, NativeIssuanceValidationData.ToManaged));
}

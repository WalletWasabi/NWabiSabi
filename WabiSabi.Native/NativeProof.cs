using WabiSabi.Crypto;
using WabiSabi.Crypto.Groups;
using WabiSabi.Crypto.ZeroKnowledge;

namespace WabiSabi.Native;

public struct NativeProof
{
	public NativeArray<NativeGroupElement> PublicNonces;
	public NativeArray<NativeScalar> Responses;

	internal static NativeProof FromManaged(Proof managed) => new()
	{
		PublicNonces = NativeArray.FromManaged(managed.PublicNonces, NativeGroupElement.FromManaged),
		Responses = NativeArray.FromManaged(managed.Responses, NativeScalar.FromManaged)
	};

	internal static Proof ToManaged(in NativeProof native) => new(
			new GroupElementVector(NativeArray.ToManaged(native.PublicNonces, NativeGroupElement.ToManaged)),
			new ScalarVector(NativeArray.ToManaged(native.Responses, NativeScalar.ToManaged)));
}

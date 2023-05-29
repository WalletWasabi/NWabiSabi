using WabiSabi.Crypto.ZeroKnowledge;

namespace WabiSabi.Native;

public struct NativeCredentialPresentation
{
	public NativeGroupElement Ca;
	public NativeGroupElement Cx0;
	public NativeGroupElement Cx1;
	public NativeGroupElement Cv;
	public NativeGroupElement S;

	internal static NativeCredentialPresentation FromMananged(CredentialPresentation managed) => new()
	{
		Cx0 = NativeGroupElement.FromManaged(managed.Cx0),
		Cx1 = NativeGroupElement.FromManaged(managed.Cx1),
		Ca = NativeGroupElement.FromManaged(managed.Ca),
		Cv = NativeGroupElement.FromManaged(managed.CV),
		S = NativeGroupElement.FromManaged(managed.S)
	};
}

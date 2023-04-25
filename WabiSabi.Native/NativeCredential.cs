using WabiSabi.Crypto;
using WabiSabi.Crypto.ZeroKnowledge;

namespace WabiSabi.Native;

public struct NativeCredential
{
	public long Value;
	public NativeScalar Randomness;
	public NativeMac Mac;

	internal static NativeCredential FromManaged(Credential managed) => new()
	{
		Value = managed.Value,
		Randomness = NativeScalar.FromManaged(managed.Randomness),
		Mac = new()
		{
			T = NativeScalar.FromManaged(managed.Mac.T),
			V = NativeGroupElement.FromManaged(managed.Mac.V)
		}
	};

	internal static Credential ToManaged(in NativeCredential native) => new(
		native.Value,
		NativeScalar.ToManaged(native.Randomness),
		new MAC(
			NativeScalar.ToManaged(native.Mac.T),
			NativeGroupElement.ToManaged(native.Mac.V)));
}

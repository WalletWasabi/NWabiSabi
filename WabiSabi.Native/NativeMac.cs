using WabiSabi.Crypto;

namespace WabiSabi.Native;

public struct NativeMac
{
	public NativeScalar T;
	public NativeGroupElement V;

	internal static MAC ToManaged(in NativeMac native) => new(
		NativeScalar.ToManaged(native.T),
		NativeGroupElement.ToManaged(native.V));
}

using System.Runtime.CompilerServices;

namespace WabiSabi.Native;

public struct NativeIssuanceValidationData
{
	public long Value;
	public NativeScalar Randomness;
	public NativeGroupElement Ma;

	internal static NativeIssuanceValidationData FromManaged(IssuanceValidationData managed)
	{
		NativeIssuanceValidationData native;
		Unsafe.SkipInit(out native);

		native.Value = managed.Value;
		native.Randomness = NativeScalar.FromManaged(managed.Randomness);
		native.Ma = NativeGroupElement.FromManaged(managed.Ma);

		return native;
	}

	internal static IssuanceValidationData ToManaged(in NativeIssuanceValidationData native)
	{
		return new(
			native.Value,
			NativeScalar.ToManaged(native.Randomness),
			NativeGroupElement.ToManaged(native.Ma));
	}
}

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NBitcoin.Secp256k1;

namespace WabiSabi.Native;

public unsafe struct NativeScalar
{
	public fixed uint D[8];

	internal static NativeScalar FromManaged(Scalar managed)
	{
		NativeScalar native;
		Unsafe.SkipInit(out native);

		var span = MemoryMarshal.CreateSpan(ref native.D[0], 8);
		managed.Deconstruct(ref span);

		return native;
	}

	internal static Scalar ToManaged(in NativeScalar native)
	{
		var span = MemoryMarshal.CreateSpan(ref Unsafe.AsRef(native.D[0]), 8);
		return new Scalar(span);
	}
}

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using NBitcoin.Secp256k1;

namespace WabiSabi.Native;

public unsafe struct NativeFieldElement
{
	public fixed uint N[10];
	public int Magnitude;
	public bool Normalized;

	internal static NativeFieldElement FromManaged(in FE managed)
	{
		NativeFieldElement native;
		Unsafe.SkipInit(out native);

		var span = MemoryMarshal.CreateSpan(ref native.N[0], 10);
		managed.Deconstruct(ref span, out native.Magnitude, out native.Normalized);
		
		return native;
	}

	internal static FE ToManaged(in NativeFieldElement native)
	{
		FE managed;
		Unsafe.SkipInit(out managed);

		Interop.SetField(managed.n0, native.N[0]);
		Interop.SetField(managed.n1, native.N[1]);
		Interop.SetField(managed.n2, native.N[2]);
		Interop.SetField(managed.n3, native.N[3]);
		Interop.SetField(managed.n4, native.N[4]);
		Interop.SetField(managed.n5, native.N[5]);
		Interop.SetField(managed.n6, native.N[6]);
		Interop.SetField(managed.n7, native.N[7]);
		Interop.SetField(managed.n8, native.N[8]);
		Interop.SetField(managed.n9, native.N[9]);
		Interop.SetField(managed.magnitude, native.Magnitude);
		Interop.SetField(managed.normalized, native.Normalized);

		return managed;
	}
}

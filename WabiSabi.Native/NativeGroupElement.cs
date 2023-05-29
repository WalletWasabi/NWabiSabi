using System.Runtime.CompilerServices;
using NBitcoin.Secp256k1;
using WabiSabi.Crypto.Groups;

namespace WabiSabi.Native;

public struct NativeGroupElement
{
	public NativeFieldElement X;
	public NativeFieldElement Y;
	public bool Infinite;
	
	internal  static NativeGroupElement FromManaged(GroupElement managed)
	{
		NativeGroupElement native;
		Unsafe.SkipInit(out native);
		
		native.X = NativeFieldElement.FromManaged(managed.Ge.x);
		native.Y = NativeFieldElement.FromManaged(managed.Ge.y);
		native.Infinite = managed.Ge.infinity;

		return native;
	}

	internal static GroupElement ToManaged(in NativeGroupElement native)
	{
		GE managed;
		Unsafe.SkipInit(out managed);

		Interop.SetField(managed.x, NativeFieldElement.ToManaged(native.X));
		Interop.SetField(managed.y, NativeFieldElement.ToManaged(native.Y));
		Interop.SetField(managed.infinity, native.Infinite);

		return new(managed);
	}
}

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using WabiSabi.Crypto.StrobeProtocol;

namespace WabiSabi.Native;

public unsafe struct NativeStrobe
{
	public fixed byte State[25 * 8];
	public byte Position;
	public byte Begin;
	public byte Flags;

	internal static NativeStrobe FromManaged(in Strobe128 managed)
	{
		NativeStrobe native;
		Unsafe.SkipInit(out native);

		var state = MemoryMarshal.CreateSpan(ref native.State[0], 25 * 8);
		var flags = default(StrobeFlags);
		
		managed.Deconstruct(state, out flags, out native.Begin, out native.Position);
		native.Flags = (byte)flags;

		return native;
	}

	internal static Strobe128 ToManaged(in NativeStrobe native)
	{
		var state = MemoryMarshal.CreateSpan(ref Unsafe.AsRef(native.State[0]), 25 * 8);
		var flags = (StrobeFlags)native.Flags;;

 		return new(state, flags, native.Begin, native.Position);
	}
}

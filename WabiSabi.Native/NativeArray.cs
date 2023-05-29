using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace WabiSabi.Native;

internal delegate TNative MarshalFromManaged<TNative, TManaged>(TManaged managed) where TNative : unmanaged;
internal delegate TManaged MarshalToManaged<TNative, TManaged>(in TNative native) where TNative : unmanaged;

internal static class NativeArray
{
	internal static unsafe Span<T> AsSpan<T>(this NativeArray<T> array)
		where T : unmanaged
	{
		return MemoryMarshal.CreateSpan(ref Unsafe.AsRef(*array.Data), array.Length);
	}

	internal static unsafe NativeArray<TNative> FromManaged<TManaged, TNative>(IReadOnlyCollection<TManaged> managed, MarshalFromManaged<TNative, TManaged> marshal)
		where TNative : unmanaged
	{
		var nativeLength = managed.Count;
		var native = nativeLength == 0
			? ref Unsafe.NullRef<TNative>()
			: ref Unsafe.AddByteOffset(ref Unsafe.NullRef<TNative>(), Marshal.AllocHGlobal(Unsafe.SizeOf<TNative>() * managed.Count));

		ref var nativeItem = ref native;
		foreach (var managedItem in managed)
		{
			nativeItem = marshal(managedItem);
			nativeItem = ref Unsafe.Add(ref nativeItem, 1);
		}

		return new() { Data = &native, Length = nativeLength };
	}

	internal static TManaged[] ToManaged<TManaged, TNative>(NativeArray<TNative> native, MarshalToManaged<TNative, TManaged> marshal)
		where TNative : unmanaged
	{
		if (native.Length == 0)
		{
			return Array.Empty<TManaged>();
		}
		
		var managed = new TManaged[native.Length];

		ref var managedItem = ref managed[0];
		foreach (ref var nativeItem in native.AsSpan())
		{
			managedItem = marshal(nativeItem);
			managedItem = ref Unsafe.Add(ref managedItem, 1)!;
		}

		return managed;
	}
}

public unsafe struct NativeArray<T>
	where T : unmanaged
{
	public T* Data;
	public int Length;
}

namespace WabiSabi.Collections;

public static class ImmutableValueSequenceExtensions
{
	public static ImmutableValueSequence<T> ToImmutableValueSequence<T>(this IEnumerable<T> list) where T : IEquatable<T>
		=> new(list);
}

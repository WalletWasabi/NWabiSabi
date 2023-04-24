using System.Collections;
using System.Collections.Immutable;

namespace WabiSabi.Collections;

/// <summary>
/// ImmutableValueSequence represents an immutable sequence with value semantics, meaning that
/// it can be compared with other sequences and the equality of two sequences is based on the
/// equality of the elements.
/// </summary>
public readonly struct ImmutableValueSequence<T> : IEnumerable<T>, IEquatable<ImmutableValueSequence<T>> where T : IEquatable<T>
{
	private readonly ImmutableArray<T> _elements;

	public ImmutableValueSequence(IEnumerable<T> sequence)
	{
		_elements = sequence.ToImmutableArray();
	}

	public static ImmutableValueSequence<T> Empty { get; } = new();

	public ImmutableArray<T>.Enumerator GetEnumerator() => _elements.GetEnumerator();

	public override int GetHashCode()
	{
		var hash = new HashCode();
		foreach (var element in _elements)
		{
			hash.Add(element);
		}
		return hash.ToHashCode();
	}

	public override bool Equals(object? obj)
		=> obj is ImmutableValueSequence<T> other && other.Equals(this);

	public bool Equals(ImmutableValueSequence<T> other)
		=> other.SequenceEqual(this);

	IEnumerator<T> IEnumerable<T>.GetEnumerator() => GetEnumerator(_elements);

	IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(_elements);

	private static IEnumerator<T> GetEnumerator<TArray>(in TArray array)
		where TArray : IEnumerable<T>
	{
		return array.GetEnumerator();
	}
}

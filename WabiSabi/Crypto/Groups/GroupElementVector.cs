using System.Collections;
using WabiSabi.Helpers;

namespace WabiSabi.Crypto.Groups;

public class GroupElementVector : IReadOnlyCollection<GroupElement>
{
	internal GroupElementVector(IEnumerable<GroupElement> groupElements)
	{
		Guard.NotNullOrEmpty(nameof(groupElements), groupElements);
		GroupElements = groupElements.ToArray();
	}

	internal GroupElementVector(params GroupElement[] groupElements)
		: this(groupElements as IEnumerable<GroupElement>)
	{
	}

	private IEnumerable<GroupElement> GroupElements { get; }

	public IEnumerator<GroupElement> GetEnumerator() =>
		GroupElements.GetEnumerator();

	IEnumerator IEnumerable.GetEnumerator() =>
		GetEnumerator();

	public int Count => GroupElements.Count();

	public static bool operator ==(GroupElementVector? x, GroupElementVector? y) => x?.Equals(y) ?? false;

	public static bool operator !=(GroupElementVector? x, GroupElementVector? y) => !(x == y);

	public override int GetHashCode()
	{
		int hc = 0;

		foreach (var element in GroupElements)
		{
			hc ^= element.GetHashCode();
			hc = (hc << 7) | (hc >> (32 - 7));
		}

		return hc;
	}

	public override bool Equals(object? other) => Equals(other as GroupElementVector);

	public bool Equals(GroupElementVector? other)
	{
		if (other is null)
		{
			return false;
		}

		return GroupElements.SequenceEqual(other.GroupElements);
	}
}

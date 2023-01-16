using System.Globalization;

namespace WabiSabi.Helpers;

public static class ByteHelpers
{
	public static byte[] Combine(params byte[][] arrays)
	{
		return Combine(arrays.AsEnumerable());
	}

	public static byte[] Combine(IEnumerable<byte[]> arrays)
	{
		byte[] ret = new byte[arrays.Sum(x => x.Length)];
		int offset = 0;
		foreach (byte[] data in arrays)
		{
			Buffer.BlockCopy(data, 0, ret, offset, data.Length);
			offset += data.Length;
		}
		return ret;
	}

	public static string ToHex(params byte[] bytes) =>
		Convert.ToHexString(bytes);

	/// <seealso cref="Convert.FromHexString(string)"/>
	public static byte[] FromHex(string hex)
	{
		if (string.IsNullOrWhiteSpace(hex))
		{
			return Array.Empty<byte>();
		}

		return Convert.FromHexString(hex);
	}
}

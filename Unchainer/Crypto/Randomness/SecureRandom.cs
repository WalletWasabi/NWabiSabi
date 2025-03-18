using System.Security.Cryptography;

namespace Unchainer.Crypto.Randomness;

public class SecureRandom : UnchainexRandom
{
	public static readonly SecureRandom Instance = new();

	public SecureRandom()
	{
	}

	public override void GetBytes(byte[] buffer)
	{
		RandomNumberGenerator.Fill(buffer);
	}

	public override void GetBytes(Span<byte> buffer)
	{
		RandomNumberGenerator.Fill(buffer);
	}

	public override int GetInt(int fromInclusive, int toExclusive)
	{
		return RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
	}
}

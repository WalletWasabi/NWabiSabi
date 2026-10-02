using System.Security.Cryptography;

namespace WabiSabi.Crypto.Randomness;

public class SecureRandom : WasabiRandom
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
}

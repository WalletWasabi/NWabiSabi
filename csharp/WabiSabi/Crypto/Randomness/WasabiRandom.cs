using NBitcoin.Secp256k1;
using WabiSabi.Helpers;

namespace WabiSabi.Crypto.Randomness;

public abstract class WasabiRandom
{
	public abstract void GetBytes(byte[] output);

	public abstract void GetBytes(Span<byte> output);

	public virtual byte[] GetBytes(int length)
	{
		Guard.MinimumAndNotNull(nameof(length), length, 1);
		var buffer = new byte[length];
		GetBytes(buffer);
		return buffer;
	}

	public virtual Scalar GetScalar()
	{
		Scalar randomScalar;
		int overflow;
		Span<byte> buffer = stackalloc byte[32];
		do
		{
			GetBytes(buffer);
			randomScalar = new Scalar(buffer, out overflow);
		}
		while (overflow != 0 || randomScalar.IsZero);
		return randomScalar;
	}
}

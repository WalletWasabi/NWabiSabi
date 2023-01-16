namespace WabiSabi.Crypto.StrobeProtocol;

using System.Text;
using WabiSabi;

public sealed class StrobeHasher
{
	private Strobe128 _strobe;

	private StrobeHasher(string domain)
	{
		_strobe = new Strobe128(ProtocolConstants.WabiSabiProtocolIdentifier);
		Append(ProtocolConstants.DomainStrobeSeparator, domain);
	}

	public static StrobeHasher Create(string domain)
		=> new(domain);

	public StrobeHasher Append(string fieldName, DateTimeOffset dateTime)
		=> Append(fieldName, dateTime.ToUnixTimeMilliseconds());

	public StrobeHasher Append(string fieldName, TimeSpan time)
		=> Append(fieldName, time.Ticks);

	public StrobeHasher Append(string fieldName, int num)
		=> Append(fieldName, BitConverter.GetBytes(num));

	public StrobeHasher Append(string fieldName, long num)
		=> Append(fieldName, BitConverter.GetBytes(num));

	public StrobeHasher Append(string fieldName, ulong num)
		=> Append(fieldName, BitConverter.GetBytes(num));

	public StrobeHasher Append(string fieldName, CredentialIssuerParameters issuerParameters)
		=> Append($"{fieldName}.Cw", issuerParameters.Cw.ToBytes())
		.Append($"{fieldName}.I", issuerParameters.I.ToBytes());

	public StrobeHasher Append(string fieldName, string str)
		=> Append($"{fieldName}.Cw", Encoding.UTF8.GetBytes(str));

	public StrobeHasher Append(string fieldName, byte[] serializedValue)
	{
		_strobe.AddAssociatedMetaData(Encoding.UTF8.GetBytes(fieldName), false);
		_strobe.AddAssociatedMetaData(BitConverter.GetBytes(serializedValue.Length), true);
		_strobe.AddAssociatedData(serializedValue, false);
		return this;
	}
}

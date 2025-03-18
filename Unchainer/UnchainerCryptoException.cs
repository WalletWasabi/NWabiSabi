using System.Runtime.Serialization;

namespace Unchainer.Crypto;

[Serializable]
public class UnchainerCryptoException : Exception
{
	public UnchainerCryptoException(UnchainerCryptoErrorCode errorCode, string? message = null, Exception? innerException = null)
		: base(message, innerException)
	{
		ErrorCode = errorCode;
	}

	protected UnchainerCryptoException(SerializationInfo info, StreamingContext context)
		: base(info, context)
	{
	}

	public UnchainerCryptoErrorCode ErrorCode { get; }
}

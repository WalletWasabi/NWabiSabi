// Minimal reference copies of the two WalletWasabi NBitcoinExtensions helpers the
// vendored Crypto classes depend on (FromBytes, TryGetScriptType), lifted from
// WalletWasabi/Extensions/NBitcoinExtensions.cs. See OwnershipIdentifier.cs for
// why these reference copies exist.
using NBitcoin;

namespace WalletWasabi.Extensions;

public static class NBitcoinExtensions
{
	public static T FromBytes<T>(byte[] input) where T : IBitcoinSerializable, new()
	{
		BitcoinStream inputStream = new(input);
		var instance = new T();
		inputStream.ReadWrite(instance);
		if (inputStream.Inner.Length != inputStream.Inner.Position)
		{
			throw new FormatException("Expected end of stream");
		}

		return instance;
	}

	public static ScriptType? TryGetScriptType(this Script script)
	{
		foreach (ScriptType scriptType in new[] { ScriptType.P2WPKH, ScriptType.P2PKH, ScriptType.P2PK, ScriptType.P2WSH, ScriptType.Taproot, ScriptType.P2SH })
		{
			if (script.IsScriptType(scriptType))
			{
				return scriptType;
			}
		}

		return null;
	}
}

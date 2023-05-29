namespace WabiSabi.Crypto.ZeroKnowledge;

using NBitcoin.Secp256k1;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Groups;
using Randomness;
using StrobeProtocol;
using LinearRelation;
using Helpers;

// High level API for transcripts of compound Sigma protocol style proofs
// implements synthetic nonces and Fiat-Shamir challenges.
public sealed class Transcript
{
	private const int KeySizeInBytes = 32;

	private static readonly byte[] StatementTag = Encoding.UTF8.GetBytes("statement");
	private static readonly byte[] ChallengeTag = Encoding.UTF8.GetBytes("challenge");
	private static readonly byte[] PublicNonceTag = Encoding.UTF8.GetBytes("nonce-commitment");
	private static readonly byte[] DomainSeparatorTag = Encoding.UTF8.GetBytes("domain-separator");

	/// <summary>
	/// Initialize a new transcript with the supplied <param>label</param>, which
	/// is used as a domain separator.
	/// </summary>
	/// <remarks>
	/// This function should be called by a proof library's API consumer
	/// (i.e., the application using the proof library), and
	/// **not by the proof implementation**.  See the [Passing
	/// Transcripts](https://merlin.cool/use/passing.html) section of
	/// the Merlin website for more details on why.
	/// </remarks>
	public Transcript(byte[] label)
		: this(new Strobe128(ProtocolConstants.WabiSabiProtocolIdentifier))
	{
		AddMessage(DomainSeparatorTag, label);
	}

	// Private constructor used for cloning.
	internal Transcript(Strobe128 strobe)
	{
		Strobe = strobe;
	}

	internal Strobe128 Strobe { get; }

	// Generate synthetic nonce using current state combined with additional randomness.
	public SyntheticSecretNonceProvider CreateSyntheticSecretNonceProvider(IEnumerable<Scalar> secrets, WasabiRandom random)
		=> new(Strobe.MakeCopy(), secrets, random);

	public void CommitPublicNonces(IEnumerable<GroupElement> publicNonces)
	{
		Guard.NotNullOrInfinity(nameof(publicNonces), publicNonces);
		AddMessages(PublicNonceTag, publicNonces.Select(x => x.ToBytes()));
	}

	internal void CommitStatement(Statement statement)
	{
		AddMessages(StatementTag, statement.PublicPoints.Select(x => x.ToBytes()).Concat(statement.Generators.Select(x => x.ToBytes())));
	}

	// Generate Fiat Shamir challenges
	public Scalar GenerateChallenge()
	{
		Scalar scalar;
		int overflow;
		do
		{
			Strobe.AddAssociatedMetaData(ChallengeTag, false);
			scalar = new Scalar(Strobe.Prf(KeySizeInBytes, false), out overflow);
		}
		while (overflow != 0);
		return scalar;
	}

	private void AddMessage(byte[] label, byte[] message)
	{
		Strobe.AddAssociatedMetaData(label, false);
		Strobe.AddAssociatedMetaData(BitConverter.GetBytes(message.Length), true);
		Strobe.AddAssociatedData(message, false);
	}

	private void AddMessages(byte[] label, IEnumerable<byte[]> messages)
	{
		Strobe.AddAssociatedMetaData(label, false);
		Strobe.AddAssociatedMetaData(BitConverter.GetBytes(messages.Count()), true);
		foreach (var message in messages.Select((m, i) => (Index: i, Payload: m)))
		{
			AddMessage(BitConverter.GetBytes(message.Index), message.Payload);
		}
	}
}

using System.Linq;
using NBitcoin.Secp256k1;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.Crypto.ZeroKnowledge.LinearRelation;

namespace WabiSabi.Tests.Crypto;

internal class ProofSystemHelpers
{
	public static bool Verify(Statement statement, Proof proof)
	{
		return ProofSystem.Verify(new Transcript(Array.Empty<byte>()), new[] { statement }, new[] { proof });
	}

	public static Proof Prove(Knowledge knowledge, WasabiRandom random)
	{
		return ProofSystem.Prove(new Transcript(Array.Empty<byte>()), new[] { knowledge }, random).First();
	}

	public static Proof Prove(Statement statement, Scalar witness, WasabiRandom random)
	{
		return Prove(statement, new ScalarVector(witness), random);
	}

	public static Proof Prove(Statement statement, ScalarVector witness, WasabiRandom random)
	{
		return Prove(new Knowledge(statement, witness), random);
	}
}

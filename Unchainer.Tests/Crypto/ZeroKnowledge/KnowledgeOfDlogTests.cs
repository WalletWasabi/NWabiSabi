using Moq;
using NBitcoin.Secp256k1;
using Unchainer.Crypto.Groups;
using Unchainer.Crypto.Randomness;
using Unchainer.Crypto.ZeroKnowledge.LinearRelation;
using UnchainexWallet.Tests.Helpers;

namespace Unchainer.Tests.Crypto.ZeroKnowledge;

public class KnowledgeOfDLogTests
{
	[Theory]
	[InlineData(1)]
	[InlineData(3)]
	[InlineData(5)]
	[InlineData(7)]
	[InlineData(short.MaxValue)]
	[InlineData(int.MaxValue)]
	[InlineData(uint.MaxValue)]
	public void End2EndVerificationSimple(uint scalarSeed)
	{
		var secret = new Scalar(scalarSeed);
		var generator = Generators.G;
		var publicPoint = secret * generator;
		var statement = new Statement(publicPoint, generator);
		var mockRandom = new Mock<UnchainexRandom>();
		mockRandom.Setup(rnd => rnd.GetBytes(32)).Returns(new byte[32]);
		var proof = ProofSystemHelpers.Prove(statement, secret, mockRandom.Object);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));
	}

	[Fact]
	public void End2EndVerification()
	{
		foreach (var secret in CryptoHelpers.GetScalars(x => !x.IsOverflow && !x.IsZero))
		{
			var generator = Generators.G;
			var publicPoint = secret * generator;
			var statement = new Statement(publicPoint, Generators.G);
			var proof = ProofSystemHelpers.Prove(statement, secret, SecureRandom.Instance);
			Assert.True(ProofSystemHelpers.Verify(statement, proof));
		}
	}

	[Fact]
	public void End2EndVerificationLargeScalar()
	{
		var random = SecureRandom.Instance;
		uint val = int.MaxValue;
		var gen = new Scalar(4) * Generators.G;

		var secret = new Scalar(val, val, val, val, val, val, val, val);
		var p = secret * gen;
		var statement = new Statement(p, gen);
		var proof = ProofSystemHelpers.Prove(statement, secret, random);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));

		secret = EC.N + Scalar.One.Negate();
		p = secret * gen;
		statement = new Statement(p, gen);
		proof = ProofSystemHelpers.Prove(statement, secret, random);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));

		secret = EC.NC;
		p = secret * gen;
		statement = new Statement(p, gen);
		proof = ProofSystemHelpers.Prove(statement, secret, random);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));

		secret = EC.NC + Scalar.One;
		p = secret * gen;
		statement = new Statement(p, gen);
		proof = ProofSystemHelpers.Prove(statement, secret, random);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));

		secret = EC.NC + Scalar.One.Negate();
		p = secret * gen;
		statement = new Statement(p, gen);
		proof = ProofSystemHelpers.Prove(statement, secret, random);
		Assert.True(ProofSystemHelpers.Verify(statement, proof));
	}
}

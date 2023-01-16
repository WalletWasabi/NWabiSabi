namespace WabiSabi.Crypto.ZeroKnowledge.LinearRelation;

using NBitcoin.Secp256k1;
using Helpers;

internal record Knowledge
{
	internal Knowledge(Statement statement, ScalarVector witness)
	{
		Guard.True(nameof(witness), witness.Count == statement.Equations.First().Generators.Count, $"{nameof(witness)} size does not match {nameof(statement)}.{nameof(statement.Equations)}");

		Statement = statement;
		Witness = witness;
	}

	public Statement Statement { get; }
	public ScalarVector Witness { get; }

	internal ScalarVector RespondToChallenge(Scalar challenge, ScalarVector secretNonces) =>
		Equation.Respond(Witness, secretNonces, challenge);

	/// <summary>For testing purposes.</summary>
	internal void AssertSoundness()
	{
		foreach (var equation in Statement.Equations)
		{
			equation.CheckSolution(Witness);
		}
	}
}

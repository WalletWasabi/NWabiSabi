using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using Xunit;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;

namespace WabiSabiInterop.Tests;

/// <summary>Thread-safe RNG (RandomNumberGenerator is thread-safe), matching how
/// WalletWasabi shares one thread-safe RNG across concurrent Alices.</summary>
internal sealed class ThreadSafeRandom : WasabiRandom
{
    public override void GetBytes(byte[] output) => RandomNumberGenerator.Fill(output);
    public override void GetBytes(Span<byte> output) => RandomNumberGenerator.Fill(output);
    public override int GetInt(int fromInclusive, int toExclusive) =>
        RandomNumberGenerator.GetInt32(fromInclusive, toExclusive);
}

/// <summary>
/// Regression guard for the native proof-generation thread-safety bug. The C proof
/// code (proof.c) used function-local <c>static</c> scratch buffers shared across all
/// threads; concurrent prove/verify calls clobbered each other and produced invalid
/// proofs that the C# issuer rejected with <c>CoordinatorReceivedInvalidProofs</c>.
///
/// This reproduced in WalletWasabi because two Alices share one ArenaClient (one native
/// amount client) and run their input-registration + confirmation flows concurrently.
/// The race is process-global (it reproduces even with separate client instances), so
/// these tests drive many concurrent full-protocol flows and assert every one succeeds.
/// </summary>
[Collection("NativeLibrary")]
public class ConcurrencyTests
{
    private const long WalletWasabiMaxAmount = 4_300_000_000_000L; // width 42

    private static Sha256ChainRandom ChainRng(string label) =>
        new(SHA256.HashData(Encoding.ASCII.GetBytes(label)));

    // One full confirmation-style flow: native client presents bootstrap zero
    // credentials and requests `amount`, verified by a C# issuer.
    private static long RunFlow(NativeClient client, CsIssuer issuer, long amount)
    {
        var zero      = client.CreateRequestForZeroAmount();
        var zeroResp  = issuer.HandleRequest(zero.CredentialsRequest);
        var zeroCreds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        var real      = client.CreateRequest(new[] { amount, 0L }, zeroCreds, CancellationToken.None);
        var realResp  = issuer.HandleRequest(real.CredentialsRequest);
        var creds     = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();
        return creds.Sum(c => c.Value);
    }

    // Shared client instance across concurrent flows — mirrors WalletWasabi's ArenaClient.
    [Fact]
    public async Task SharedClient_ManyConcurrentFlows_AllProofsValid()
    {
        var sk      = new CredentialIssuerSecretKey(ChainRng("conc-shared-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();
        var client  = new NativeClient(iparams, new ThreadSafeRandom(), WalletWasabiMaxAmount);
        var issuer  = new CsIssuer(sk, ChainRng("conc-shared-issuer"), WalletWasabiMaxAmount);

        var amounts = Enumerable.Range(1, 16).Select(i => (long)i * 100_000_000L).ToArray();
        var tasks = amounts.Select(a => Task.Run(() => RunFlow(client, issuer, a))).ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(amounts, results);
    }

    // Separate client instances, still concurrent — proves the fixed scratch is not
    // process-global shared state anymore.
    [Fact]
    public async Task SeparateClients_ManyConcurrentFlows_AllProofsValid()
    {
        var sk      = new CredentialIssuerSecretKey(ChainRng("conc-sep-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();
        var issuer  = new CsIssuer(sk, ChainRng("conc-sep-issuer"), WalletWasabiMaxAmount);

        long Flow(int i)
        {
            var client = new NativeClient(iparams, ChainRng($"conc-sep-client-{i}"), WalletWasabiMaxAmount);
            return RunFlow(client, issuer, (long)i * 100_000_000L);
        }

        var tasks = Enumerable.Range(1, 16).Select(i => Task.Run(() => Flow(i))).ToArray();
        var results = await Task.WhenAll(tasks);

        Assert.Equal(Enumerable.Range(1, 16).Select(i => (long)i * 100_000_000L), results);
    }
}

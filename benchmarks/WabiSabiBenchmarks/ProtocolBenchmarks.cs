using System.Linq;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.CredentialRequesting;

// The managed reference types and the native FFI-backed wrappers share an
// identical API but live in different namespaces; alias them apart.
using CsClient = WabiSabi.Crypto.WabiSabiClient;
using CsIssuer = WabiSabi.Crypto.CredentialIssuer;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using NativeIssuer = WabiSabi.Native.CredentialIssuer;

namespace WabiSabiBenchmarks;

/// <summary>
/// Compares the throughput of the pure-managed C# implementation against the
/// native C library (via the P/Invoke wrappers) over a realistic WabiSabi
/// credential exchange.
///
/// The measured workload is NOT a trivial zero→real bootstrap. It is the full
/// client⇄coordinator conversation:
///
///   Round 1 — bootstrap : client requests k zero-value credentials.
///   Round 2 — issuance  : client presents the zero credentials and requests
///                          k real-value credentials (sum = S).
///   Round 3..N — reissue: client presents its REAL credentials and requests
///                          k new REAL credentials whose amounts again sum to S
///                          (a balance-neutral re-issuance, i.e. exactly the
///                          "present real credentials, get more real credentials"
///                          step). At least one such round always runs.
///
/// Every round exercises proof generation (client), proof verification +
/// MAC issuance (coordinator), and issuance-proof verification (client),
/// so the numbers reflect the end-to-end cryptographic cost of the protocol.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput, launchCount: 1, warmupCount: 3, iterationCount: 8)]
public class ProtocolBenchmarks
{
    private const long MaxAmount = 1_000_000L;

    // Round 2 mints two real credentials summing to 800_000.
    private static readonly long[] InitialAmounts = { 500_000L, 300_000L };

    // Each reissuance round presents the previous real credentials (sum 800_000)
    // and requests new amounts that again sum to 800_000 — balance-neutral, so
    // the coordinator's running balance never changes and the proofs stay valid.
    private static readonly long[] ReissueAmounts = { 400_000L, 400_000L };

    /// <summary>How many extra real→real re-issuance rounds run after issuance.</summary>
    [Params(1, 3)]
    public int ReissuanceRounds;

    private CredentialIssuerSecretKey _sk = null!;
    private CredentialIssuerParameters _iparams = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Issuer key / parameter generation is a one-time coordinator cost and is
        // deliberately excluded from the measured per-exchange work.
        _sk = new CredentialIssuerSecretKey(SecureRandom.Instance);
        _iparams = _sk.ComputeCredentialIssuerParameters();
    }

    [Benchmark(Baseline = true, Description = "Managed C#")]
    public object Managed()
    {
        var rng = SecureRandom.Instance;
        var client = new CsClient(_iparams, rng, MaxAmount);
        var issuer = new CsIssuer(_sk, rng, MaxAmount);

        // Round 1 — bootstrap zero-value credentials.
        var zero = client.CreateRequestForZeroAmount();
        var zeroResp = issuer.HandleRequest(zero.CredentialsRequest);
        var creds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        // Round 2 — present zero credentials, obtain real credentials.
        var real = client.CreateRequest(InitialAmounts, creds, CancellationToken.None);
        var realResp = issuer.HandleRequest(real.CredentialsRequest);
        creds = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        // Round 3..N — present real credentials, obtain more real credentials.
        for (int i = 0; i < ReissuanceRounds; i++)
        {
            var re = client.CreateRequest(ReissueAmounts, creds, CancellationToken.None);
            var reResp = issuer.HandleRequest(re.CredentialsRequest);
            creds = client.HandleResponse(reResp, re.CredentialsResponseValidation).ToArray();
        }

        return creds;
    }

    [Benchmark(Description = "Native C")]
    public object Native()
    {
        var rng = SecureRandom.Instance;
        var client = new NativeClient(_iparams, rng, MaxAmount);
        var issuer = new NativeIssuer(_sk, rng, MaxAmount);

        // Round 1 — bootstrap zero-value credentials.
        var zero = client.CreateRequestForZeroAmount();
        var zeroResp = issuer.HandleRequest(zero.CredentialsRequest);
        var creds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        // Round 2 — present zero credentials, obtain real credentials.
        var real = client.CreateRequest(InitialAmounts, creds, CancellationToken.None);
        var realResp = issuer.HandleRequest(real.CredentialsRequest);
        creds = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        // Round 3..N — present real credentials, obtain more real credentials.
        for (int i = 0; i < ReissuanceRounds; i++)
        {
            var re = client.CreateRequest(ReissueAmounts, creds, CancellationToken.None);
            var reResp = issuer.HandleRequest(re.CredentialsRequest);
            creds = client.HandleResponse(reResp, re.CredentialsResponseValidation).ToArray();
        }

        return creds;
    }
}

using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.CredentialRequesting;
using WabiSabi.Native;
using Xunit;

// Aliases distinguish the native FFI wrappers from the C# reference classes.
using NativeIssuer = WabiSabi.Native.CredentialIssuer;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using CsClient     = WabiSabi.Crypto.WabiSabiClient;

namespace WabiSabiInterop.Tests;

/// <summary>
/// The byte-equality differential test (the "debugging superpower"), seed variant.
///
/// Both implementations derive randomness from the <b>same 32-byte seed</b> using
/// the same block function <c>block_i = SHA256(seed || LE32(i))</c>:
/// <list type="bullet">
/// <item>the managed reference draws from <see cref="Sha256SeedRandom"/>, which
///   expands the seed exactly that way;</item>
/// <item>the native side receives the raw seed over the FFI (the wrapper is handed
///   a <see cref="FixedSeedRandom"/> so its single <c>GetBytes(32)</c> forwards the
///   seed verbatim) and expands it identically in <c>c/src/rand_stream.h</c>.</item>
/// </list>
/// Fed the same seed with the same consumption order, their wire output is
/// <b>byte-identical</b> — a far stricter check than the validity-level gate in
/// <see cref="BinaryCompatibilityTests"/>, and the one that catches silent drift in
/// randomness-consumption order.
///
/// <para>The native wrapper re-seeds (draws a fresh FFI seed, counter back to 0) on
/// every call, so each protocol message is produced by a freshly constructed,
/// identically seeded pair — keeping both sides at block index zero for the
/// comparison. This mirrors how randomness is a per-request concern in practice.</para>
/// </summary>
[Collection("NativeLibrary")]
public class ByteEqualityTests
{
    private const long MaxAmount = 1_000_000L;
    private static readonly long[] TestAmounts = { 500_000L, 300_000L };

    private static readonly CredentialIssuerSecretKey FixedSk = new(ChainRng("be-sk-seed"));
    private static readonly CredentialIssuerParameters FixedIparams = FixedSk.ComputeCredentialIssuerParameters();

    [Fact]
    public void ZeroRequest_IsByteIdentical()
    {
        var seed = Seed("client-zero");

        var cs = new CsClient(FixedIparams, new Sha256SeedRandom(seed), MaxAmount)
            .CreateRequestForZeroAmount().CredentialsRequest;
        var nv = new NativeClient(FixedIparams, new FixedSeedRandom(seed), MaxAmount)
            .CreateRequestForZeroAmount().CredentialsRequest;

        Assert.Equal(
            WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)cs),
            WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)nv));
    }

    [Fact]
    public void FullProtocol_IsByteIdenticalAtEveryStep()
    {
        // Each round uses its own freshly, identically seeded pair so both sides sit
        // at block index zero for every compared message. The zero client is reused
        // for HandleResponse (which consumes no randomness) since the native wrapper
        // tracks per-request validation state per instance.
        var zeroSeed = Seed("client-zero");
        var csClientZero = new CsClient(FixedIparams, new Sha256SeedRandom(zeroSeed), MaxAmount);
        var nvClientZero = new NativeClient(FixedIparams, new FixedSeedRandom(zeroSeed), MaxAmount);

        // ── Step 1: bootstrap (zero) request ──
        var csZeroData = csClientZero.CreateRequestForZeroAmount();
        var nvZeroData = nvClientZero.CreateRequestForZeroAmount();

        Assert.Equal(
            WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)csZeroData.CredentialsRequest),
            WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)nvZeroData.CredentialsRequest));

        // ── Step 2: issuer response to the (identical) zero request ──
        var issuerZeroSeed = Seed("issuer-zero");
        var csZeroResp = new CsIssuer(FixedSk, new Sha256SeedRandom(issuerZeroSeed), MaxAmount)
            .HandleRequest(csZeroData.CredentialsRequest);
        var nvZeroResp = new NativeIssuer(FixedSk, new FixedSeedRandom(issuerZeroSeed), MaxAmount)
            .HandleRequest(nvZeroData.CredentialsRequest);

        Assert.Equal(
            WireFormat.SerializeResponse(csZeroResp),
            WireFormat.SerializeResponse(nvZeroResp));

        // Extract credentials (no randomness consumed here). Identical responses +
        // identical validation state ⇒ identical credentials on both sides.
        var csCredentials = csClientZero.HandleResponse(csZeroResp, csZeroData.CredentialsResponseValidation).ToArray();
        var nvCredentials = nvClientZero.HandleResponse(nvZeroResp, nvZeroData.CredentialsResponseValidation).ToArray();
        Assert.Equal(
            csCredentials.Select(WireFormat.SerializeCredential),
            nvCredentials.Select(WireFormat.SerializeCredential));

        // ── Step 3: real (input-registration) request presenting those credentials ──
        var realSeed = Seed("client-real");
        var csRealData = new CsClient(FixedIparams, new Sha256SeedRandom(realSeed), MaxAmount)
            .CreateRequest(TestAmounts, csCredentials, CancellationToken.None);
        var nvRealData = new NativeClient(FixedIparams, new FixedSeedRandom(realSeed), MaxAmount)
            .CreateRequest(TestAmounts, nvCredentials, CancellationToken.None);

        Assert.Equal(
            WireFormat.SerializeRealRequest((RealCredentialsRequest)csRealData.CredentialsRequest),
            WireFormat.SerializeRealRequest((RealCredentialsRequest)nvRealData.CredentialsRequest));

        // ── Step 4: issuer response to the (identical) real request ──
        var issuerRealSeed = Seed("issuer-real");
        var csRealResp = new CsIssuer(FixedSk, new Sha256SeedRandom(issuerRealSeed), MaxAmount)
            .HandleRequest(csRealData.CredentialsRequest);
        var nvRealResp = new NativeIssuer(FixedSk, new FixedSeedRandom(issuerRealSeed), MaxAmount)
            .HandleRequest(nvRealData.CredentialsRequest);

        Assert.Equal(
            WireFormat.SerializeResponse(csRealResp),
            WireFormat.SerializeResponse(nvRealResp));
    }

    // A fixed 32-byte seed from a label (the seed handed, identically, to both sides).
    private static byte[] Seed(string label) => SHA256.HashData(Encoding.ASCII.GetBytes(label));

    private static Sha256ChainRandom ChainRng(string label) =>
        new(SHA256.HashData(Encoding.ASCII.GetBytes(label)));
}

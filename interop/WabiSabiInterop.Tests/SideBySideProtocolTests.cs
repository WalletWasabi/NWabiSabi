using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi.Crypto;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.Native;
using Xunit;

// Aliases distinguish the native FFI wrappers from the C# reference classes.
using NativeIssuer = WabiSabi.Native.CredentialIssuer;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using CsClient     = WabiSabi.Crypto.WabiSabiClient;

namespace WabiSabiInterop.Tests;

/// <summary>
/// Runs the <b>same protocol scenario independently in each implementation</b>
/// — the C# reference pair (C# client ↔ C# issuer) and the native pair
/// (native client ↔ native issuer) — and asserts that the protocol results
/// returned by both are identical after every step.
///
/// Why this is a <i>semantic</i> comparison, not a byte comparison
/// ───────────────────────────────────────────────────────────────
/// Across the two implementations the only byte-deterministic artefact is the
/// issuer parameters (covered by <see cref="BinaryCompatibilityTests"/> Test 1).
/// Everything on the wire carries randomness drawn through divergent interfaces:
///   • the issuer's MAC tag <c>t</c> is a fresh random scalar (CredentialIssuer.cs);
///   • all zero-knowledge proofs use fresh random nonces;
///   • the native side expands a single 32-byte seed in C, whereas the managed
///     reference pulls <c>GetScalar()</c> repeatedly — so identical seeds do
///     <b>not</b> produce identical scalars.
/// Therefore the raw request/response bytes legitimately differ between the two
/// implementations. What MUST agree are the protocol <b>results</b>: how many
/// credentials are issued, their values, and the issuer's running balance.
///
/// Unlike <see cref="BinaryCompatibilityTests"/> (which cross-feeds one
/// implementation's messages to the other and so depends on cross-language
/// proof verification), here each implementation only ever talks to itself, so
/// these tests do not depend on the open Fiat-Shamir compatibility problem and
/// act as a guard that both implementations realise the same protocol.
/// </summary>
[Collection("NativeLibrary")]
public class SideBySideProtocolTests
{
    private const long MaxAmount = 1_000_000L;
    private static readonly long[] TestAmounts = { 500_000L, 300_000L };

    private static readonly CredentialIssuerSecretKey FixedSk =
        new(ChainRng("side-by-side-sk-seed"));

    private static readonly CredentialIssuerParameters FixedIparams =
        FixedSk.ComputeCredentialIssuerParameters();

    // -----------------------------------------------------------------------
    // Step 1 — bootstrap (zero) round, side by side
    // -----------------------------------------------------------------------

    [Fact]
    public void ZeroRound_RunInBothImplementations_ProducesSameResults()
    {
        var (cs, native) = MakeProtocolPairs();

        var csZero     = RunZeroRound(cs.Client, cs.Issuer);
        var nativeZero = RunZeroRound(native.Client, native.Issuer);

        AssertCredentialValuesEqual(csZero, nativeZero);
        Assert.All(csZero, c => Assert.Equal(0L, c.Value));
        Assert.Equal(cs.Issuer.Balance, native.Issuer.Balance);
    }

    // -----------------------------------------------------------------------
    // Step 1 + 2 — full two-round protocol, side by side, compared per step
    // -----------------------------------------------------------------------

    [Fact]
    public void FullProtocol_RunInBothImplementations_ProducesSameResultsAtEachStep()
    {
        var (cs, native) = MakeProtocolPairs();

        // ── Step 1: bootstrap round ──
        var csZero     = RunZeroRound(cs.Client, cs.Issuer);
        var nativeZero = RunZeroRound(native.Client, native.Issuer);

        AssertCredentialValuesEqual(csZero, nativeZero);
        Assert.Equal(cs.Issuer.Balance, native.Issuer.Balance);

        // ── Step 2: input-registration round ──
        // Each implementation presents the credentials it obtained in step 1.
        var csValue = RunRealRound(cs.Client, cs.Issuer, csZero);
        var nativeValue = RunRealRound(native.Client, native.Issuer, nativeZero);

        AssertCredentialValuesEqual(csValue, nativeValue);
        Assert.Equal(TestAmounts.Sum(), csValue.Sum(c => c.Value));
        Assert.Equal(TestAmounts.Sum(), nativeValue.Sum(c => c.Value));
        Assert.Equal(cs.Issuer.Balance, native.Issuer.Balance);
    }

    // -----------------------------------------------------------------------
    // Protocol drivers (identical API on both the reference and native types)
    // -----------------------------------------------------------------------

    private static Credential[] RunZeroRound(CsClient client, CsIssuer issuer)
    {
        var data = client.CreateRequestForZeroAmount();
        var resp = issuer.HandleRequest(data.CredentialsRequest);
        return client.HandleResponse(resp, data.CredentialsResponseValidation).ToArray();
    }

    private static Credential[] RunZeroRound(NativeClient client, NativeIssuer issuer)
    {
        var data = client.CreateRequestForZeroAmount();
        var resp = issuer.HandleRequest(data.CredentialsRequest);
        return client.HandleResponse(resp, data.CredentialsResponseValidation).ToArray();
    }

    private static Credential[] RunRealRound(CsClient client, CsIssuer issuer, Credential[] toPresent)
    {
        var data = client.CreateRequest(TestAmounts, toPresent, CancellationToken.None);
        var resp = issuer.HandleRequest(data.CredentialsRequest);
        return client.HandleResponse(resp, data.CredentialsResponseValidation).ToArray();
    }

    private static Credential[] RunRealRound(NativeClient client, NativeIssuer issuer, Credential[] toPresent)
    {
        var data = client.CreateRequest(TestAmounts, toPresent, CancellationToken.None);
        var resp = issuer.HandleRequest(data.CredentialsRequest);
        return client.HandleResponse(resp, data.CredentialsResponseValidation).ToArray();
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Builds a C# reference pair and a native pair that share the fixed issuer
    /// key/parameters and the same per-role RNG seeds, so any difference in the
    /// results is attributable to the implementations, not the inputs.
    /// </summary>
    private static ((CsClient Client, CsIssuer Issuer) Cs,
                    (NativeClient Client, NativeIssuer Issuer) Native) MakeProtocolPairs()
    {
        var cs = (
            Client: new CsClient(FixedIparams, ChainRng("sbs-client"), MaxAmount),
            Issuer: new CsIssuer(FixedSk, ChainRng("sbs-issuer"), MaxAmount));

        var native = (
            Client: new NativeClient(FixedIparams, ChainRng("sbs-client"), MaxAmount),
            Issuer: new NativeIssuer(FixedSk, ChainRng("sbs-issuer"), MaxAmount));

        return (cs, native);
    }

    /// <summary>
    /// Asserts the two credential sets carry exactly the same values (the
    /// randomness and MAC bytes legitimately differ — see class summary).
    /// </summary>
    private static void AssertCredentialValuesEqual(Credential[] a, Credential[] b)
    {
        Assert.Equal(NativeWabi.CredentialCount, a.Length);
        Assert.Equal(a.Length, b.Length);
        Assert.Equal(
            a.Select(c => c.Value).OrderBy(v => v),
            b.Select(c => c.Value).OrderBy(v => v));
    }

    private static Sha256ChainRandom ChainRng(string label) =>
        new(SHA256.HashData(Encoding.ASCII.GetBytes(label)));
}

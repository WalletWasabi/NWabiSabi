using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi.Crypto;
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
/// Verifies binary compatibility between the C native library and the C#
/// reference implementation.
///
/// Test taxonomy
/// ─────────────
/// 1. IssuerParams        — deterministic; exact byte equality (the primary
///                          "exact byte vector" test).
/// 2. ZeroBootstrap A     — C# client bytes consumed by native issuer; native
///                          response consumed by C# client.
/// 3. ZeroBootstrap B     — native client bytes consumed by C# issuer; C#
///                          response consumed by native client.
/// 4. FullProtocol A      — two-round C# client → native issuer.
/// 5. FullProtocol B      — two-round native client → C# issuer.
/// 6. Credential encoding — native credential bytes survive a C# WireFormat
///                          parse/re-serialise round-trip byte-for-byte.
/// </summary>
[Collection("NativeLibrary")]
public class BinaryCompatibilityTests
{
    // -----------------------------------------------------------------------
    // Shared fixed parameters
    // -----------------------------------------------------------------------

    private const long MaxAmount = 1_000_000L;
    private static readonly long[] TestAmounts = { 500_000L, 300_000L };

    // Stable secret key derived from a fixed seed so the C# reference bytes
    // never change between runs.
    private static readonly CredentialIssuerSecretKey FixedSk =
        new(ChainRng("binary-compat-sk-seed"));

    private static readonly byte[] FixedSkBytes = SerializeSecretKey(FixedSk);

    private static readonly CredentialIssuerParameters FixedIparams =
        FixedSk.ComputeCredentialIssuerParameters();

    private static readonly byte[] FixedIparamsBytes = SerializeIparams(FixedIparams);

    // -----------------------------------------------------------------------
    // Test 1 — IssuerParams: exact byte equality (no randomness involved)
    // -----------------------------------------------------------------------

    /// <summary>
    /// <c>wabisabi_iparams_from_sk</c> must produce the same 66 bytes as
    /// <see cref="CredentialIssuerSecretKey.ComputeCredentialIssuerParameters"/>.
    /// </summary>
    [Fact]
    public void IssuerParams_FromFixedSecretKey_NativeOutputMatchesCSharp()
    {
        var expected = new byte[NativeWabi.IParamsSize];
        FixedIparams.Cw.ToBytes().CopyTo(expected, 0);
        FixedIparams.I .ToBytes().CopyTo(expected, NativeWabi.GeSize);

        var actual = new byte[NativeWabi.IParamsSize];
        Assert.Equal(0, NativeWabi.IparamsFromSk(FixedSkBytes, actual));

        Assert.Equal<byte>(expected, actual);
    }

    // -----------------------------------------------------------------------
    // Test 2 — Zero bootstrap: C# client → native issuer
    // -----------------------------------------------------------------------

    /// <summary>
    /// The native issuer must accept the exact wire bytes produced by the C#
    /// client and issue a response the C# client can validate.
    /// </summary>
    [Fact]
    public void ZeroBootstrap_CSharpClientBytes_NativeIssuerAccepts_CSharpClientValidates()
    {
        var csClient    = new CsClient(FixedIparams, ChainRng("zb-a-cs-client"), MaxAmount);
        var nativeIssuer = new NativeIssuer(FixedSk, ChainRng("zb-a-native-issuer"), MaxAmount);

        var zeroData = csClient.CreateRequestForZeroAmount();
        var resp     = nativeIssuer.HandleRequest(zeroData.CredentialsRequest);
        var creds    = csClient.HandleResponse(resp, zeroData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, creds.Length);
        Assert.All(creds, c => Assert.Equal(0L, c.Value));
    }

    // -----------------------------------------------------------------------
    // Test 3 — Zero bootstrap: native client → C# issuer
    // -----------------------------------------------------------------------

    /// <summary>
    /// The C# issuer must accept the exact wire bytes produced by the native
    /// client and issue a response the native client can validate.
    /// </summary>
    [Fact]
    public void ZeroBootstrap_NativeClientBytes_CSharpIssuerAccepts_NativeClientValidates()
    {
        var csIssuer     = new CsIssuer(FixedSk, ChainRng("zb-b-cs-issuer"), MaxAmount);
        var nativeClient = new NativeClient(FixedIparams, ChainRng("zb-b-native-client"), MaxAmount);

        var zeroData = nativeClient.CreateRequestForZeroAmount();
        var nativeReqBytes = WireFormat.SerializeZeroRequest(
            (ZeroCredentialsRequest)zeroData.CredentialsRequest);
        var nativeReq = WireFormat.DeserializeZeroRequest(nativeReqBytes);

        var resp  = csIssuer.HandleRequest(nativeReq);
        var creds = nativeClient.HandleResponse(resp, zeroData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, creds.Length);
        Assert.All(creds, c => Assert.Equal(0L, c.Value));
    }

    // -----------------------------------------------------------------------
    // Test 4 — Full protocol: C# client → native issuer (Scenario A)
    // -----------------------------------------------------------------------

    [Fact]
    public void FullProtocol_CSharpClient_NativeIssuer_IssuesCorrectValueCredentials()
    {
        var csClient     = new CsClient(FixedIparams, ChainRng("fp-a-cs-client"), MaxAmount);
        var nativeIssuer = new NativeIssuer(FixedSk, ChainRng("fp-a-native-issuer"), MaxAmount);

        // Round 1: bootstrap
        var zeroData  = csClient.CreateRequestForZeroAmount();
        var zeroResp  = nativeIssuer.HandleRequest(zeroData.CredentialsRequest);
        var zeroCreds = csClient.HandleResponse(zeroResp, zeroData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, zeroCreds.Length);

        // Round 2: input registration
        var realData   = csClient.CreateRequest(TestAmounts, zeroCreds, CancellationToken.None);
        var realResp   = nativeIssuer.HandleRequest(realData.CredentialsRequest);
        var valueCreds = csClient.HandleResponse(realResp, realData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, valueCreds.Length);
        Assert.Equal(TestAmounts.Sum(), valueCreds.Sum(c => c.Value));
    }

    // -----------------------------------------------------------------------
    // Test 5 — Full protocol: native client → C# issuer (Scenario B)
    // -----------------------------------------------------------------------

    [Fact]
    public void FullProtocol_NativeClient_CSharpIssuer_IssuesCorrectValueCredentials()
    {
        var csIssuer     = new CsIssuer(FixedSk, ChainRng("fp-b-cs-issuer"), MaxAmount);
        var nativeClient = new NativeClient(FixedIparams, ChainRng("fp-b-native-client"), MaxAmount);
        var rangeWidth   = (int)Math.Ceiling(Math.Log2(MaxAmount));

        // Round 1: bootstrap
        var zeroData = nativeClient.CreateRequestForZeroAmount();
        var nativeZeroReq = WireFormat.DeserializeZeroRequest(
            WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)zeroData.CredentialsRequest));
        var zeroResp  = csIssuer.HandleRequest(nativeZeroReq);
        var zeroCreds = nativeClient.HandleResponse(zeroResp, zeroData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, zeroCreds.Length);

        // Round 2: input registration
        var realData = nativeClient.CreateRequest(TestAmounts, zeroCreds, CancellationToken.None);
        var nativeRealReq = WireFormat.DeserializeRealRequest(
            WireFormat.SerializeRealRequest((RealCredentialsRequest)realData.CredentialsRequest),
            rangeWidth);
        var realResp   = csIssuer.HandleRequest(nativeRealReq);
        var valueCreds = nativeClient.HandleResponse(realResp, realData.CredentialsResponseValidation).ToArray();

        Assert.Equal(NativeWabi.CredentialCount, valueCreds.Length);
        Assert.Equal(TestAmounts.Sum(), valueCreds.Sum(c => c.Value));
    }

    // -----------------------------------------------------------------------
    // Test 6 — Credential wire-format encoding stability
    // -----------------------------------------------------------------------

    /// <summary>
    /// Credential bytes written by <c>wabisabi_client_handle_response</c>
    /// must survive a C# WireFormat parse/re-serialise round-trip unchanged.
    /// </summary>
    [Fact]
    public void Credential_NativeWriteCredential_CSharpParseReserialize_IsIdentical()
    {
        var csIssuer = new CsIssuer(FixedSk, ChainRng("cred-cs-issuer"), MaxAmount);

        // Use the stateless C API directly to hold the raw credential bytes.
        var clientRand = ChainRng("cred-native-client").GetBytes(NativeWabi.RandSize);
        var reqOut     = new byte[NativeWabi.MaxRequestSize];
        var valOut     = new byte[NativeWabi.ValidationSize];
        int reqLen;
        Assert.Equal(0, NativeWabi.ClientCreateZeroRequest(clientRand, reqOut, reqOut.Length, out reqLen, valOut));

        // C# issuer processes the native zero request.
        var nativeZeroReq = WireFormat.DeserializeZeroRequest(reqOut[..reqLen]);
        var zeroResp      = csIssuer.HandleRequest(nativeZeroReq);
        var respBytes     = WireFormat.SerializeResponse(zeroResp);

        // Native client processes the C# issuer response; raw credential bytes
        // are written directly into credBuffer by the C library.
        var credBuffer = new byte[NativeWabi.CredentialCount * NativeWabi.CredentialSize];
        int nCreds;
        Assert.Equal(0, NativeWabi.ClientHandleResponse(
            FixedIparamsBytes, respBytes, respBytes.Length, valOut, credBuffer, credBuffer.Length, out nCreds));
        Assert.Equal(NativeWabi.CredentialCount, nCreds);

        // C# WireFormat parses the raw C bytes, then re-serialises them.
        // The output must be byte-for-byte identical to what C wrote.
        var parsedCreds  = WireFormat.UnpackCredentials(credBuffer, nCreds);
        var reserialised = WireFormat.PackCredentials(parsedCreds);

        Assert.Equal<byte>(credBuffer[..(nCreds * NativeWabi.CredentialSize)], reserialised);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static Sha256ChainRandom ChainRng(string label) =>
        new(SHA256.HashData(Encoding.ASCII.GetBytes(label)));

    private static byte[] SerializeSecretKey(CredentialIssuerSecretKey sk)
    {
        var buf = new byte[NativeWabi.SkSize];
        sk.W .ToBytes().CopyTo(buf,                      0);
        sk.Wp.ToBytes().CopyTo(buf,     NativeWabi.ScalarSize);
        sk.X0.ToBytes().CopyTo(buf, 2 * NativeWabi.ScalarSize);
        sk.X1.ToBytes().CopyTo(buf, 3 * NativeWabi.ScalarSize);
        sk.Ya.ToBytes().CopyTo(buf, 4 * NativeWabi.ScalarSize);
        return buf;
    }

    private static byte[] SerializeIparams(CredentialIssuerParameters iparams)
    {
        var buf = new byte[NativeWabi.IParamsSize];
        iparams.Cw.ToBytes().CopyTo(buf,                  0);
        iparams.I .ToBytes().CopyTo(buf, NativeWabi.GeSize);
        return buf;
    }
}

using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi.Crypto;
using Xunit;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using CsClient     = WabiSabi.Crypto.WabiSabiClient;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using NativeIssuer = WabiSabi.Native.CredentialIssuer;

namespace WabiSabiInterop.Tests;

/// <summary>
/// Regression guard for the FFI output-buffer overflow: a real credential request
/// grows with the range-proof width. WalletWasabi's coordinator uses
/// MaxRegistrableAmount = 43,000 BTC (width 42), whose real request is ~17.6 KiB and
/// overran the old fixed 16 KiB native reqOut/respOut buffers — crashing the process.
/// These exercise the full protocol through the native client AND native issuer at
/// that width; they must not crash and must round-trip the credential values.
/// </summary>
[Collection("NativeLibrary")]
public class LargeRangeWidthTests
{
    // 43,000 BTC in satoshis — the WalletWasabi default MaxRegistrableAmount (width 42).
    private const long WalletWasabiMaxAmount = 4_300_000_000_000L;
    private static readonly long[] Amounts = { 500_000L, 300_000L };

    [Fact]
    public void FullProtocol_NativeClient_CSharpIssuer_AtWalletWasabiWidth()
    {
        var sk      = new CredentialIssuerSecretKey(ChainRng("lrw-cs-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();

        var client = new NativeClient(iparams, ChainRng("lrw-native-client"), WalletWasabiMaxAmount);
        var issuer = new CsIssuer(sk, ChainRng("lrw-cs-issuer"), WalletWasabiMaxAmount);

        var zero      = client.CreateRequestForZeroAmount();
        var zeroResp  = issuer.HandleRequest(WireRoundTripZero(zero.CredentialsRequest));
        var zeroCreds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        var real      = client.CreateRequest(Amounts, zeroCreds, CancellationToken.None);
        var realResp  = issuer.HandleRequest(real.CredentialsRequest);
        var creds     = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        Assert.Equal(2, creds.Length);
        Assert.Equal(Amounts.Sum(), creds.Sum(c => c.Value));
    }

    [Fact]
    public void FullProtocol_CSharpClient_NativeIssuer_AtWalletWasabiWidth()
    {
        var sk      = new CredentialIssuerSecretKey(ChainRng("lrw2-cs-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();

        var client = new CsClient(iparams, ChainRng("lrw2-cs-client"), WalletWasabiMaxAmount);
        var issuer = new NativeIssuer(sk, ChainRng("lrw2-native-issuer"), WalletWasabiMaxAmount);

        var zero      = client.CreateRequestForZeroAmount();
        var zeroResp  = issuer.HandleRequest(zero.CredentialsRequest);
        var zeroCreds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        var real      = client.CreateRequest(Amounts, zeroCreds, CancellationToken.None);
        var realResp  = issuer.HandleRequest(real.CredentialsRequest);
        var creds     = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        Assert.Equal(2, creds.Length);
        Assert.Equal(Amounts.Sum(), creds.Sum(c => c.Value));
    }

    // The native client emits a ZeroCredentialsRequest; round-trip it through the wire
    // so the C# issuer receives exactly the serialized form (mirrors the existing suite).
    private static WabiSabi.CredentialRequesting.ZeroCredentialsRequest WireRoundTripZero(
        WabiSabi.CredentialRequesting.ICredentialsRequest req)
    {
        var bytes = WabiSabi.Native.WireFormat.SerializeZeroRequest(
            (WabiSabi.CredentialRequesting.ZeroCredentialsRequest)req);
        return WabiSabi.Native.WireFormat.DeserializeZeroRequest(bytes);
    }

    private static Sha256ChainRandom ChainRng(string label) =>
        new(SHA256.HashData(Encoding.ASCII.GetBytes(label)));
}

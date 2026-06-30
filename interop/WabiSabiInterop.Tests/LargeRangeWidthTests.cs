using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi.Crypto;
using WabiSabi.CredentialRequesting;
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

    // Mirrors the WalletWasabi confirmation flow: present zero credentials and request
    // the real coin value (1 BTC / 2 BTC). These values set high range-proof bits (~27)
    // that the {500k,300k} test above never touches.
    [Theory]
    [InlineData(100_000_000L, 0L)]
    [InlineData(100_000_000L, 200_000_000L)]
    [InlineData(4_299_999_999_999L, 0L)]
    public void FullProtocol_NativeClient_CSharpIssuer_LargeValues(long a0, long a1)
    {
        var amounts = new[] { a0, a1 };
        var sk      = new CredentialIssuerSecretKey(ChainRng("lrwhv-cs-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();

        var client = new NativeClient(iparams, ChainRng("lrwhv-native-client"), WalletWasabiMaxAmount);
        var issuer = new CsIssuer(sk, ChainRng("lrwhv-cs-issuer"), WalletWasabiMaxAmount);

        var zero      = client.CreateRequestForZeroAmount();
        var zeroResp  = issuer.HandleRequest(WireRoundTripZero(zero.CredentialsRequest));
        var zeroCreds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        var real      = client.CreateRequest(amounts, zeroCreds, CancellationToken.None);
        var realResp  = issuer.HandleRequest(real.CredentialsRequest);
        var creds     = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        Assert.Equal(2, creds.Length);
        Assert.Equal(amounts.Sum(), creds.Sum(c => c.Value));
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

    // Reproduces the WalletWasabi output-registration flow: a managed client first
    // obtains real credentials, then issues a *presentation-only* request (presents the
    // credentials, requests none) against the native issuer. This shape — Delta < 0 with
    // zero requested credentials — was unrepresentable in the FFI wire format and made the
    // native issuer fail with a parse error (WABISABI_ERR_PARSE). The native issuer must
    // verify it and return an empty (zero-credential) response.
    [Fact]
    public void PresentationOnly_CSharpClient_NativeIssuer()
    {
        var sk      = new CredentialIssuerSecretKey(ChainRng("pres-cs-sk"));
        var iparams = sk.ComputeCredentialIssuerParameters();

        var client = new CsClient(iparams, ChainRng("pres-cs-client"), WalletWasabiMaxAmount);
        var issuer = new NativeIssuer(sk, ChainRng("pres-native-issuer"), WalletWasabiMaxAmount);

        // Bootstrap then obtain real credentials worth Amounts.
        var zero      = client.CreateRequestForZeroAmount();
        var zeroResp  = issuer.HandleRequest(zero.CredentialsRequest);
        var zeroCreds = client.HandleResponse(zeroResp, zero.CredentialsResponseValidation).ToArray();

        var real      = client.CreateRequest(Amounts, zeroCreds, CancellationToken.None);
        var realResp  = issuer.HandleRequest(real.CredentialsRequest);
        var creds     = client.HandleResponse(realResp, real.CredentialsResponseValidation).ToArray();

        // Presentation-only request: present the credentials, request nothing.
        var present     = client.CreateRequest(creds, CancellationToken.None);
        Assert.True(present.CredentialsRequest.IsPresentationOnlyRequest());

        var presentResp = issuer.HandleRequest(present.CredentialsRequest);
        Assert.Empty(presentResp.IssuedCredentials);
        Assert.Empty(presentResp.Proofs);

        // The balance returned to zero after the presented amount was spent.
        Assert.Equal(0L, issuer.Balance);
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

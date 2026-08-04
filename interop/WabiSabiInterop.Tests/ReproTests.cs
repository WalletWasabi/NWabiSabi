using System;
using System.Linq;
using System.Threading;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.Native;
using Xunit;
using Xunit.Abstractions;

using NativeIssuer = WabiSabi.Native.CredentialIssuer;
using NativeClient = WabiSabi.Native.WabiSabiClient;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using CsClient     = WabiSabi.Crypto.WabiSabiClient;

namespace WabiSabiInterop.Tests;

[Collection("NativeLibrary")]
public class ReproTests
{
    private const long MaxAmount = 1_000_000L;
    private readonly ITestOutputHelper _out;
    public ReproTests(ITestOutputHelper o) => _out = o;

    // C# client -> native issuer, real RNG, many iterations, varied amounts.
    [Fact]
    public void Repro_CSharpClient_NativeIssuer_RealRng()
    {
        int fails = 0, ok = 0;
        var rng = SecureRandom.Instance;
        for (int i = 0; i < 200; i++)
        {
            var sk = new CredentialIssuerSecretKey(rng);
            var ip = sk.ComputeCredentialIssuerParameters();
            var client = new CsClient(ip, rng, MaxAmount);
            var issuer = new NativeIssuer(sk, rng, MaxAmount);
            try
            {
                var zd = client.CreateRequestForZeroAmount();
                var zr = issuer.HandleRequest(zd.CredentialsRequest);
                var zc = client.HandleResponse(zr, zd.CredentialsResponseValidation).ToArray();

                long total = (long)(new Random(i).NextDouble() * (MaxAmount - 1));
                long a0 = total / 2, a1 = total - a0;
                var amounts = new long[] { a0, a1 };
                var rd = client.CreateRequest(amounts, zc, CancellationToken.None);
                var rr = issuer.HandleRequest(rd.CredentialsRequest);
                var vc = client.HandleResponse(rr, rd.CredentialsResponseValidation).ToArray();

                // Reissuance round: present the value credentials we just got.
                var rd2 = client.CreateRequest(new long[] { a1, a0 }, vc, CancellationToken.None);
                var rr2 = issuer.HandleRequest(rd2.CredentialsRequest);
                client.HandleResponse(rr2, rd2.CredentialsResponseValidation).ToArray();
                ok++;
            }
            catch (Exception e)
            {
                fails++;
                if (fails <= 8) _out.WriteLine($"iter {i} FAIL: {e.Message}");
            }
        }
        _out.WriteLine($"C#client->nativeIssuer: ok={ok} fails={fails}");
        Assert.Equal(0, fails);
    }

    // native client -> C# issuer, real RNG, many iterations.
    [Fact]
    public void Repro_NativeClient_CSharpIssuer_RealRng()
    {
        int fails = 0, ok = 0;
        var rng = SecureRandom.Instance;
        int rangeWidth = (int)Math.Ceiling(Math.Log2(MaxAmount));
        for (int i = 0; i < 200; i++)
        {
            var sk = new CredentialIssuerSecretKey(rng);
            var ip = sk.ComputeCredentialIssuerParameters();
            var client = new NativeClient(ip, rng, MaxAmount);
            var issuer = new CsIssuer(sk, rng, MaxAmount);
            try
            {
                var zd = client.CreateRequestForZeroAmount();
                var zr = issuer.HandleRequest(zd.CredentialsRequest);
                var zc = client.HandleResponse(zr, zd.CredentialsResponseValidation).ToArray();

                long total = (long)(new Random(i).NextDouble() * (MaxAmount - 1));
                long a0 = total / 2, a1 = total - a0;
                var amounts = new long[] { a0, a1 };
                var rd = client.CreateRequest(amounts, zc, CancellationToken.None);
                var rr = issuer.HandleRequest(rd.CredentialsRequest);
                client.HandleResponse(rr, rd.CredentialsResponseValidation).ToArray();
                ok++;
            }
            catch (Exception e)
            {
                fails++;
                if (fails <= 8) _out.WriteLine($"iter {i} FAIL: {e.Message}");
            }
        }
        _out.WriteLine($"nativeClient->C#issuer: ok={ok} fails={fails}");
        Assert.Equal(0, fails);
    }
}

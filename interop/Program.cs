/*
 * WabiSabi Cross-Language Interoperability Test
 *
 * Verifies that the C (native) and C# implementations are fully interoperable:
 * a request created by one implementation is correctly processed by the other,
 * and vice versa.
 *
 *   Scenario A — native client, C# issuer:
 *     1. NativeClient creates zero request
 *     2. CsIssuer processes zero request → issues zero credentials
 *     3. NativeClient validates response, receives zero credentials
 *     4. NativeClient creates real request using those credentials
 *     5. CsIssuer processes real request → issues value credentials
 *     6. NativeClient validates response, receives value credentials
 *
 *   Scenario B — C# client, native issuer:
 *     1. CsClient creates zero request
 *     2. NativeIssuer processes zero request → issues zero credentials
 *     3. CsClient validates response, receives zero credentials
 *     4. CsClient creates real request using those credentials
 *     5. NativeIssuer processes real request → issues value credentials
 *     6. CsClient validates response, receives value credentials
 *
 * Prerequisites:
 *   Build the C shared library first:
 *     cmake -B c/build -S c -DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR
 *     cmake --build c/build
 */

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using WabiSabi;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.CredentialRequesting;
using WabiSabiInterop;
using CsIssuer     = WabiSabi.Crypto.CredentialIssuer;
using CsClient     = WabiSabi.Crypto.WabiSabiClient;
using NativeIssuer = WabiSabiInterop.CredentialIssuer;
using NativeClient = WabiSabiInterop.WabiSabiClient;

// -----------------------------------------------------------------------
// Main test runner
// -----------------------------------------------------------------------
class Program
{
    private const long MaxAmount       = 1_000_000L;
    private const int  CredentialCount = ProtocolConstants.CredentialNumber; // 2

    private static readonly long[] AmountsToRegister = new[] { 500_000L, 300_000L };

    private static int _pass = 0;
    private static int _fail = 0;

    static void Check(string label, bool ok)
    {
        if (ok) { Console.WriteLine($"  [PASS] {label}"); _pass++; }
        else    { Console.WriteLine($"  [FAIL] {label}"); _fail++; }
    }

    static void Main(string[] args)
    {
        Console.WriteLine("=== WabiSabi C ↔ C# Interoperability Tests ===\n");

        NativeWabi.Init();
        Console.WriteLine("Native runtime initialized.\n");

        var skRng = new Sha256ChainRandom(Encoding.ASCII.GetBytes("interop-test-sk-seed"));
        var sk    = new CredentialIssuerSecretKey(skRng);
        Console.WriteLine("Secret key generated (deterministic).\n");

        try
        {
            RunScenarioA(sk);
            RunScenarioB(sk);
        }
        finally
        {
            NativeWabi.Cleanup();
        }

        Console.WriteLine();
        Console.WriteLine($"Results: {_pass} passed, {_fail} failed.");
        if (_fail > 0) Environment.Exit(1);
        Console.WriteLine("\n=== All interop tests passed ===");
    }

    // -------------------------------------------------------------------
    // Scenario A: native client → C# issuer
    // -------------------------------------------------------------------
    static void RunScenarioA(CredentialIssuerSecretKey sk)
    {
        Console.WriteLine("--- Scenario A: native client  →  C# issuer ---\n");

        var iparams = sk.ComputeCredentialIssuerParameters();

        var csIssuer           = new CsIssuer(sk, Rng("A-cs-issuer"), MaxAmount);
        var nativeClient = new NativeClient(iparams, Rng("A-native-client"), MaxAmount);

        // ---- Round 1: Bootstrap (zero-value credentials) ----
        Console.WriteLine("  [Round 1] Bootstrap (zero-value credentials)");

        Credential[] zeroCreds;
        try
        {
            var zeroData = nativeClient.CreateRequestForZeroAmount();
            var zeroResp = csIssuer.HandleRequest(zeroData.CredentialsRequest);
            zeroCreds    = nativeClient.HandleResponse(zeroResp, zeroData.CredentialsResponseValidation).ToArray();

            Check("Round 1: issued 2 zero credentials", zeroCreds.Length == CredentialCount);
            for (int i = 0; i < zeroCreds.Length; i++)
                Check($"Round 1: credential[{i}].value == 0", zeroCreds[i].Value == 0);
        }
        catch (Exception ex)
        {
            Check("Round 1: bootstrap succeeded", false);
            Console.WriteLine($"    {ex.Message}");
            return;
        }

        Console.WriteLine();

        // ---- Round 2: Input registration (value credentials) ----
        Console.WriteLine("  [Round 2] Input registration (request value credentials)");

        try
        {
            var realData   = nativeClient.CreateRequest(AmountsToRegister, zeroCreds, CancellationToken.None);
            var realResp   = csIssuer.HandleRequest(realData.CredentialsRequest);
            var valueCreds = nativeClient.HandleResponse(realResp, realData.CredentialsResponseValidation).ToArray();

            Check("Round 2: issued 2 value credentials", valueCreds.Length == CredentialCount);
            long total = valueCreds.Sum(c => c.Value);
            Check("Round 2: total value == 800 000", total == 800_000L);
            for (int i = 0; i < valueCreds.Length; i++)
                Console.WriteLine($"    credential[{i}].value = {valueCreds[i].Value}");
        }
        catch (Exception ex)
        {
            Check("Round 2: input registration succeeded", false);
            Console.WriteLine($"    {ex.Message}");
        }

        Console.WriteLine();
    }

    // -------------------------------------------------------------------
    // Scenario B: C# client → native issuer
    // -------------------------------------------------------------------
    static void RunScenarioB(CredentialIssuerSecretKey sk)
    {
        Console.WriteLine("--- Scenario B: C# client  →  native issuer ---\n");

        var iparams = sk.ComputeCredentialIssuerParameters();

        var nativeIssuer = new NativeIssuer(sk, Rng("B-native-issuer"), MaxAmount);
        var csClient           = new CsClient(iparams, Rng("B-cs-client"), MaxAmount);

        // ---- Round 1: Bootstrap (zero-value credentials) ----
        Console.WriteLine("  [Round 1] Bootstrap (zero-value credentials)");

        Credential[] zeroCreds;
        try
        {
            var zeroData = csClient.CreateRequestForZeroAmount();
            var zeroResp = nativeIssuer.HandleRequest(zeroData.CredentialsRequest);
            zeroCreds    = csClient.HandleResponse(zeroResp, zeroData.CredentialsResponseValidation).ToArray();

            Check("Round 1: issued 2 zero credentials", zeroCreds.Length == CredentialCount);
            for (int i = 0; i < zeroCreds.Length; i++)
                Check($"Round 1: credential[{i}].value == 0", zeroCreds[i].Value == 0);
        }
        catch (Exception ex)
        {
            Check("Round 1: bootstrap succeeded", false);
            Console.WriteLine($"    {ex.Message}");
            return;
        }

        Console.WriteLine();

        // ---- Round 2: Input registration (value credentials) ----
        Console.WriteLine("  [Round 2] Input registration (request value credentials)");

        try
        {
            var realData   = csClient.CreateRequest(AmountsToRegister, zeroCreds, CancellationToken.None);
            var realResp   = nativeIssuer.HandleRequest(realData.CredentialsRequest);
            var valueCreds = csClient.HandleResponse(realResp, realData.CredentialsResponseValidation).ToArray();

            Check("Round 2: issued 2 value credentials", valueCreds.Length == CredentialCount);
            long total = valueCreds.Sum(c => c.Value);
            Check("Round 2: total value == 800 000", total == 800_000L);
            for (int i = 0; i < valueCreds.Length; i++)
                Console.WriteLine($"    credential[{i}].value = {valueCreds[i].Value}");
        }
        catch (Exception ex)
        {
            Check("Round 2: input registration succeeded", false);
            Console.WriteLine($"    {ex.Message}");
        }

        Console.WriteLine();
    }

    /// <summary>Returns a deterministic <see cref="Sha256ChainRandom"/> seeded from a label string.</summary>
    private static Sha256ChainRandom Rng(string label)
        => new Sha256ChainRandom(SHA256.HashData(Encoding.ASCII.GetBytes("interop-test-" + label)));
}

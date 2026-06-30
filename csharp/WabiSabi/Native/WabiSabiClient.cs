using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using NBitcoin.Secp256k1;
using WabiSabi;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Randomness;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.CredentialRequesting;

namespace WabiSabi.Native;

/// <summary>
/// FFI-backed drop-in replacement for <see cref="WabiSabi.Crypto.WabiSabiClient"/> that
/// delegates all cryptographic work to the C shared library via <see cref="NativeWabi"/>.
///
/// The interface matches <see cref="WabiSabi.Crypto.WabiSabiClient"/> exactly:
///   • Not IDisposable — no native handles are held.
///   • <see cref="HandleResponse"/> accepts a <see cref="CredentialsResponseValidation"/>
///     returned by the corresponding <see cref="CreateRequestForZeroAmount"/> /
///     <see cref="CreateRequest"/> call.
/// </summary>
public class WabiSabiClient
{
    private readonly byte[] _iparamsBytes;
    private readonly long _maxAmount;
    private readonly WasabiRandom _rng;

    // Maps each CredentialsResponseValidation instance (by reference) to the
    // serialized C validation state produced by the corresponding create call.
    // ConditionalWeakTable uses reference equality and weak keys, so entries are
    // collected automatically when the validation object is no longer reachable.
    private readonly ConditionalWeakTable<CredentialsResponseValidation, byte[]> _validationStates = new();

    public WabiSabiClient(
        CredentialIssuerParameters credentialIssuerParameters,
        WasabiRandom randomNumberGenerator,
        long rangeProofUpperBound)
    {
        RangeProofWidth = (int)Math.Ceiling(Math.Log2(rangeProofUpperBound));
        _rng = randomNumberGenerator;
        _maxAmount = rangeProofUpperBound;
        _iparamsBytes = SerializeIssuerParameters(credentialIssuerParameters);
    }

    public int RangeProofWidth { get; }
    public int NumberOfCredentials => NativeWabi.CredentialCount;

    /// <summary>Creates a request for <c>k</c> zero-value credentials (bootstrap round).</summary>
    public ZeroCredentialsRequestData CreateRequestForZeroAmount()
    {
        var rand   = new byte[NativeWabi.RandSize];
        _rng.GetBytes(rand);

        var reqOut = new byte[NativeWabi.MaxRequestSize];
        var valOut = new byte[NativeWabi.ValidationSize];
        int reqLen;
        int rc = NativeWabi.ClientCreateZeroRequest(rand, reqOut, reqOut.Length, out reqLen, valOut);
        if (rc != 0)
            throw new WabiSabiCryptoException(
                WabiSabiCryptoErrorCode.ClientReceivedInvalidProofs,
                $"C client zero request failed with error code {rc}.");

        var zeroReq = WireFormat.DeserializeZeroRequest(reqOut[..reqLen]);

        // Build placeholder validation data — the C library's real state is in valOut.
        var placeholderRequested = zeroReq.Requested
            .Select(r => new IssuanceValidationData(0, new Scalar(0UL), r.Ma))
            .ToArray();

        var validation = new CredentialsResponseValidation(
            BuildTranscript(isNullRequest: true),
            Enumerable.Empty<Credential>(),
            placeholderRequested);

        // Associate the C validation state with this specific validation instance.
        _validationStates.Add(validation, valOut);

        return new ZeroCredentialsRequestData(zeroReq, validation);
    }

    /// <summary>Creates a request to present <paramref name="credentialsToPresent"/> and obtain zero-valued outputs.</summary>
    public RealCredentialsRequestData CreateRequest(
        IEnumerable<Credential> credentialsToPresent,
        CancellationToken cancellationToken)
        => CreateRequest(Array.Empty<long>(), credentialsToPresent, cancellationToken);

    /// <summary>Creates a request to present credentials and obtain credentials of the given <paramref name="amountsToRequest"/>.</summary>
    public RealCredentialsRequestData CreateRequest(
        IEnumerable<long> amountsToRequest,
        IEnumerable<Credential> credentialsToPresent,
        CancellationToken cancellationToken)
    {
        var amounts    = amountsToRequest.ToList();
        while (amounts.Count < NumberOfCredentials) amounts.Add(0L);

        var credsList  = credentialsToPresent.ToArray();
        var credsBytes = WireFormat.PackCredentials(credsList);

        var rand   = new byte[NativeWabi.RandSize];
        _rng.GetBytes(rand);

        var reqOut = new byte[NativeWabi.MaxRequestSize];
        var valOut = new byte[NativeWabi.ValidationSize];
        int reqLen;
        int rc = NativeWabi.ClientCreateRealRequest(
            _iparamsBytes,
            _maxAmount,
            amounts.ToArray(), amounts.Count,
            credsBytes, credsList.Length,
            rand,
            reqOut, reqOut.Length, out reqLen,
            valOut);

        if (rc != 0)
            throw new WabiSabiCryptoException(
                WabiSabiCryptoErrorCode.ClientReceivedInvalidProofs,
                $"C client real request failed with error code {rc}.");

        var realReq = WireFormat.DeserializeRealRequest(reqOut[..reqLen], RangeProofWidth);

        // Build placeholder validation data — the C library's real state is in valOut.
        var placeholderRequested = realReq.Requested
            .Zip(amounts, (r, v) => new IssuanceValidationData(v, new Scalar(0UL), r.Ma))
            .ToArray();

        var validation = new CredentialsResponseValidation(
            BuildTranscript(isNullRequest: false),
            credsList,
            placeholderRequested);

        _validationStates.Add(validation, valOut);

        return new RealCredentialsRequestData(realReq, validation);
    }

    /// <summary>
    /// Validates <paramref name="registrationResponse"/> using the C library and returns the issued credentials.
    /// </summary>
    /// <param name="registrationResponse">The response received from the coordinator.</param>
    /// <param name="registrationValidationData">
    ///   The validation data returned by the corresponding
    ///   <see cref="CreateRequestForZeroAmount"/> or <see cref="CreateRequest"/> call.
    /// </param>
    public IEnumerable<Credential> HandleResponse(
        CredentialsResponse registrationResponse,
        CredentialsResponseValidation registrationValidationData)
    {
        if (!_validationStates.TryGetValue(registrationValidationData, out var valBytes))
            throw new WabiSabiCryptoException(
                WabiSabiCryptoErrorCode.ClientReceivedInvalidProofs,
                "No pending request found for the provided validation data.");

        var respBytes = WireFormat.SerializeResponse(registrationResponse);
        var credsOut  = new byte[NativeWabi.CredentialCount * NativeWabi.CredentialSize];
        int nCreds;
        int rc = NativeWabi.ClientHandleResponse(
            _iparamsBytes,
            respBytes, respBytes.Length,
            valBytes,
            credsOut, credsOut.Length, out nCreds);

        if (rc != 0)
            throw new WabiSabiCryptoException(
                WabiSabiCryptoErrorCode.ClientReceivedInvalidProofs,
                $"C client response validation failed with error code {rc}.");

        return WireFormat.UnpackCredentials(credsOut, nCreds);
    }

    private static byte[] SerializeIssuerParameters(CredentialIssuerParameters iparams)
    {
        var buf = new byte[NativeWabi.IParamsSize];
        iparams.Cw.ToBytes().CopyTo(buf,             0);
        iparams.I .ToBytes().CopyTo(buf, NativeWabi.GeSize);
        return buf;
    }

    private static Transcript BuildTranscript(bool isNullRequest)
    {
        var label = $"UnifiedRegistration/{NativeWabi.CredentialCount}/{isNullRequest}";
        return new Transcript(Encoding.UTF8.GetBytes(label));
    }
}

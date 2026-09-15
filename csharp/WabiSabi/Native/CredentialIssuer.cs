using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Groups;
using WabiSabi.Crypto.Randomness;
using WabiSabi.CredentialRequesting;

namespace WabiSabi.Native;

/// <summary>
/// FFI-backed drop-in replacement for <see cref="WabiSabi.Crypto.CredentialIssuer"/> that
/// delegates all cryptographic work to the C shared library via <see cref="NativeWabi"/>.
///
/// The interface matches <see cref="WabiSabi.Crypto.CredentialIssuer"/> exactly:
///   • Not IDisposable — all mutable state is stored as a managed byte array.
///   • <see cref="Balance"/> reflects the current issued amount.
///   • Thread-safe: concurrent <see cref="HandleRequest"/> calls are serialized.
/// </summary>
public class CredentialIssuer
{
    private readonly byte[] _skBytes;
    private readonly WasabiRandom _rng;
    private readonly byte[] _mstateOutBuf; // pre-allocated output buffer (IssuerMStateMaxSize)
    private byte[] _currentMstate;         // compact serialized mutable state (just the balance)
    private readonly object _lock = new();

    // The native library performs only cryptographic verification and balance
    // bookkeeping; it does NOT track serial numbers. Double-spend prevention
    // lives here, mirroring the managed WabiSabi.Crypto.CredentialIssuer.
    private readonly HashSet<GroupElement> _serialNumbers = new();

    public CredentialIssuer(
        CredentialIssuerSecretKey credentialIssuerSecretKey,
        WasabiRandom randomNumberGenerator,
        long maxAmount)
    {
        MaxAmount                 = maxAmount;
        RangeProofWidth           = (int)Math.Ceiling(Math.Log2(maxAmount));
        CredentialIssuerSecretKey = credentialIssuerSecretKey;
        _rng                      = randomNumberGenerator;
        _skBytes                  = SerializeSecretKey(credentialIssuerSecretKey);
        _mstateOutBuf             = new byte[NativeWabi.IssuerMStateMaxSize];
        _currentMstate            = Array.Empty<byte>(); // initial state: balance=0, no serials
    }

    public long MaxAmount { get; }
    public CredentialIssuerSecretKey CredentialIssuerSecretKey { get; }
    public int RangeProofWidth { get; }
    public int NumberOfCredentials => NativeWabi.CredentialCount;

    /// <summary>Gets the current issued balance (sum of delta values accepted so far).</summary>
    public long Balance
    {
        get
        {
            lock (_lock)
            {
                return ReadBalance(_currentMstate);
            }
        }
    }

    public Task<CredentialsResponse> HandleRequestAsync(
        ICredentialsRequest registrationRequest,
        CancellationToken cancel)
        => Task.Run(() => HandleRequest(registrationRequest), cancel);

    public CredentialsResponse HandleRequest(ICredentialsRequest registrationRequest)
    {
        bool isZero = registrationRequest is ZeroCredentialsRequest;
        byte[] reqBytes = isZero
            ? WireFormat.SerializeZeroRequest((ZeroCredentialsRequest)registrationRequest)
            : WireFormat.SerializeRealRequest((RealCredentialsRequest)registrationRequest);

        var rand    = new byte[NativeWabi.RandSize];
        _rng.GetBytes(rand);

        var respOut = new byte[NativeWabi.MaxRequestSize];

        // Check all the serial numbers are unique within the request. Even
        // presenting a previously-unused credential more than once in the same
        // request is a double spend. (No-op for a zero request: it presents none.)
        if (registrationRequest.AreThereDuplicatedSerialNumbers())
            throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.SerialNumberDuplicated);

        var presentedSerialNumbers = registrationRequest.SerialNumbers().ToArray();

        lock (_lock)
        {
            // Reject serial numbers seen in a previous (valid) request. Note the
            // serials are not cryptographically verified yet, but a request with
            // an invalid proof and a reused serial number is rejected regardless.
            if (presentedSerialNumbers.Any(_serialNumbers.Contains))
                throw new WabiSabiCryptoException(WabiSabiCryptoErrorCode.SerialNumberAlreadyUsed, "Serial number reused");

            // Tentatively record them; roll back below if the native call fails.
            foreach (var s in presentedSerialNumbers)
                _serialNumbers.Add(s);

            int respLen, mstateOutLen;
            int rc = isZero
                ? NativeWabi.IssuerHandleZero(
                    _skBytes, MaxAmount,
                    _currentMstate, _currentMstate.Length,
                    reqBytes, reqBytes.Length,
                    rand,
                    respOut, respOut.Length, out respLen,
                    _mstateOutBuf, _mstateOutBuf.Length, out mstateOutLen)
                : NativeWabi.IssuerHandleReal(
                    _skBytes, MaxAmount,
                    _currentMstate, _currentMstate.Length,
                    reqBytes, reqBytes.Length,
                    rand,
                    respOut, respOut.Length, out respLen,
                    _mstateOutBuf, _mstateOutBuf.Length, out mstateOutLen);

            if (rc != 0)
            {
                // The request was rejected (e.g. invalid proofs); its serial
                // numbers were unused, so release them to keep the nullifier set
                // from being clogged with serials from invalid requests.
                foreach (var s in presentedSerialNumbers)
                    _serialNumbers.Remove(s);
                throw new WabiSabiCryptoException(MapError(rc), $"C issuer returned error code {rc}.");
            }

            // Store compact copy of the updated mutable state.
            _currentMstate = _mstateOutBuf[..mstateOutLen];

            return WireFormat.DeserializeResponse(respOut[..respLen]);
        }
    }

    /// <summary>
    /// Maps a C FFI error code (see WABISABI_ERR_* in wabisabi_ffi.h) to the matching
    /// <see cref="WabiSabiCryptoErrorCode"/> the managed <see cref="WabiSabi.Crypto.CredentialIssuer"/>
    /// would have thrown, so callers that branch on the specific error keep working.
    /// </summary>
    private static WabiSabiCryptoErrorCode MapError(int rc) => rc switch
    {
        4  => WabiSabiCryptoErrorCode.CoordinatorReceivedInvalidProofs, // INVALID_PROOF
        5  => WabiSabiCryptoErrorCode.InvalidNumberOfRequestedCredentials, // INVALID_CRED_COUNT
        6  => WabiSabiCryptoErrorCode.InvalidBitCommitment,            // INVALID_BIT_COMMITMENT
        7  => WabiSabiCryptoErrorCode.SerialNumberDuplicated,          // SERIAL_DUPLICATED
        8  => WabiSabiCryptoErrorCode.SerialNumberAlreadyUsed,         // SERIAL_REUSED
        9  => WabiSabiCryptoErrorCode.NegativeBalance,                 // NEGATIVE_BALANCE
        _  => WabiSabiCryptoErrorCode.CoordinatorReceivedInvalidProofs,
    };

    /// <summary>Reads the balance from the compact serialized mutable state.</summary>
    private static long ReadBalance(byte[] mstate)
    {
        if (mstate.Length < 8) return 0L;
        long b = 0;
        for (int i = 0; i < 8; i++)
            b |= (long)mstate[i] << (8 * i);
        return b;
    }

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
}

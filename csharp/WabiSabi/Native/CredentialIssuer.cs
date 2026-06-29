using System;
using System.Threading;
using System.Threading.Tasks;
using WabiSabi.Crypto;
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
    private byte[] _currentMstate;         // compact serialized mutable state
    private readonly object _lock = new();

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

        var respOut = new byte[16 * 1024];

        lock (_lock)
        {
            int respLen, mstateOutLen;
            int rc = isZero
                ? NativeWabi.IssuerHandleZero(
                    _skBytes, MaxAmount,
                    _currentMstate, _currentMstate.Length,
                    reqBytes, reqBytes.Length,
                    rand,
                    respOut, out respLen,
                    _mstateOutBuf, out mstateOutLen)
                : NativeWabi.IssuerHandleReal(
                    _skBytes, MaxAmount,
                    _currentMstate, _currentMstate.Length,
                    reqBytes, reqBytes.Length,
                    rand,
                    respOut, out respLen,
                    _mstateOutBuf, out mstateOutLen);

            if (rc != 0)
                throw new WabiSabiCryptoException(
                    WabiSabiCryptoErrorCode.CoordinatorReceivedInvalidProofs,
                    $"C issuer returned error code {rc}.");

            // Store compact copy of the updated mutable state.
            _currentMstate = _mstateOutBuf[..mstateOutLen];

            return WireFormat.DeserializeResponse(respOut[..respLen]);
        }
    }

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

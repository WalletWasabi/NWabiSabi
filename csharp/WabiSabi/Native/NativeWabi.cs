using System;
using System.Runtime.InteropServices;

namespace WabiSabi.Native;

/// <summary>
/// P/Invoke bindings for the WabiSabi C shared library (libwabisabi.so / wabisabi.dll).
///
/// The C library is stateless: all state (mutable issuer state, client validation state)
/// is serialized to byte arrays and passed explicitly by the caller.
///
/// Build the shared library first:
///   cd c && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
///     -DFETCHCONTENT_SOURCE_DIR_SECP256K1=$SECP256K1_SOURCE_DIR && cmake --build build
/// Then either copy build/libwabisabi.so next to this executable, or set LD_LIBRARY_PATH.
/// </summary>
internal static class NativeWabi
{
    private const string Lib = "wabisabi";

    /// <summary>
    /// Static constructor ensures the native library is initialized before any P/Invoke calls.
    /// </summary>
    static NativeWabi()
    {
        Init();
    }

    // Wire-format sizes (mirror of C WABISABI_*_SIZE constants)
    public const int ScalarSize          = 32;
    public const int GeSize              = 33;
    public const int ValueSize           =  8;
    public const int RandSize            = ScalarSize;
    public const int SkSize              = 5 * ScalarSize;
    public const int IParamsSize         = 2 * GeSize;
    public const int MacSize             = ScalarSize + GeSize;
    public const int PresentationSize    = 5 * GeSize;
    public const int CredentialSize      = ValueSize + ScalarSize + MacSize;
    public const int CredentialCount     = 2;

    /// <summary>
    /// Fixed size of the serialized client validation state (353 bytes).
    /// See wabisabi_ffi.h: strobe(203) + n_req(4) + 2*(value(8)+rand(32)+ma(33)).
    /// </summary>
    public const int ValidationSize      = 353;

    /// <summary>Maximum number of serial numbers tracked by the issuer.</summary>
    public const int IssuerMaxSerials    = 65536;

    /// <summary>Maximum size of the serialized mutable issuer state in bytes.</summary>
    public const int IssuerMStateMaxSize = 8 + 4 + IssuerMaxSerials * GeSize;

    // ---- Initialization ----

    [DllImport(Lib, EntryPoint = "wabisabi_init", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Init();

    [DllImport(Lib, EntryPoint = "wabisabi_cleanup", CallingConvention = CallingConvention.Cdecl)]
    public static extern void Cleanup();

    /// <param name="skBytes">160 bytes: w(32) wp(32) x0(32) x1(32) ya(32)</param>
    /// <param name="outBytes">66-byte output buffer: Cw(33) I(33)</param>
    [DllImport(Lib, EntryPoint = "wabisabi_iparams_from_sk", CallingConvention = CallingConvention.Cdecl)]
    public static extern int IparamsFromSk(
        [In] byte[] skBytes,
        [Out] byte[] outBytes);

    // ---- Issuer (stateless) ----

    /// <summary>
    /// Process a zero (bootstrap) credential request.
    /// </summary>
    /// <param name="skBytes">WABISABI_SK_SIZE secret key bytes.</param>
    /// <param name="maxAmount">Upper bound on credential values.</param>
    /// <param name="mstateIn">Serialized mutable state from previous call, or empty for initial state.</param>
    /// <param name="mstateInLen">Length of mstateIn (0 for initial state).</param>
    /// <param name="reqBytes">Wire-encoded ZeroRequest.</param>
    /// <param name="reqLen">Length of reqBytes.</param>
    /// <param name="randBytes">WABISABI_RAND_SIZE bytes of randomness.</param>
    /// <param name="respOut">Output buffer (16 KiB is sufficient).</param>
    /// <param name="respLenOut">Set to actual response length on success.</param>
    /// <param name="mstateOut">Output buffer for updated mutable state (IssuerMStateMaxSize bytes).</param>
    /// <param name="mstateOutLen">Set to actual mutable state length on success.</param>
    [DllImport(Lib, EntryPoint = "wabisabi_issuer_handle_zero", CallingConvention = CallingConvention.Cdecl)]
    public static extern int IssuerHandleZero(
        [In] byte[] skBytes,
        long maxAmount,
        [In] byte[] mstateIn, int mstateInLen,
        [In] byte[] reqBytes, int reqLen,
        [In] byte[] randBytes,
        [Out] byte[] respOut, out int respLenOut,
        [Out] byte[] mstateOut, out int mstateOutLen);

    /// <summary>Process a real credential request. Same parameters as IssuerHandleZero.</summary>
    [DllImport(Lib, EntryPoint = "wabisabi_issuer_handle_real", CallingConvention = CallingConvention.Cdecl)]
    public static extern int IssuerHandleReal(
        [In] byte[] skBytes,
        long maxAmount,
        [In] byte[] mstateIn, int mstateInLen,
        [In] byte[] reqBytes, int reqLen,
        [In] byte[] randBytes,
        [Out] byte[] respOut, out int respLenOut,
        [Out] byte[] mstateOut, out int mstateOutLen);

    // ---- Client (stateless) ----

    /// <summary>
    /// Create a zero (bootstrap) credential request.
    /// </summary>
    /// <param name="randBytes">WABISABI_RAND_SIZE bytes of randomness.</param>
    /// <param name="reqOut">Output buffer (16 KiB is sufficient).</param>
    /// <param name="reqLenOut">Set to actual request length on success.</param>
    /// <param name="valOut">Output buffer of exactly ValidationSize bytes; pass to HandleResponse.</param>
    [DllImport(Lib, EntryPoint = "wabisabi_client_create_zero_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ClientCreateZeroRequest(
        [In] byte[] randBytes,
        [Out] byte[] reqOut, out int reqLenOut,
        [Out] byte[] valOut);

    /// <summary>
    /// Create a real credential request.
    /// </summary>
    /// <param name="iparamsBytes">WABISABI_IPARAMS_SIZE bytes of issuer public parameters.</param>
    /// <param name="maxAmount">Upper bound used to compute range-proof width.</param>
    /// <param name="amounts">Array of nAmounts int64 values to request.</param>
    /// <param name="nAmounts">Number of amounts.</param>
    /// <param name="credsBytes">Serialized credentials (nCreds × CredentialSize bytes).</param>
    /// <param name="nCreds">Number of credentials being presented.</param>
    /// <param name="randBytes">WABISABI_RAND_SIZE bytes of randomness.</param>
    /// <param name="reqOut">Output buffer (16 KiB is sufficient).</param>
    /// <param name="reqLenOut">Set to actual request length on success.</param>
    /// <param name="valOut">Output buffer of exactly ValidationSize bytes; pass to HandleResponse.</param>
    [DllImport(Lib, EntryPoint = "wabisabi_client_create_real_request", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ClientCreateRealRequest(
        [In] byte[] iparamsBytes,
        long maxAmount,
        [In] long[] amounts, int nAmounts,
        [In] byte[] credsBytes, int nCreds,
        [In] byte[] randBytes,
        [Out] byte[] reqOut, out int reqLenOut,
        [Out] byte[] valOut);

    /// <summary>
    /// Process an issuer response and extract credentials.
    /// </summary>
    /// <param name="iparamsBytes">WABISABI_IPARAMS_SIZE bytes (for proof verification).</param>
    /// <param name="respBytes">Wire-encoded Response from the issuer.</param>
    /// <param name="respLen">Length of respBytes.</param>
    /// <param name="valBytes">ValidationSize bytes from the corresponding CreateZero/RealRequest call.</param>
    /// <param name="credsOut">Output buffer (CredentialCount × CredentialSize bytes).</param>
    /// <param name="nCredsOut">Set to number of credentials on success.</param>
    [DllImport(Lib, EntryPoint = "wabisabi_client_handle_response", CallingConvention = CallingConvention.Cdecl)]
    public static extern int ClientHandleResponse(
        [In] byte[] iparamsBytes,
        [In] byte[] respBytes, int respLen,
        [In] byte[] valBytes,
        [Out] byte[] credsOut, out int nCredsOut);
}

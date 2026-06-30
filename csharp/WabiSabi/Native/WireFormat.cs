using System;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Secp256k1;
using WabiSabi;
using WabiSabi.Crypto;
using WabiSabi.Crypto.Groups;
using WabiSabi.Crypto.ZeroKnowledge;
using WabiSabi.CredentialRequesting;

namespace WabiSabi.Native;

/// <summary>
/// Serializes and deserializes WabiSabi protocol messages to/from the binary wire format
/// used by the C FFI layer (see c/include/wabisabi_ffi.h for full specification).
///
/// Wire format summary:
///   GroupElement : WABISABI_GE_SIZE bytes    (compressed secp256k1; 0x00 = infinity)
///   Scalar       : WABISABI_SCALAR_SIZE bytes (big-endian)
///   MAC          : [t:SCALAR_SIZE][V:GE_SIZE] = MAC_SIZE bytes
///   Proof        : [n_nonces:1][n_responses:1][nonces:n*GE_SIZE][responses:n*SCALAR_SIZE]
///   IssuanceReq  : [Ma:GE_SIZE][bits:w*GE_SIZE]  (w=0 for zero requests)
///   Presentation : [Ca][Cx0][Cx1][CV][S]          = PRESENTATION_SIZE bytes
///   Credential   : [value:VALUE_SIZE LE][randomness:SCALAR_SIZE][mac:MAC_SIZE] = CREDENTIAL_SIZE bytes
///   ZeroRequest  : [Ma_0][Ma_1][proof_0][proof_1]
///   RealRequest  : [delta:VALUE_SIZE LE][pres_0:PRESENTATION_SIZE][pres_1:PRESENTATION_SIZE][n_requested:1][req_0]...[n_proofs:1][proofs...]
///                  (n_requested is 0 for a presentation-only request, e.g. output registration)
///   Response     : [n_issued:1][mac_0]...[mac_{n-1}][proof_0]...[proof_{n-1}]
/// </summary>
internal static class WireFormat
{
    private static readonly int CredentialCount = NativeWabi.CredentialCount;

    // ---- Primitive serialization ----

    private static byte[] WriteGe(GroupElement ge) => ge.ToBytes();

    private static GroupElement ReadGe(byte[] buf, ref int off)
    {
        var bytes = buf[off..(off + NativeWabi.GeSize)];
        off += NativeWabi.GeSize;
        return GroupElement.FromBytes(bytes);
    }

    private static byte[] WriteScalar(Scalar s) => s.ToBytes();

    private static Scalar ReadScalar(byte[] buf, ref int off)
    {
        var bytes = buf[off..(off + NativeWabi.ScalarSize)];
        off += NativeWabi.ScalarSize;
        return new Scalar(bytes, out _);
    }

    // ---- Proof serialization ----

    private static byte[] WriteProof(Proof p)
    {
        var nonces    = p.PublicNonces.ToArray();
        var responses = p.Responses.ToArray();

        var bytes = new List<byte>();
        bytes.Add((byte)nonces.Length);
        bytes.Add((byte)responses.Length);
        foreach (var n in nonces)    bytes.AddRange(WriteGe(n));
        foreach (var r in responses) bytes.AddRange(WriteScalar(r));
        return bytes.ToArray();
    }

    private static Proof ReadProof(byte[] buf, ref int off)
    {
        int nNonces    = buf[off++];
        int nResponses = buf[off++];

        var nonces = new GroupElement[nNonces];
        for (int i = 0; i < nNonces; i++)
            nonces[i] = ReadGe(buf, ref off);

        var responses = new Scalar[nResponses];
        for (int i = 0; i < nResponses; i++)
            responses[i] = ReadScalar(buf, ref off);

        return new Proof(new GroupElementVector(nonces), new ScalarVector(responses));
    }

    // ---- MAC serialization ----

    private static byte[] WriteMac(MAC mac)
    {
        var bytes = new List<byte>(NativeWabi.MacSize);
        bytes.AddRange(WriteScalar(mac.T));
        bytes.AddRange(WriteGe(mac.V));
        return bytes.ToArray();
    }

    private static MAC ReadMac(byte[] buf, ref int off)
    {
        var t = ReadScalar(buf, ref off);
        var v = ReadGe(buf, ref off);
        return new MAC(t, v);
    }

    // ---- Zero request ----

    /// <summary>
    /// Serializes a <see cref="ZeroCredentialsRequest"/> to wire bytes.
    /// Format: [Ma_0][Ma_1][proof_0][proof_1]
    /// </summary>
    public static byte[] SerializeZeroRequest(ZeroCredentialsRequest req)
    {
        var bytes = new List<byte>();
        foreach (var r in req.Requested)
            bytes.AddRange(WriteGe(r.Ma));
        foreach (var p in req.Proofs)
            bytes.AddRange(WriteProof(p));
        return bytes.ToArray();
    }

    /// <summary>
    /// Deserializes a <see cref="ZeroCredentialsRequest"/> from wire bytes (produced by the C client).
    /// </summary>
    public static ZeroCredentialsRequest DeserializeZeroRequest(byte[] bytes)
    {
        int off = 0;
        var requested = new IssuanceRequest[CredentialCount];
        for (int i = 0; i < CredentialCount; i++)
            requested[i] = new IssuanceRequest(ReadGe(bytes, ref off), Enumerable.Empty<GroupElement>());

        var proofs = new Proof[CredentialCount];
        for (int i = 0; i < CredentialCount; i++)
            proofs[i] = ReadProof(bytes, ref off);

        return new ZeroCredentialsRequest(requested, proofs);
    }

    // ---- Real request ----

    /// <summary>
    /// Serializes a <see cref="RealCredentialsRequest"/> to wire bytes.
    /// Format: [delta:VALUE_SIZE LE][pres_0:PRESENTATION_SIZE][pres_1:PRESENTATION_SIZE][req_0][req_1][n_proofs:1][proofs...]
    /// </summary>
    public static byte[] SerializeRealRequest(RealCredentialsRequest req)
    {
        var bytes = new List<byte>();

        long delta = req.Delta;
        for (int i = 0; i < NativeWabi.ValueSize; i++)
            bytes.Add((byte)(delta >> (8 * i)));

        foreach (var p in req.Presented)
        {
            bytes.AddRange(WriteGe(p.Ca));
            bytes.AddRange(WriteGe(p.Cx0));
            bytes.AddRange(WriteGe(p.Cx1));
            bytes.AddRange(WriteGe(p.CV));
            bytes.AddRange(WriteGe(p.S));
        }

        // A presentation-only request (output registration) has no requested
        // credentials; the count distinguishes it from a normal request.
        var requestedList = req.Requested.ToArray();
        bytes.Add((byte)requestedList.Length);
        foreach (var r in requestedList)
        {
            bytes.AddRange(WriteGe(r.Ma));
            foreach (var bc in r.BitCommitments)
                bytes.AddRange(WriteGe(bc));
        }

        var proofList = req.Proofs.ToArray();
        bytes.Add((byte)proofList.Length);
        foreach (var p in proofList)
            bytes.AddRange(WriteProof(p));

        return bytes.ToArray();
    }

    /// <summary>
    /// Deserializes a <see cref="RealCredentialsRequest"/> from wire bytes (produced by the C client).
    /// </summary>
    public static RealCredentialsRequest DeserializeRealRequest(byte[] bytes, int rangeWidth)
    {
        int off = 0;

        long delta = 0;
        for (int i = 0; i < NativeWabi.ValueSize; i++)
            delta |= ((long)bytes[off + i]) << (8 * i);
        off += NativeWabi.ValueSize;

        var presented = new CredentialPresentation[CredentialCount];
        for (int i = 0; i < CredentialCount; i++)
            presented[i] = new CredentialPresentation(
                ReadGe(bytes, ref off), ReadGe(bytes, ref off),
                ReadGe(bytes, ref off), ReadGe(bytes, ref off),
                ReadGe(bytes, ref off));

        int nRequested = bytes[off++];
        var requested = new IssuanceRequest[nRequested];
        for (int i = 0; i < nRequested; i++)
        {
            var ma   = ReadGe(bytes, ref off);
            var bits = new GroupElement[rangeWidth];
            for (int b = 0; b < rangeWidth; b++) bits[b] = ReadGe(bytes, ref off);
            requested[i] = new IssuanceRequest(ma, bits);
        }

        int nProofs = bytes[off++];
        var proofs = new Proof[nProofs];
        for (int i = 0; i < nProofs; i++)
            proofs[i] = ReadProof(bytes, ref off);

        return new RealCredentialsRequest(delta, presented, requested, proofs);
    }

    // ---- Response ----

    /// <summary>
    /// Serializes a <see cref="CredentialsResponse"/> to wire bytes (for passing to the C client).
    /// Format: [mac_0:MAC_SIZE][mac_1:MAC_SIZE][proof_0][proof_1]
    /// </summary>
    public static byte[] SerializeResponse(CredentialsResponse resp)
    {
        var bytes = new List<byte>();
        var macs = resp.IssuedCredentials.ToArray();
        // n_issued: 0 for a presentation-only request's response.
        bytes.Add((byte)macs.Length);
        foreach (var mac in macs)
            bytes.AddRange(WriteMac(mac));
        foreach (var proof in resp.Proofs)
            bytes.AddRange(WriteProof(proof));
        return bytes.ToArray();
    }

    /// <summary>
    /// Deserializes a <see cref="CredentialsResponse"/> from wire bytes (produced by the C issuer).
    /// </summary>
    public static CredentialsResponse DeserializeResponse(byte[] bytes)
    {
        int off = 0;
        int nIssued = bytes[off++];
        var macs   = new MAC[nIssued];
        var proofs = new Proof[nIssued];

        for (int i = 0; i < nIssued; i++)
            macs[i] = ReadMac(bytes, ref off);
        for (int i = 0; i < nIssued; i++)
            proofs[i] = ReadProof(bytes, ref off);

        return new CredentialsResponse(macs, proofs);
    }

    // ---- Credential ----

    /// <summary>
    /// Serializes a <see cref="Credential"/> to CREDENTIAL_SIZE bytes.
    /// </summary>
    public static byte[] SerializeCredential(Credential cred)
    {
        var bytes = new List<byte>(NativeWabi.CredentialSize);
        long v = cred.Value;
        for (int i = 0; i < NativeWabi.ValueSize; i++)
            bytes.Add((byte)(v >> (8 * i)));
        bytes.AddRange(WriteScalar(cred.Randomness));
        bytes.AddRange(WriteMac(cred.Mac));
        return bytes.ToArray();
    }

    /// <summary>
    /// Deserializes a <see cref="Credential"/> from CREDENTIAL_SIZE bytes.
    /// </summary>
    public static Credential DeserializeCredential(byte[] buf, int offset = 0)
    {
        int off = offset;
        long value = 0;
        for (int i = 0; i < NativeWabi.ValueSize; i++)
            value |= ((long)buf[off + i]) << (8 * i);
        off += NativeWabi.ValueSize;

        var randomness = ReadScalar(buf, ref off);
        var mac        = ReadMac(buf, ref off);
        return new Credential(value, randomness, mac);
    }

    /// <summary>Packs serialized credentials into a single byte array.</summary>
    public static byte[] PackCredentials(IEnumerable<Credential> creds)
    {
        var buf = new List<byte>();
        foreach (var c in creds) buf.AddRange(SerializeCredential(c));
        return buf.ToArray();
    }

    /// <summary>Unpacks <paramref name="n"/> credentials from a packed byte array.</summary>
    public static Credential[] UnpackCredentials(byte[] buf, int n)
    {
        var result = new Credential[n];
        for (int i = 0; i < n; i++)
            result[i] = DeserializeCredential(buf, i * NativeWabi.CredentialSize);
        return result;
    }
}

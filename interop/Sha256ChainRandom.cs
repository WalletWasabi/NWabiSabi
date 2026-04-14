using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using WabiSabi.Crypto.Randomness;

namespace WabiSabiInterop;

/// <summary>
/// Deterministic SHA-256 chain RNG for reproducible test runs.
/// Each call to GetBytes advances an internal SHA-256 state chain.
/// </summary>
public sealed class Sha256ChainRandom : WasabiRandom
{
    private byte[] _state;

    public Sha256ChainRandom(byte[] seed)
    {
        _state = SHA256.HashData(seed);
    }

    public override void GetBytes(byte[] buffer) => GetBytes(buffer.AsSpan());

    public override void GetBytes(Span<byte> buffer)
    {
        int written = 0;
        while (written < buffer.Length)
        {
            _state = SHA256.HashData(_state);
            int chunk = Math.Min(32, buffer.Length - written);
            _state.AsSpan(0, chunk).CopyTo(buffer.Slice(written));
            written += chunk;
        }
    }

    public override int GetInt(int fromInclusive, int toExclusive)
    {
        _state = SHA256.HashData(_state);
        uint v = MemoryMarshal.Read<uint>(_state);
        return fromInclusive + (int)(v % (uint)(toExclusive - fromInclusive));
    }
}

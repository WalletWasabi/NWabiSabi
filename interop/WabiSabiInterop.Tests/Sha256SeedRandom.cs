using System;
using System.Security.Cryptography;
using WabiSabi.Crypto.Randomness;

namespace WabiSabiInterop.Tests;

/// <summary>
/// Deterministic seed-expansion RNG matching the native library's
/// <c>c/src/rand_stream.h</c>: the i-th 32-byte block is
/// <c>SHA256(seed || LE32(i))</c>, with the block counter advancing once per
/// 32-byte draw. Fed the <b>same seed</b> the native FFI receives, this makes the
/// managed reference draw byte-identical randomness, so both emit byte-identical
/// wire output for the same logical input (see <c>ByteEqualityTests</c>).
///
/// <para>Unlike <see cref="Sha256ChainRandom"/> this does <b>not</b> hash the seed
/// first — it uses the raw seed exactly as the native side does with its
/// <c>rand_bytes</c> argument. <see cref="GetScalar"/> is inherited from
/// <see cref="WasabiRandom"/>: it draws 32-byte blocks and rejects overflow/zero,
/// mirroring the native <c>scalar()</c> reject loop.</para>
/// </summary>
public sealed class Sha256SeedRandom : WasabiRandom
{
    private readonly byte[] _seed;
    private uint _counter;

    public Sha256SeedRandom(byte[] seed)
    {
        if (seed.Length != 32)
        {
            throw new ArgumentException("seed must be 32 bytes", nameof(seed));
        }
        _seed = (byte[])seed.Clone();
    }

    public override void GetBytes(byte[] buffer) => GetBytes(buffer.AsSpan());

    public override void GetBytes(Span<byte> buffer)
    {
        Span<byte> preimage = stackalloc byte[36];
        Span<byte> block = stackalloc byte[32];
        _seed.CopyTo(preimage);
        int written = 0;
        while (written < buffer.Length)
        {
            preimage[32] = (byte)_counter;
            preimage[33] = (byte)(_counter >> 8);
            preimage[34] = (byte)(_counter >> 16);
            preimage[35] = (byte)(_counter >> 24);
            _counter++;

            SHA256.HashData(preimage, block);
            int chunk = Math.Min(32, buffer.Length - written);
            block.Slice(0, chunk).CopyTo(buffer.Slice(written));
            written += chunk;
        }
    }

    public override int GetInt(int fromInclusive, int toExclusive)
    {
        Span<byte> b = stackalloc byte[4];
        GetBytes(b);
        uint v = (uint)(b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24));
        return fromInclusive + (int)(v % (uint)(toExclusive - fromInclusive));
    }
}

/// <summary>
/// A <see cref="WasabiRandom"/> that returns a fixed seed verbatim. Used to drive
/// the native wrapper, whose <c>GetBytes(32)</c> call produces the raw seed handed
/// to the FFI — so the native side expands exactly the seed a paired
/// <see cref="Sha256SeedRandom"/> expands on the managed side.
/// </summary>
public sealed class FixedSeedRandom : WasabiRandom
{
    private readonly byte[] _seed;

    public FixedSeedRandom(byte[] seed)
    {
        if (seed.Length != 32)
        {
            throw new ArgumentException("seed must be 32 bytes", nameof(seed));
        }
        _seed = (byte[])seed.Clone();
    }

    public override void GetBytes(byte[] buffer) => GetBytes(buffer.AsSpan());

    public override void GetBytes(Span<byte> buffer)
    {
        if (buffer.Length != _seed.Length)
        {
            throw new InvalidOperationException(
                $"FixedSeedRandom expects a {_seed.Length}-byte request, got {buffer.Length}.");
        }
        _seed.CopyTo(buffer);
    }

    public override int GetInt(int fromInclusive, int toExclusive) =>
        throw new NotSupportedException();
}

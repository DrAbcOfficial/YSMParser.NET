using System.Security.Cryptography;

namespace YSMParser.Core;

public static class CryptoUtils
{
    public const ulong SEED_KEY_DERIVATION = 0xD017CBBA7B5D3581UL;
    public const ulong SEED_RES_VERIFICATION = 0xA62B1A2C43842BC3UL;
    public const ulong SEED_CACHE_DECRYPTION = 0xD1C3D1D13A99752BUL;
    public const ulong SEED_FILE_VERIFICATION = 0x9E5599DB80C67C29UL;
    public const ulong SEED_PACKET_VERIFICATION = 0xEE6FA63D570BD77BUL;
    public const ulong SEED_CACHE_VERIFICATION = 0xF346451E53A22261UL;

    /// <summary>
    /// XChaCha20 with YSM-modified dynamic rounds. Mirrors
    /// <c>CryptoAlgorithms::xchacha_update_state</c>.
    /// </summary>
    public static uint XChaChaUpdateState(XChaChaCtx ctx, ulong hashV)
    {
        ctx.Rounds = 10 * (uint)(hashV % 3) + 10;

        uint lo = (uint)(hashV & 0xFFFFFFFFUL);
        uint hi = (uint)((hashV >> 32) & 0xFFFFFFFFUL);

        for (int i = 4; i < 16; ++i)
        {
            if (i % 2 == 0)
            {
                ctx.Input[i] ^= lo;
            }
            else
            {
                ctx.Input[i] ^= hi;
            }
        }

        return (uint)(((hashV & 0x3FUL) | 0x40UL) << 6);
    }

    public static byte[] ModifiedChaChaDecrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ulong seed)
    {
        Span<byte> keyIv = stackalloc byte[56];
        key.CopyTo(keyIv);
        iv.CopyTo(keyIv.Slice(32));

        ulong hash2 = CityHash.CityHash64WithSeed(keyIv, 56, seed);
        uint nextRoundSize = (uint)(((hash2 & 0x3FUL) | 0x40UL) << 6);
        int blockPointer = 0;

        XChaChaCtx ctx = new();
        ctx.Rounds = 10 * (uint)(hash2 % 3) + 10;
        XChaCha20.KeySetup(ctx, key, iv);

        byte[] result = new byte[data.Length];

        while (blockPointer < data.Length)
        {
            if (blockPointer + nextRoundSize > data.Length)
            {
                nextRoundSize = (uint)(data.Length - blockPointer);
            }

            int remaining = (int)nextRoundSize;
            ReadOnlySpan<byte> encSpan = data.Slice(blockPointer, remaining);
            Span<byte> decSpan = result.AsSpan(blockPointer, remaining);

            // XChaCha20 internally processes 64-byte blocks with a running counter;
            // calling it with a multi-block span produces the same output as the
            // C++ xchacha_decrypt_bytes(...) call.
            XChaCha20.DecryptBytes(ctx, encSpan, decSpan, nextRoundSize);

            ulong resHash = CityHash.CityHash64WithSeed(decSpan, remaining, seed);
            nextRoundSize = XChaChaUpdateState(ctx, resHash);

            blockPointer += remaining;
        }

        return result;
    }

    public static byte[] MT19937XorDecrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        Span<byte> keyIv = stackalloc byte[56];
        key.CopyTo(keyIv);
        iv.CopyTo(keyIv.Slice(32));

        ulong seed = CityHash.CityHash64WithSeed(keyIv, 56, SEED_KEY_DERIVATION);
        var mt = new Mt19937(seed);
        byte[] result = new byte[data.Length];

        int i = 0;
        while (i < data.Length)
        {
            ulong rnd = mt.NextUInt64();
            for (int j = 0; j < 8 && i < data.Length; ++j)
            {
                byte ks = (byte)((rnd >> (j * 8)) & 0xFF);
                result[i] = (byte)(data[i] ^ ks);
                ++i;
            }
        }
        return result;
    }

    public static byte[] DecompressZstd(ReadOnlySpan<byte> compressedData)
    {
        byte[] washed = YsmZstd.Wash(compressedData);
        using var decompressor = new ZstdSharp.Decompressor();
        int maxSize = Math.Max(8, washed.Length * 8);
        for (int attempt = 0; attempt < 4; attempt++)
        {
            byte[] output = new byte[maxSize];
            int written = decompressor.Unwrap(washed, output);
            if (written > 0)
            {
                Array.Resize(ref output, written);
                return output;
            }
            maxSize *= 4;
        }
        throw new InvalidOperationException("Zstd decompression failed (no output produced).");
    }
}

/// <summary>
/// 64-bit Mersenne Twister implementation that mirrors the seeded
/// <c>std::mt19937_64</c> used by the C++ implementation.
/// </summary>
internal sealed class Mt19937
{
    private const ulong MATRIX_A = 0xB5026F5AA96619E9UL;
    private const ulong UPPER_MASK = 0xFFFFFFFF80000000UL;
    private const ulong LOWER_MASK = 0x7FFFFFFFUL;

    private readonly ulong[] _mt = new ulong[312];
    private int _mti = 312;

    public Mt19937(ulong seed)
    {
        _mt[0] = seed;
        for (int i = 1; i < 312; i++)
        {
            _mt[i] = 6364136223846793005UL * (_mt[i - 1] ^ (_mt[i - 1] >> 62)) + (ulong)i;
        }
    }

    public ulong NextUInt64()
    {
        if (_mti >= 312)
        {
            Twist();
        }
        ulong y = _mt[_mti++];
        y ^= (y >> 29) & 0x5555555555555555UL;
        y ^= (y << 17) & 0x71D67FFFEDA60000UL;
        y ^= (y << 37) & 0xFFF7EEE000000000UL;
        y ^= y >> 43;
        return y;
    }

    private void Twist()
    {
        const int N = 312;
        const int M = 156;

        for (int i = 0; i < N - M; i++)
        {
            ulong y = (_mt[i] & UPPER_MASK) | (_mt[i + 1] & LOWER_MASK);
            _mt[i] = _mt[i + M] ^ (y >> 1) ^ ((y & 1UL) != 0 ? MATRIX_A : 0UL);
        }
        for (int i = N - M; i < N - 1; i++)
        {
            ulong y = (_mt[i] & UPPER_MASK) | (_mt[i + 1] & LOWER_MASK);
            _mt[i] = _mt[i + (M - N)] ^ (y >> 1) ^ ((y & 1UL) != 0 ? MATRIX_A : 0UL);
        }
        ulong yz = (_mt[N - 1] & UPPER_MASK) | (_mt[0] & LOWER_MASK);
        _mt[N - 1] = _mt[M - 1] ^ (yz >> 1) ^ ((yz & 1UL) != 0 ? MATRIX_A : 0UL);
        _mti = 0;
    }
}

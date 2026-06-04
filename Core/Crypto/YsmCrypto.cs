namespace YSMParser.Core.Crypto;

public static class YsmCrypto
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
        iv.CopyTo(keyIv[32..]);

        ulong hash2 = CityHash64.CityHash64WithSeed(keyIv, 56, seed);
        uint nextRoundSize = (uint)(((hash2 & 0x3FUL) | 0x40UL) << 6);
        int blockPointer = 0;

        XChaChaCtx ctx = new()
        {
            Rounds = 10 * (uint)(hash2 % 3) + 10
        };
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

            ulong resHash = CityHash64.CityHash64WithSeed(decSpan, remaining, seed);
            nextRoundSize = XChaChaUpdateState(ctx, resHash);

            blockPointer += remaining;
        }

        return result;
    }

    public static byte[] MT19937XorDecrypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        Span<byte> keyIv = stackalloc byte[56];
        key.CopyTo(keyIv);
        iv.CopyTo(keyIv[32..]);

        ulong seed = CityHash64.CityHash64WithSeed(keyIv, 56, SEED_KEY_DERIVATION);
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

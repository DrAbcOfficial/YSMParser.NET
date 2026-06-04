using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace YSMParser.Core;

/// <summary>
/// XChaCha20 stream cipher implementation. Direct port of the C library
/// used by the YSM parser, including the YSM-specific dynamic rounds
/// stored in <see cref="Rounds"/>.
/// </summary>
public sealed class XChaChaCtx
{
    public readonly uint[] Input = new uint[16];
    public uint Rounds;
}

public static class XChaCha20
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b; d ^= a; d = BitOperations.RotateLeft(d, 16);
        c += d; b ^= c; b = BitOperations.RotateLeft(b, 12);
        a += b; d ^= a; d = BitOperations.RotateLeft(d, 8);
        c += d; b ^= c; b = BitOperations.RotateLeft(b, 7);
    }

    public static void HChaCha20(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key, uint rounds)
    {
        uint x0 = 0x61707865, x1 = 0x3320646e, x2 = 0x79622d32, x3 = 0x6b206574;
        uint x4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
        uint x5 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
        uint x6 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
        uint x7 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));
        uint x8 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
        uint x9 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
        uint x10 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
        uint x11 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));
        uint x12 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(0, 4));
        uint x13 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(4, 4));
        uint x14 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(8, 4));
        uint x15 = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(12, 4));

        for (uint i = 0; i < rounds; i += 2)
        {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x1, ref x5, ref x9, ref x13);
            QuarterRound(ref x2, ref x6, ref x10, ref x14);
            QuarterRound(ref x3, ref x7, ref x11, ref x15);
            QuarterRound(ref x0, ref x5, ref x10, ref x15);
            QuarterRound(ref x1, ref x6, ref x11, ref x12);
            QuarterRound(ref x2, ref x7, ref x8, ref x13);
            QuarterRound(ref x3, ref x4, ref x9, ref x14);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(0, 4), x0);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(4, 4), x1);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(8, 4), x2);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(12, 4), x3);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(16, 4), x12);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(20, 4), x13);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(24, 4), x14);
        BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(28, 4), x15);
    }

    public static void KeySetup(XChaChaCtx ctx, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        Span<byte> k2 = stackalloc byte[32];
        HChaCha20(k2, iv.Slice(0, 16), key, ctx.Rounds);

        ctx.Input[0] = 0x61707865;
        ctx.Input[1] = 0x3320646e;
        ctx.Input[2] = 0x79622d32;
        ctx.Input[3] = 0x6b206574;
        ctx.Input[4] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(0, 4));
        ctx.Input[5] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(4, 4));
        ctx.Input[6] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(8, 4));
        ctx.Input[7] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(12, 4));
        ctx.Input[8] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(16, 4));
        ctx.Input[9] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(20, 4));
        ctx.Input[10] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(24, 4));
        ctx.Input[11] = BinaryPrimitives.ReadUInt32LittleEndian(k2.Slice(28, 4));
        ctx.Input[12] = 0;
        ctx.Input[13] = 0;
        ctx.Input[14] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(16, 4));
        ctx.Input[15] = BinaryPrimitives.ReadUInt32LittleEndian(iv.Slice(20, 4));
    }

    /// <summary>
    /// Process one 64-byte block. Reads 64 bytes from <paramref name="m"/> (which
    /// may alias <paramref name="c"/> for in-place operation), writes 64 bytes
    /// to <paramref name="c"/>, and XORs the message with the keystream after
    /// performing the configured number of rounds. Identical to the C++ reference.
    /// </summary>
    private static void EncryptBlock(XChaChaCtx ctx, ReadOnlySpan<byte> m, Span<byte> c, uint j12Init, uint j13Init)
    {
        uint x0 = ctx.Input[0], x1 = ctx.Input[1], x2 = ctx.Input[2], x3 = ctx.Input[3];
        uint x4 = ctx.Input[4], x5 = ctx.Input[5], x6 = ctx.Input[6], x7 = ctx.Input[7];
        uint x8 = ctx.Input[8], x9 = ctx.Input[9], x10 = ctx.Input[10], x11 = ctx.Input[11];
        uint x12 = j12Init, x13 = j13Init, x14 = ctx.Input[14], x15 = ctx.Input[15];

        for (uint i = ctx.Rounds; i > 0; i -= 2)
        {
            QuarterRound(ref x0, ref x4, ref x8, ref x12);
            QuarterRound(ref x1, ref x5, ref x9, ref x13);
            QuarterRound(ref x2, ref x6, ref x10, ref x14);
            QuarterRound(ref x3, ref x7, ref x11, ref x15);
            QuarterRound(ref x0, ref x5, ref x10, ref x15);
            QuarterRound(ref x1, ref x6, ref x11, ref x12);
            QuarterRound(ref x2, ref x7, ref x8, ref x13);
            QuarterRound(ref x3, ref x4, ref x9, ref x14);
        }

        x0 += ctx.Input[0]; x1 += ctx.Input[1]; x2 += ctx.Input[2]; x3 += ctx.Input[3];
        x4 += ctx.Input[4]; x5 += ctx.Input[5]; x6 += ctx.Input[6]; x7 += ctx.Input[7];
        x8 += ctx.Input[8]; x9 += ctx.Input[9]; x10 += ctx.Input[10]; x11 += ctx.Input[11];
        x12 += j12Init; x13 += j13Init; x14 += ctx.Input[14]; x15 += ctx.Input[15];

        x0 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(0, 4));
        x1 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(4, 4));
        x2 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(8, 4));
        x3 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(12, 4));
        x4 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(16, 4));
        x5 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(20, 4));
        x6 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(24, 4));
        x7 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(28, 4));
        x8 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(32, 4));
        x9 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(36, 4));
        x10 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(40, 4));
        x11 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(44, 4));
        x12 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(48, 4));
        x13 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(52, 4));
        x14 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(56, 4));
        x15 ^= BinaryPrimitives.ReadUInt32LittleEndian(m.Slice(60, 4));

        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(0, 4), x0);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(4, 4), x1);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(8, 4), x2);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(12, 4), x3);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(16, 4), x4);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(20, 4), x5);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(24, 4), x6);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(28, 4), x7);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(32, 4), x8);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(36, 4), x9);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(40, 4), x10);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(44, 4), x11);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(48, 4), x12);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(52, 4), x13);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(56, 4), x14);
        BinaryPrimitives.WriteUInt32LittleEndian(c.Slice(60, 4), x15);
    }

    public static void EncryptBytes(XChaChaCtx ctx, ReadOnlySpan<byte> input, Span<byte> output, uint bytes)
    {
        if (bytes == 0) return;

        uint j12 = ctx.Input[12];
        uint j13 = ctx.Input[13];

        int inputOffset = 0;
        int outputOffset = 0;
        uint remaining = bytes;

        while (true)
        {
            if (remaining < 64)
            {
                if (remaining == 0)
                {
                    ctx.Input[12] = j12;
                    ctx.Input[13] = j13;
                    return;
                }
                Span<byte> scratch = stackalloc byte[64];
                for (uint i = 0; i < remaining; ++i)
                {
                    scratch[(int)i] = input[inputOffset + (int)i];
                }
                EncryptBlock(ctx, scratch, scratch, j12, j13);
                scratch.Slice(0, (int)remaining).CopyTo(output.Slice(outputOffset));
                ctx.Input[12] = j12;
                ctx.Input[13] = j13;
                return;
            }

            EncryptBlock(ctx, input.Slice(inputOffset, 64), output.Slice(outputOffset, 64), j12, j13);

            j12++;
            if (j12 == 0) j13++;

            remaining -= 64;
            inputOffset += 64;
            outputOffset += 64;

            if (remaining == 0)
            {
                ctx.Input[12] = j12;
                ctx.Input[13] = j13;
                return;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DecryptBytes(XChaChaCtx ctx, ReadOnlySpan<byte> input, Span<byte> output, uint bytes)
    {
        EncryptBytes(ctx, input, output, bytes);
    }
}

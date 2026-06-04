using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace YSMParser.Core;

/// <summary>
/// CityHash64 implementation with the YSM-modified constants.
/// Ported from the reference C++ implementation in <c>external/cityhash</c>.
/// </summary>
public static class CityHash
{
    // YSM-Modified constants.
    private const ulong k0 = 0xE4986A230E5AAA17UL;
    private const ulong k1 = 0x91AF10802CAB25A5UL;
    private const ulong k2 = 0xAF29CE778879D9C7UL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Fetch64(ReadOnlySpan<byte> s) => MemoryMarshal.Read<ulong>(s);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint Fetch32(ReadOnlySpan<byte> s) => MemoryMarshal.Read<uint>(s);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Rotate(ulong val, int shift) => shift == 0 ? val : (val >> shift) | (val << (64 - shift));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong ShiftMix(ulong val) => val ^ (val >> 47);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong BSwap64(ulong v) => System.Buffers.Binary.BinaryPrimitives.ReverseEndianness(v);

    private static ulong HashLen16(ulong u, ulong v) => Hash128to64(u, v);

    private static ulong HashLen16(ulong u, ulong v, ulong mul)
    {
        ulong a = (u ^ v) * mul;
        a ^= (a >> 47);
        ulong b = (v ^ a) * mul;
        b ^= (b >> 47);
        b *= mul;
        return b;
    }

    private static ulong Hash128to64(ulong u, ulong v)
    {
        // YSM-modified: completely different algorithm from standard CityHash
        const ulong kMul = 0xDE0F6EE09BDBAB91UL;
        return kMul * ShiftMix(kMul * (ShiftMix((u ^ v) * kMul) ^ u));
    }

    private static ulong HashLen0to16(ReadOnlySpan<byte> s, int len)
    {
        if (len >= 8)
        {
            ulong mul = k2 + (ulong)len * 2;
            ulong a = Fetch64(s) + k2;
            ulong b = Fetch64(s.Slice(len - 8));
            ulong c = Rotate(b, 37) * mul + a;
            ulong d = (Rotate(a, 25) + b) * mul;
            return HashLen16(c, d, mul);
        }
        if (len >= 4)
        {
            ulong mul = k2 + (ulong)len * 2;
            ulong a = Fetch32(s);
            return HashLen16((ulong)len + (a << 3), Fetch32(s.Slice(len - 4)), mul);
        }
        if (len > 0)
        {
            byte a = s[0];
            byte b = s[len >> 1];
            byte c = s[len - 1];
            uint y = (uint)a + ((uint)b << 8);
            uint z = (uint)len + ((uint)c << 2);
            return ShiftMix((ulong)y * k2 ^ (ulong)z * k0) * k2;
        }
        return k2;
    }

    private static ulong HashLen17to32(ReadOnlySpan<byte> s, int len)
    {
        ulong mul = k2 + (ulong)len * 2;
        ulong a = Fetch64(s) * k1;
        ulong b = Fetch64(s.Slice(8));
        ulong c = Fetch64(s.Slice(len - 8)) * mul;
        ulong d = Fetch64(s.Slice(len - 16)) * k2;
        return HashLen16(Rotate(a + b, 43) + Rotate(c, 30) + d,
                         a + Rotate(b + k2, 18) + c, mul);
    }

    private static (ulong First, ulong Second) WeakHashLen32WithSeeds(ReadOnlySpan<byte> s, ulong a, ulong b)
    {
        return WeakHashLen32WithSeeds(Fetch64(s), Fetch64(s.Slice(8)),
                                       Fetch64(s.Slice(16)), Fetch64(s.Slice(24)), a, b);
    }

    private static (ulong First, ulong Second) WeakHashLen32WithSeeds(ulong w, ulong x, ulong y, ulong z, ulong a, ulong b)
    {
        a += w;
        b = Rotate(b + a + z, 21);
        ulong c = a;
        a += x;
        a += y;
        b += Rotate(a, 44);
        return (a + z, b + c);
    }

    private static ulong HashLen33to64(ReadOnlySpan<byte> s, int len)
    {
        ulong mul = k2 + (ulong)len * 2;
        ulong a = Fetch64(s) * k2;
        ulong b = Fetch64(s.Slice(8));
        ulong c = Fetch64(s.Slice(len - 24));
        ulong d = Fetch64(s.Slice(len - 32));
        ulong e = Fetch64(s.Slice(16)) * k2;
        ulong f = Fetch64(s.Slice(24)) * 9;
        ulong g = Fetch64(s.Slice(len - 8));
        ulong h = Fetch64(s.Slice(len - 16)) * mul;
        ulong u = Rotate(a + g, 43) + (Rotate(b, 30) + c) * 9;
        ulong v = ((a + g) ^ d) + f + 1;
        ulong w = BSwap64((u + v) * mul) + h;
        ulong x = Rotate(e + f, 42) + c;
        ulong y = (BSwap64((v + w) * mul) + g) * mul;
        ulong z = e + f + c;
        a = BSwap64((x + z) * mul + y) + b;
        b = ShiftMix((z + a) * mul + d + h) * mul;
        return b + x;
    }

    public static ulong CityHash64(ReadOnlySpan<byte> s, int len)
    {
        if (len <= 32)
        {
            if (len <= 16)
            {
                return HashLen0to16(s, len);
            }
            return HashLen17to32(s, len);
        }
        if (len <= 64)
        {
            return HashLen33to64(s, len);
        }

        ulong xx = Fetch64(s.Slice(len - 40));
        ulong y = Fetch64(s.Slice(len - 16)) + Fetch64(s.Slice(len - 56));
        ulong z = HashLen16(Fetch64(s.Slice(len - 48)) + (ulong)len, Fetch64(s.Slice(len - 24)));
        var v = WeakHashLen32WithSeeds(s.Slice(len - 64), (ulong)len, z);
        var w = WeakHashLen32WithSeeds(s.Slice(len - 32), y + k1, xx);
        xx = xx * k1 + Fetch64(s);

        int rem = (len - 1) & ~63;
        do
        {
            xx = Rotate(xx + y + v.First + Fetch64(s.Slice(8)), 37) * k1;
            y = Rotate(y + v.Second + Fetch64(s.Slice(48)), 42) * k1;
            xx ^= w.Second;
            y += v.First + Fetch64(s.Slice(40));
            z = Rotate(z + w.First, 33) * k1;
            v = WeakHashLen32WithSeeds(s, v.Second * k1, xx + w.First);
            w = WeakHashLen32WithSeeds(s.Slice(32), z + w.Second, y + Fetch64(s.Slice(16)));
            (z, xx) = (xx, z);
            s = s.Slice(64);
            rem -= 64;
        } while (rem != 0);
        return HashLen16(HashLen16(v.First, w.First) + ShiftMix(y) * k1 + z,
                         HashLen16(v.Second, w.Second) + xx);
    }

    public static ulong CityHash64WithSeed(ReadOnlySpan<byte> s, int len, ulong seed) =>
        CityHash64WithSeeds(s, len, k2, seed);

    public static ulong CityHash64WithSeeds(ReadOnlySpan<byte> s, int len, ulong seed0, ulong seed1) =>
        HashLen16(CityHash64(s, len) - seed0, seed1);
}

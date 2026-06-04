namespace YSMParser.Core;

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

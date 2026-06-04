namespace YSMParser.Core.Parsers;

/// <summary>
/// Java's <c>java.util.Random</c> reproduced for YSM V2 PRNG derivation.
/// The mask is the standard 48-bit LCG: <c>seed = (seed * 0x5DEECE66D + 0xB) &amp; ((1 &lt;&lt; 48) - 1)</c>.
/// </summary>
internal sealed class JavaRandom(ulong initialSeed)
{
    private const ulong Multiplier = 0x5DEECE66DUL;
    private const ulong Addend = 0xBUL;
    private const ulong Mask = (1UL << 48) - 1;

    private ulong _seed = (initialSeed ^ Multiplier) & Mask;

    public int Next(int bits)
    {
        _seed = (_seed * Multiplier + Addend) & Mask;
        return (int)(_seed >> (48 - bits));
    }

    public void NextBytes(Span<byte> bytes)
    {
        int i = 0;
        while (i < bytes.Length)
        {
            int rnd = Next(32);
            int n = Math.Min(bytes.Length - i, 4);
            for (int k = 0; k < n; k++)
            {
                bytes[i++] = (byte)rnd;
                rnd >>= 8;
            }
        }
    }
}

namespace YSMParser.Tests;

public sealed class Mt19937Tests
{
    [Fact]
    public void SeedZero_Produces_NonZeroOutput()
    {
        var mt = new Mt19937(0);
        ulong v = mt.NextUInt64();
        Assert.NotEqual(0ul, v);
    }

    [Fact]
    public void Produces_DeterministicSequence()
    {
        var mt1 = new Mt19937(0xCAFEBABEul);
        var mt2 = new Mt19937(0xCAFEBABEul);

        for (int i = 0; i < 100; i++)
        {
            Assert.Equal(mt1.NextUInt64(), mt2.NextUInt64());
        }
    }

    [Fact]
    public void DifferentSeeds_ProduceDifferentOutput()
    {
        var mt1 = new Mt19937(0xAAAAAAAAul);
        var mt2 = new Mt19937(0xBBBBBBBBul);

        Assert.NotEqual(mt1.NextUInt64(), mt2.NextUInt64());
    }

    [Fact]
    public void Generates_MoreThan312Values_AfterTwist()
    {
        var mt = new Mt19937(42);
        // Generate more than state size to force twist
        for (int i = 0; i < 500; i++)
        {
            ulong v = mt.NextUInt64();
            Assert.NotEqual(0ul, v); // should never be 0 with non-zero seed
        }
    }
}

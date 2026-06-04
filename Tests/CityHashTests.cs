using YSMParser.Core;

namespace YSMParser.Tests;

public sealed class CityHashTests
{
    [Fact]
    public void Empty_ReturnsK2()
    {
        ulong h = CityHash.CityHash64([], 0);
        Assert.Equal(0xAF29CE778879D9C7ul, h);
    }

    [Fact]
    public void SingleChar_A()
    {
        byte[] data = "a"u8.ToArray();
        ulong h = CityHash.CityHash64(data, data.Length);
        Assert.Equal(0x9B523756FC604CD5ul, h);
    }

    [Fact]
    public void ThreeChars_Abc()
    {
        byte[] data = "abc"u8.ToArray();
        ulong h = CityHash.CityHash64(data, data.Length);
        Assert.Equal(0xF207656CA5D4DC83ul, h);
    }

    [Fact]
    public void ElevenChars_HelloWorld()
    {
        byte[] data = "hello world"u8.ToArray();
        ulong h = CityHash.CityHash64(data, data.Length);
        Assert.Equal(0xC099D1F62205DF38ul, h);
    }

    [Fact]
    public void Fox_Length43()
    {
        byte[] data = "The quick brown fox jumps over the lazy dog"u8.ToArray();
        ulong h = CityHash.CityHash64(data, data.Length);
        Assert.Equal(0x1C37F2033D092FF7ul, h);
    }

    [Fact]
    public void WithSeed_Deterministic()
    {
        byte[] data = "test data"u8.ToArray();
        ulong h1 = CityHash.CityHash64WithSeed(data, data.Length, 0xCAFEBABEul);
        ulong h2 = CityHash.CityHash64WithSeed(data, data.Length, 0xCAFEBABEul);
        Assert.Equal(h1, h2);
    }
}

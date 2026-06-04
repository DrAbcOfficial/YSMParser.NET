using YSMParser.Core.Utilities;

namespace YSMParser.Tests;

public sealed class MemoryUtilsTests
{
    [Fact]
    public void ReadLE_Uint32()
    {
        byte[] data = [0x78, 0x56, 0x34, 0x12];
        uint value = MemoryUtils.ReadLE<uint>(data);
        Assert.Equal(0x12345678u, value);
    }

    [Fact]
    public void ReadLE_Uint64()
    {
        byte[] data = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        ulong value = MemoryUtils.ReadLE<ulong>(data);
        Assert.Equal(0x0123456789ABCDEFul, value);
    }

    [Fact]
    public void ReadBE_Uint32()
    {
        byte[] data = [0x12, 0x34, 0x56, 0x78];
        uint value = MemoryUtils.ReadBE<uint>(data);
        Assert.Equal(0x12345678u, value);
    }

    [Fact]
    public void ReadLE24()
    {
        byte[] data = [0x78, 0x56, 0x34];
        uint value = MemoryUtils.ReadLE24(data);
        Assert.Equal(0x345678u, value);
    }

    [Fact]
    public void WriteLE_Uint32_RoundTrip()
    {
        byte[] buffer = new byte[4];
        uint original = 0xABCDEF01u;
        MemoryUtils.WriteLE(buffer, original);
        uint result = MemoryUtils.ReadLE<uint>(buffer);
        Assert.Equal(original, result);
    }

    [Fact]
    public void WriteBE_Uint32_RoundTrip()
    {
        byte[] buffer = new byte[4];
        uint original = 0xABCDEF01u;
        MemoryUtils.WriteBE(buffer, original);
        uint result = MemoryUtils.ReadBE<uint>(buffer);
        Assert.Equal(original, result);
    }

    [Fact]
    public void BOM_Detection_ReadLE24()
    {
        byte[] data = [0xEF, 0xBB, 0xBF];
        uint bom = MemoryUtils.ReadLE24(data);
        Assert.Equal(0xBFBBEFu, bom);
    }
}

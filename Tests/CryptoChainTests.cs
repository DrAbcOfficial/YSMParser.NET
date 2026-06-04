using YSMParser.Core;

namespace YSMParser.Tests;

public sealed class CryptoChainTests
{
    [Fact]
    public void ZstdSharp_RoundTrip_Works()
    {
        byte[] original = "Hello ZSTD Test Data!"u8.ToArray();
        using var compressor = new ZstdSharp.Compressor(3);
        byte[] compressed = compressor.Wrap(original).ToArray();

        using var decompressor = new ZstdSharp.Decompressor();
        byte[] decompressed = decompressor.Unwrap(compressed, compressed.Length * 4).ToArray();

        Assert.Equal(original, decompressed);
    }

    [Fact]
    public void SEED_Constants_AreAsExpected()
    {
        Assert.Equal(0xD017CBBA7B5D3581ul, CryptoUtils.SEED_KEY_DERIVATION);
        Assert.Equal(0xA62B1A2C43842BC3ul, CryptoUtils.SEED_RES_VERIFICATION);
        Assert.Equal(0x9E5599DB80C67C29ul, CryptoUtils.SEED_FILE_VERIFICATION);
    }

    [Fact]
    public void Mt19937_XorDecrypt_RoundTrip()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];
        Random.Shared.NextBytes(key);
        Random.Shared.NextBytes(iv);

        byte[] data = new byte[256];
        Random.Shared.NextBytes(data);

        byte[] encrypted = CryptoUtils.MT19937XorDecrypt(data, key, iv);
        byte[] decrypted = CryptoUtils.MT19937XorDecrypt(encrypted, key, iv);

        Assert.Equal(data, decrypted);
    }

    [Fact]
    public void ModifiedChaChaDecrypt_ProducesDeterministicOutput()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];
        byte[] data = new byte[512];
        Random.Shared.NextBytes(data);

        byte[] r1 = CryptoUtils.ModifiedChaChaDecrypt(data, key, iv, 0xCAFEBABEul);
        byte[] r2 = CryptoUtils.ModifiedChaChaDecrypt(data, key, iv, 0xCAFEBABEul);

        Assert.Equal(r1, r2);
    }
}

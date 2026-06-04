using YSMParser.Core;

namespace YSMParser.Tests;

public sealed class XChaCha20Tests
{
    [Fact]
    public void KeySetup_InitializesInput()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];

        var ctx = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctx, key, iv);

        Assert.Equal(0x61707865u, ctx.Input[0]);
        Assert.Equal(0u, ctx.Input[12]);
        Assert.Equal(0u, ctx.Input[13]);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        byte[] key = new byte[32];
        Random.Shared.NextBytes(key);
        byte[] iv = new byte[24];
        Random.Shared.NextBytes(iv);

        byte[] plaintext = new byte[128];
        Random.Shared.NextBytes(plaintext);

        var ctxEnc = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctxEnc, key, iv);
        byte[] ciphertext = new byte[128];
        XChaCha20.EncryptBytes(ctxEnc, plaintext, ciphertext, 128);

        var ctxDec = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctxDec, key, iv);
        byte[] decrypted = new byte[128];
        XChaCha20.DecryptBytes(ctxDec, ciphertext, decrypted, 128);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptDecrypt_ShortInput()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];

        byte[] plaintext = "hello"u8.ToArray();

        var ctxEnc = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctxEnc, key, iv);
        byte[] ciphertext = new byte[5];
        XChaCha20.EncryptBytes(ctxEnc, plaintext, ciphertext, 5);

        var ctxDec = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctxDec, key, iv);
        byte[] decrypted = new byte[5];
        XChaCha20.DecryptBytes(ctxDec, ciphertext, decrypted, 5);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Encrypt_DifferentRounds_ProduceDifferentOutput()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];
        byte[] plaintext = new byte[64];

        var ctx10 = new XChaChaCtx { Rounds = 10 };
        XChaCha20.KeySetup(ctx10, key, iv);
        byte[] output10 = new byte[64];
        XChaCha20.EncryptBytes(ctx10, plaintext, output10, 64);

        var ctx20 = new XChaChaCtx { Rounds = 20 };
        XChaCha20.KeySetup(ctx20, key, iv);
        byte[] output20 = new byte[64];
        XChaCha20.EncryptBytes(ctx20, plaintext, output20, 64);

        Assert.NotEqual(output10, output20);
    }

    [Fact]
    public void Encrypt_ExactBlockSize_DoesNotHang()
    {
        byte[] key = new byte[32];
        byte[] iv = new byte[24];
        byte[] plaintext = new byte[64];

        var ctx = new XChaChaCtx { Rounds = 10 };
        XChaCha20.KeySetup(ctx, key, iv);
        byte[] output = new byte[64];
        XChaCha20.EncryptBytes(ctx, plaintext, output, 64);

        // Should not throw, and output should be 64 bytes
        Assert.NotNull(output);
    }
}

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace YSMParser.Core;

public static class AesUtil
{
    public static byte[] DecryptCbc(ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray();
        aes.IV = iv.ToArray();

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(cipherText.ToArray(), 0, cipherText.Length);
    }
}

public static class ZlibUtil
{
    public static byte[] Decompress(ReadOnlySpan<byte> compressedData)
    {
        var compressed = compressedData.ToArray();
        using var input = new MemoryStream(compressed);
        using var deflate = new System.IO.Compression.DeflateStream(input, System.IO.Compression.CompressionMode.Decompress, leaveOpen: true);
        using var output = new MemoryStream();
        deflate.CopyTo(output);
        return output.ToArray();
    }
}

public static class Md5Util
{
    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[16];
        MD5.HashData(data, hash);
        return hash.ToArray();
    }

    public static ulong HashToLong(byte[] hash)
    {
        return System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(8));
    }
}

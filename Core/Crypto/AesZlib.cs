using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;

namespace YSMParser.Core.Crypto;

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
        if (compressedData.Length < 2)
            throw new InvalidDataException("Data too short for decompression.");

        // Check for zlib header (RFC 1950): CMF byte low nibble must be 8 (deflate)
        bool hasZlibHeader = (compressedData[0] & 0x0F) == 8;

        ReadOnlySpan<byte> rawDeflate;
        if (hasZlibHeader)
        {
            int headerSize = 2;
            if ((compressedData[1] & 0x20) != 0)
                headerSize += 4; // FDICT set, skip DICTID
            rawDeflate = compressedData.Slice(headerSize, compressedData.Length - headerSize - 4);
        }
        else
        {
            rawDeflate = compressedData;
        }

        using var input = new MemoryStream(rawDeflate.ToArray());
        using var deflate = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: true);
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
        return BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(8));
    }
}

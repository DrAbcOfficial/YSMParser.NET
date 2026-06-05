using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;

namespace YSMParser.Core.Crypto;

/// <summary>
/// AES-CBC decryption utilities used by YSM parser V1 and V2.
/// </summary>
public static class AesUtil
{
    /// <summary>
    /// Decrypts data using AES-CBC with no padding.
    /// </summary>
    /// <param name="cipherText">The encrypted data.</param>
    /// <param name="key">The 16-byte AES key.</param>
    /// <param name="iv">The 16-byte initialization vector.</param>
    /// <returns>The decrypted data.</returns>
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

/// <summary>
/// Zlib decompression utilities. Handles both raw deflate and RFC 1950 zlib-wrapped data.
/// </summary>
public static class ZlibUtil
{
    /// <summary>
    /// Decompresses zlib or raw deflate compressed data.
    /// </summary>
    /// <param name="compressedData">The compressed data, with or without a zlib header.</param>
    /// <returns>The decompressed data.</returns>
    /// <exception cref="InvalidDataException">Thrown if the data is too short to be valid.</exception>
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

/// <summary>
/// MD5 hashing utilities used for key derivation in YSM V2.
/// </summary>
public static class Md5Util
{
    /// <summary>
    /// Computes the MD5 hash of the given data.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>A 16-byte MD5 hash.</returns>
    public static byte[] Hash(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[16];
        MD5.HashData(data, hash);
        return hash.ToArray();
    }

    /// <summary>
    /// Reads a <see cref="ulong"/> from the second half of an MD5 hash.
    /// Used to seed a <c>JavaRandom</c> PRNG in YSM V2.
    /// </summary>
    /// <param name="hash">A 16-byte MD5 hash.</param>
    /// <returns>A 64-bit value read from bytes 8–15 of the hash in big-endian order.</returns>
    public static ulong HashToLong(byte[] hash)
    {
        return BinaryPrimitives.ReadUInt64BigEndian(hash.AsSpan(8));
    }
}

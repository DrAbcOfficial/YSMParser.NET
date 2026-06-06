namespace YSMParser.Core.Crypto;

/// <summary>
/// Reverts the YSM "obfuscation" applied to a standard ZSTD frame so the
/// stream can be fed into a normal ZSTD decoder. Mirrors the C++
/// <c>YsmZstd::wash</c> implementation.
/// </summary>
public static class YsmZstd
{
    private const uint STD_BT_RAW = 0;
    private const uint STD_BT_RLE = 1;
    private const uint STD_BT_COMPRESSED = 2;
    private const uint STD_BT_RESERVED = 3;

    private static int CalculateFrameHeaderSize(byte fhd)
    {
        int size = 1; // FHD itself.

        int dictIdSize = 0;
        int dictIdBits = fhd & 3;
        if (dictIdBits == 1) dictIdSize = 1;
        else if (dictIdBits == 2) dictIdSize = 2;
        else if (dictIdBits == 3) dictIdSize = 4;

        bool singleSegment = ((fhd >> 5) & 1) == 1;
        int fcsBits = (fhd >> 6) & 3;
        int fcsSize;
        if (fcsBits == 0) fcsSize = singleSegment ? 1 : 0;
        else if (fcsBits == 1) fcsSize = 2;
        else if (fcsBits == 2) fcsSize = 4;
        else fcsSize = 8;

        int windowDescSize = singleSegment ? 0 : 1;
        return size + windowDescSize + dictIdSize + fcsSize;
    }

    /// <summary>
    /// Reverts YSM obfuscation on a Zstd-compressed frame, restoring it to a standard
    /// Zstd frame that can be decoded by a normal Zstd decompressor. Performs in-place
    /// modifications: clears the checksum bit in the frame header descriptor and
    /// recalculates block headers using the YSM-specific obfuscation key (<c>0xD4E9</c>).
    /// </summary>
    /// <param name="compressedData">The YSM-obfuscated Zstd data.</param>
    /// <returns>A copy of the data with obfuscation removed.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown if the data is too short or does not contain a valid Zstd magic number.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown if an unknown block type is encountered.
    /// </exception>
    public static unsafe byte[] Wash(ReadOnlySpan<byte> compressedData)
    {
        if (compressedData.Length < 5)
        {
            throw new ArgumentException("Invalid data length");
        }

        var data = GC.AllocateUninitializedArray<byte>(compressedData.Length);
        compressedData.CopyTo(data);

        fixed (byte* pData = data)
        {
            if (*(uint*)pData != 0xFD2FB528)
            {
                throw new ArgumentException("Not a standard ZSTD Magic Number. May be skippable frame or unknown.");
            }

            byte fhd = pData[4];
            // Clear the checksum bit (bit 2) of the Frame Header Descriptor.
            pData[4] = (byte)(fhd & 0xFB);

            int frameHeaderSize = CalculateFrameHeaderSize(fhd);
            int offset = 4 + frameHeaderSize;

            while (offset + 3 <= data.Length)
            {
                uint b0 = pData[offset];
                uint b1 = pData[offset + 1];
                uint b2 = pData[offset + 2];

                uint lastBlock = (b0 >> 7) & 1;
                uint blockTypeYSM = (b0 >> 5) & 3;
                uint rawSize = ((b0 & 0x1F) << 16) | b1 | (b2 << 8);
                uint cSize = rawSize ^ 0xD4E9;
                var blockTypeStd = blockTypeYSM switch
                {
                    0 => STD_BT_COMPRESSED,
                    1 => STD_BT_RLE,
                    2 => STD_BT_RESERVED,
                    3 => STD_BT_RAW,
                    _ => throw new InvalidOperationException("Unknown block type"),
                };
                uint stdHeader = lastBlock | (blockTypeStd << 1) | (cSize << 3);
                pData[offset] = (byte)(stdHeader & 0xFF);
                pData[offset + 1] = (byte)((stdHeader >> 8) & 0xFF);
                pData[offset + 2] = (byte)((stdHeader >> 16) & 0xFF);

                uint blockDataSize = blockTypeStd == STD_BT_RLE ? 1u : cSize;
                offset += 3 + (int)blockDataSize;

                if (lastBlock == 1)
                {
                    break;
                }
            }
        }

        return data;
    }
}

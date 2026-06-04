using System.Buffers.Binary;

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

    public static byte[] Wash(ReadOnlySpan<byte> compressedData)
    {
        if (compressedData.Length < 5)
        {
            throw new ArgumentException("Invalid data length");
        }

        var data = compressedData.ToArray();

        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        if (magic != 0xFD2FB528)
        {
            throw new ArgumentException("Not a standard ZSTD Magic Number. May be skippable frame or unknown.");
        }

        byte fhd = data[4];
        // Clear the checksum bit (bit 2) of the Frame Header Descriptor.
        data[4] = (byte)(fhd & 0xFB);

        int frameHeaderSize = CalculateFrameHeaderSize(fhd);
        int offset = 4 + frameHeaderSize;

        while (offset + 3 <= data.Length)
        {
            uint b0 = data[offset];
            uint b1 = data[offset + 1];
            uint b2 = data[offset + 2];

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
            data[offset] = (byte)(stdHeader & 0xFF);
            data[offset + 1] = (byte)((stdHeader >> 8) & 0xFF);
            data[offset + 2] = (byte)((stdHeader >> 16) & 0xFF);

            uint blockDataSize = blockTypeStd == STD_BT_RLE ? 1u : cSize;
            offset += 3 + (int)blockDataSize;

            if (lastBlock == 1)
            {
                break;
            }
        }

        return data;
    }
}

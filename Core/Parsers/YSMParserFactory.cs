using YSMParser.Core.Utilities;

namespace YSMParser.Core.Parsers;

/// <summary>
/// Factory for creating the appropriate <see cref="YSMParser"/> implementation
/// based on file magic bytes and crypto version detection.
/// </summary>
public static class YSMParserFactory
{
    private const uint YSGP_MAGIC = 0x50475359; // "YSGP" in ASCII

    /// <summary>
    /// Reads a file from disk and auto-detects the YSM version, returning the correct parser.
    /// </summary>
    /// <param name="path">The path to the YSM file.</param>
    /// <returns>A parser instance for the detected version.</returns>
    /// <exception cref="ParserInvalidFileFormatException">Thrown if the file is too short or structurally invalid.</exception>
    /// <exception cref="ParserUnSupportVersionException">Thrown if the version cannot be determined.</exception>
    public static YSMParser Create(string path)
    {
        var data = File.ReadAllBytes(path);
        return CreateFromBytes(data);
    }

    /// <summary>
    /// Auto-detects the YSM version from raw bytes and returns the correct parser.
    /// Detection rules:
    /// <list type="bullet">
    /// <item><description>UTF-8 BOM (0xBFBBEF) at offset 0 + YSGP at offset 3 → V3</description></item>
    /// <item><description>YSGP at offset 0 + crypto byte 1 at offset 4 → V1</description></item>
    /// <item><description>YSGP at offset 0 + crypto byte 2 at offset 4 → V2</description></item>
    /// </list>
    /// </summary>
    /// <param name="data">The raw file bytes.</param>
    /// <returns>A parser instance for the detected version.</returns>
    /// <exception cref="ParserInvalidFileFormatException">Thrown if the data is too short.</exception>
    /// <exception cref="ParserUnSupportVersionException">Thrown if the version cannot be determined.</exception>
    public static YSMParser CreateFromBytes(byte[] data)
    {
        if (data.Length < 8) throw new ParserInvalidFileFormatException();

        uint utf8Header = MemoryUtils.ReadLE24(data);
        uint magic3 = MemoryUtils.ReadLE<uint>(data.AsSpan(3));
        if (utf8Header == 0xbfbbef && magic3 == YSGP_MAGIC)
        {
            return new YSMParserV3(data);
        }

        uint magic2 = MemoryUtils.ReadLE<uint>(data);
        uint crypto = MemoryUtils.ReadBE<uint>(data.AsSpan(4));
        if (magic2 == YSGP_MAGIC)
        {
            if (crypto == 1) return new YSMParserV1(data);
            if (crypto == 2) return new YSMParserV2(data);
        }
        throw new ParserUnSupportVersionException();
    }
}

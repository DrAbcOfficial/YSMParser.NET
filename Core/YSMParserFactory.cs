namespace YSMParser.Core;

public static class YSMParserFactory
{
    private const uint YSGP_MAGIC = 0x50475359; // "YSGP" in ASCII

    public static YSMParser Create(string path)
    {
        var data = File.ReadAllBytes(path);
        return CreateFromBytes(data);
    }

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

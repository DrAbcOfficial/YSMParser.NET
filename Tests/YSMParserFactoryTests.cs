using YSMParser.Core.Parsers;

namespace YSMParser.Tests;

public sealed class YSMParserFactoryTests
{
    [Fact]
    public void Create_InvalidData_Throws()
    {
        byte[] invalid = new byte[4];
        Assert.Throws<ParserInvalidFileFormatException>(() => YSMParserFactory.CreateFromBytes(invalid));
    }
}

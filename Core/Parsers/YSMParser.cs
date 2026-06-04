namespace YSMParser.Core.Parsers;

public abstract class YSMParser
{
    public bool Verbose { get; set; }
    public bool Debug { get; set; }
    public bool FormatJson { get; set; }

    public abstract int GetYSGPVersion();
    public abstract void Parse();
    public abstract byte[] GetDecryptedData();
    public abstract void SaveToDirectory(string outputDirectory);
}

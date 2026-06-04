namespace YSMParser.Core.Parsers;

public sealed record YsmResourceEntry(string Name, byte[] Data);

public sealed record YsmResourceData(
    IReadOnlyList<YsmResourceEntry> Models,
    IReadOnlyList<YsmResourceEntry> Textures,
    IReadOnlyList<YsmResourceEntry> Animations,
    IReadOnlyList<YsmResourceEntry> AnimationControllers,
    IReadOnlyList<YsmResourceEntry> Sounds,
    IReadOnlyList<YsmResourceEntry> Functions,
    IReadOnlyList<YsmResourceEntry> Languages,
    IReadOnlyList<YsmResourceEntry> Avatars,
    IReadOnlyList<YsmResourceEntry> Backgrounds,
    IReadOnlyList<YsmResourceEntry> SpecialImages,
    byte[]? InfoJson,
    byte[]? YsmJson);

public abstract class YSMParser
{
    public bool Verbose { get; set; }
    public bool Debug { get; set; }
    public bool FormatJson { get; set; }

    public abstract int GetYSGPVersion();
    public abstract void Parse();
    public abstract byte[] GetDecryptedData();
    public abstract void SaveToDirectory(string outputDirectory);
    public abstract void PrintInfo(TextWriter output);
    public abstract YsmResourceData GetResources();
}

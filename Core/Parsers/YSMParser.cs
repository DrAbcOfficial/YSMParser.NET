namespace YSMParser.Core.Parsers;

/// <summary>
/// Represents a single named resource entry (e.g. a model, texture, or animation file).
/// </summary>
/// <param name="Name">The resource file name or relative path.</param>
/// <param name="Data">The raw byte content of the resource.</param>
public sealed record YsmResourceEntry(string Name, byte[] Data);

/// <summary>
/// Holds all parsed resources extracted from a YSM file, organized by category.
/// </summary>
/// <param name="Models">Geometry/model JSON files.</param>
/// <param name="Textures">PNG texture files.</param>
/// <param name="Animations">Animation JSON files.</param>
/// <param name="AnimationControllers">Animation controller JSON files.</param>
/// <param name="Sounds">Sound files (OGG format).</param>
/// <param name="Functions">Molang function files.</param>
/// <param name="Languages">Language/localization JSON files.</param>
/// <param name="Avatars">Author avatar images (PNG).</param>
/// <param name="Backgrounds">Background images (PNG).</param>
/// <param name="SpecialImages">Normal/specular map images (PNG).</param>
/// <param name="InfoJson">Legacy info.json content, or <c>null</c>.</param>
/// <param name="YsmJson">Structured ysm.json manifest content, or <c>null</c>.</param>
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

/// <summary>
/// Abstract base class for all YSM parser versions.
/// Concrete implementations: <see cref="YSMParserV1"/>, <see cref="YSMParserV2"/>, <see cref="YSMParserV3"/>.
/// </summary>
public abstract class YSMParser
{
    /// <summary>Enables verbose console output during parsing.</summary>
    public bool Verbose { get; set; }

    /// <summary>Enables debug output (exports intermediate binary data).</summary>
    public bool Debug { get; set; }

    /// <summary>Enables pretty-printed (indented) JSON output.</summary>
    public bool FormatJson { get; set; }

    /// <summary>Returns the YSGP format version detected for this file.</summary>
    /// <returns>The version number (1, 2, or 3).</returns>
    public abstract int GetYSGPVersion();

    /// <summary>Parses the binary file and extracts all resources.</summary>
    public abstract void Parse();

    /// <summary>Returns the fully decrypted and decompressed binary data.</summary>
    /// <returns>The raw decompressed data buffer.</returns>
    public abstract byte[] GetDecryptedData();

    /// <summary>
    /// Writes all extracted resources to the given output directory.
    /// </summary>
    /// <param name="outputDirectory">The target directory path.</param>
    public abstract void SaveToDirectory(string outputDirectory);

    /// <summary>
    /// Prints metadata and resource information to the given text writer.
    /// </summary>
    /// <param name="output">The output writer (e.g. <see cref="Console.Out"/>).</param>
    public abstract void PrintInfo(TextWriter output);

    /// <summary>
    /// Returns all parsed resources organized by category.
    /// </summary>
    /// <returns>A <see cref="YsmResourceData"/> containing all extracted resources.</returns>
    public abstract YsmResourceData GetResources();
}

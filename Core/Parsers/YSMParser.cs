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
/// Summary information about a model parsed during peek.
/// </summary>
/// <param name="Name">Model file name (e.g. "main", "arm").</param>
/// <param name="Identifier">Geometry identifier (e.g. "geometry.skin").</param>
/// <param name="BoneCount">Number of bones in the model.</param>
/// <param name="TotalCubeCount">Total number of cube elements across all bones.</param>
/// <param name="TextureWidth">Texture width in pixels.</param>
/// <param name="TextureHeight">Texture height in pixels.</param>
public sealed record YsmModelInfo(
    string Name,
    string Identifier,
    int BoneCount,
    int TotalCubeCount,
    float TextureWidth,
    float TextureHeight);

/// <summary>
/// Summary information about an animation parsed during peek.
/// </summary>
/// <param name="Name">Animation name.</param>
/// <param name="Length">Animation length in seconds.</param>
/// <param name="BoneCount">Number of animated bones.</param>
public sealed record YsmAnimationInfo(
    string Name,
    float Length,
    int BoneCount);

/// <summary>
/// Lightweight metadata-only result from <see cref="YSMParser.Peek"/>.
/// Avoids full decryption and resource extraction, saving CPU and memory.
/// </summary>
/// <param name="Version">The YSGP format version (1, 2, or 3).</param>
/// <param name="FileSize">Total file size in bytes.</param>
/// <param name="InfoJson">Legacy info.json content (V3 format &lt; 4, or V1/V2).</param>
/// <param name="YsmJson">Structured ysm.json manifest content (V3 format &gt;= 4, or V1/V2).</param>
/// <param name="ResourceNames">List of resource entry names (V1/V2, or <c>null</c> for V3).</param>
/// <param name="HeaderName">V3 plaintext header &lt;name&gt; tag value.</param>
/// <param name="HeaderAuthors">V3 plaintext header &lt;authors&gt; tag value.</param>
/// <param name="HeaderFormat">V3 plaintext header &lt;format&gt; tag value.</param>
/// <param name="HeaderLicense">V3 plaintext header &lt;license&gt; tag value.</param>
/// <param name="HeaderIsFree">V3 plaintext header &lt;free&gt; tag value.</param>
/// <param name="Models">Per-model summaries (V3 only).</param>
/// <param name="Animations">Per-animation summaries (V3 only).</param>
public sealed record YsmPeekResult(
    int Version,
    long FileSize,
    byte[]? InfoJson,
    byte[]? YsmJson,
    IReadOnlyList<string>? ResourceNames,
    string? HeaderName,
    string? HeaderAuthors,
    int? HeaderFormat,
    string? HeaderLicense,
    bool? HeaderIsFree,
    IReadOnlyList<YsmModelInfo>? Models,
    IReadOnlyList<YsmAnimationInfo>? Animations);

/// <summary>
/// Abstract base class for all YSM parser versions.
/// Concrete implementations: <see cref="YSMParserV1"/>, <see cref="YSMParserV2"/>, <see cref="YSMParserV3"/>.
/// </summary>
public abstract class YSMParser : IDisposable
{
    /// <summary>Enables verbose console output during parsing.</summary>
    public bool Verbose { get; set; }

    /// <summary>Enables debug output (exports intermediate binary data).</summary>
    public bool Debug { get; set; }

    /// <summary>Enables pretty-printed (indented) JSON output.</summary>
    public bool FormatJson { get; set; }

    /// <summary>
    /// Quickly reads metadata from the YSM file without fully decrypting or extracting
    /// all resources. Significantly faster and uses less memory than <see cref="Parse"/>.
    /// </summary>
    /// <returns>A <see cref="YsmPeekResult"/> containing discovered metadata.</returns>
    public abstract YsmPeekResult Peek();

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

    /// <summary>
    /// Releases all managed resources held by this parser instance.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Releases the managed resources used by this parser.
    /// </summary>
    /// <param name="disposing">
    /// <c>true</c> to release both managed and unmanaged resources;
    /// <c>false</c> to release only unmanaged resources.
    /// </param>
    protected virtual void Dispose(bool disposing)
    {
        if (!disposing) return;
    }
}

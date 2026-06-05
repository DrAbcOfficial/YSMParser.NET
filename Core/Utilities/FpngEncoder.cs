using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.PixelFormats;

namespace YSMParser.Core.Utilities;

/// <summary>
/// RGBA-to-PNG encoder used to repack raw texture data. The C++ tool uses
/// <c>fpng</c>; here we use SixLabors.ImageSharp. The output bytes will
/// differ from fpng, but the decoded image is identical.
/// </summary>
public static class FpngEncoder
{
    /// <summary>
    /// Encodes raw RGBA pixel data to a PNG byte array.
    /// Returns an empty array if the input dimensions do not match the data length.
    /// </summary>
    /// <param name="rgba">Raw RGBA pixel data. Length must equal <c>width * height * 4</c>.</param>
    /// <param name="width">Image width in pixels.</param>
    /// <param name="height">Image height in pixels.</param>
    /// <returns>PNG-encoded byte array, or an empty array on mismatch.</returns>
    public static byte[] EncodeRgbaToPng(ReadOnlySpan<byte> rgba, int width, int height)
    {
        if (rgba.Length != width * height * 4)
        {
            return [];
        }

        using var image = Image.LoadPixelData<Rgba32>(rgba, width, height);
        using var ms = new MemoryStream();
        var encoder = new PngEncoder
        {
            ColorType = PngColorType.RgbWithAlpha,
            BitDepth = PngBitDepth.Bit8,
            CompressionLevel = PngCompressionLevel.DefaultCompression,
            FilterMethod = PngFilterMethod.None,
        };
        image.Save(ms, encoder);
        return ms.ToArray();
    }
}

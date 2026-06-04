using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.PixelFormats;

namespace YSMParser.Core;

/// <summary>
/// RGBA-to-PNG encoder used to repack raw texture data. The C++ tool uses
/// <c>fpng</c>; here we use SixLabors.ImageSharp. The output bytes will
/// differ from fpng, but the decoded image is identical.
/// </summary>
public static class Fpng
{
    public static byte[] EncodeRgbaToPng(ReadOnlySpan<byte> rgba, int width, int height)
    {
        if (rgba.Length != width * height * 4)
        {
            return Array.Empty<byte>();
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

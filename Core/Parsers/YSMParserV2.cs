using System.Text;

namespace YSMParser.Core.Parsers;

/// <summary>
/// YSM format V2 parser. Uses AES-CBC decryption with JavaRandom-based key derivation
/// and zlib decompression. Each file entry contains a Base64-encoded filename, data length,
/// encrypted key, IV, and encrypted payload.
/// </summary>
/// <param name="buffer">The raw YSM file bytes.</param>
public sealed class YSMParserV2(byte[] buffer) : YSMParser
{
    private readonly byte[] _buffer = buffer;
    private readonly byte[] _key = new byte[16];
    private readonly Dictionary<string, byte[]> _resources = [];

    /// <inheritdoc />
    public override int GetYSGPVersion() => 2;

    /// <inheritdoc />
    public override byte[] GetDecryptedData() => [];

    /// <inheritdoc />
    public override void Parse()
    {
        if (_buffer.Length == 0) return;

        int offset = 0;
        offset += 8;

        Array.Copy(_buffer, offset, _key, 0, 16);
        offset += 16;

        while (offset < _buffer.Length)
        {
            uint strSize = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;

            string b64 = Encoding.UTF8.GetString(_buffer, offset, (int)strSize);
            string fileName = Base64Decode(b64);
            offset += (int)strSize;

            uint dataLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;

            uint encryptedKeyLength = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;
            if (encryptedKeyLength != 0x20) throw new ParserInvalidFileFormatException();

            byte[] encryptedKey = _buffer.AsSpan(offset, (int)encryptedKeyLength).ToArray();
            offset += (int)encryptedKeyLength;

            byte[] iv = _buffer.AsSpan(offset, 16).ToArray();
            offset += 16;

            byte[] encryptedData = _buffer.AsSpan(offset, (int)dataLen).ToArray();
            offset += (int)dataLen;

            byte[] md5Digest = Md5Util.Hash(encryptedData);
            var jRandom = new JavaRandom(Md5Util.HashToLong(md5Digest));
            byte[] randomKey = new byte[16];
            jRandom.NextBytes(randomKey);

            byte[] realKey = AesUtil.DecryptCbc(encryptedKey, randomKey, iv);
            byte[] decrypted = AesUtil.DecryptCbc(encryptedData, realKey.AsSpan(0, 16), iv);
            byte[] decompressed = ZlibUtil.Decompress(decrypted);

            _resources[fileName] = decompressed;
        }
    }

    /// <inheritdoc />
    public override void SaveToDirectory(string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        foreach (var (fileName, data) in _resources)
        {
            var filePath = Path.Combine(outputDirectory, fileName);
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllBytes(filePath, data);
        }
    }

    /// <inheritdoc />
    public override void PrintInfo(TextWriter output)
    {
        output.WriteLine($"  Version:      2 (AES-CBC + JavaRandom + zlib)");
        output.WriteLine($"  File size:    {_buffer.Length:N0} bytes");

        int offset = 8 + 16; // skip header + key
        output.WriteLine();
        output.WriteLine("  Resources:");

        int index = 0;
        while (offset + 4 < _buffer.Length)
        {
            uint strSize = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;
            string b64 = Encoding.UTF8.GetString(_buffer, offset, (int)strSize);
            string fileName = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            offset += (int)strSize;

            uint dataLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;

            uint encKeyLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4 + (int)encKeyLen + 16 + (int)dataLen; // skip encKey + iv + encryptedData

            output.WriteLine($"    [{++index}] {fileName}  ({dataLen:N0} bytes encrypted)");
        }
    }

    /// <inheritdoc />
    public override YsmResourceData GetResources()
    {
        var models = new List<YsmResourceEntry>();
        var textures = new List<YsmResourceEntry>();
        var animations = new List<YsmResourceEntry>();

        foreach (var (name, data) in _resources)
        {
            if (name.EndsWith(".animation.json", StringComparison.OrdinalIgnoreCase) || name.Contains("animation"))
                animations.Add(new(name, data));
            else if (name.EndsWith(".png", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase))
                textures.Add(new(name, data));
            else if (name.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                models.Add(new(name, data));
            else
                models.Add(new(name, data));
        }

        return new YsmResourceData(
            models, textures, animations,
            [], [], [], [], [], [], [], null, null);
    }

    private static string Base64Decode(string input)
    {
        var bytes = Convert.FromBase64String(input);
        return Encoding.UTF8.GetString(bytes);
    }
}

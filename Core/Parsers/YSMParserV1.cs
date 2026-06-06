using System.Text;

namespace YSMParser.Core.Parsers;

/// <summary>
/// YSM format V1 parser. Uses AES-CBC decryption with per-file keys and zlib decompression.
/// Each file entry contains a filename, data length, AES key, IV, and encrypted payload.
/// </summary>
/// <param name="buffer">The raw YSM file bytes.</param>
public sealed class YSMParserV1(byte[] buffer) : YSMParser
{
    private byte[] _buffer = buffer;
    private byte[] _key = new byte[16];
    private Dictionary<string, byte[]> _resources = [];

    /// <inheritdoc />
    public override int GetYSGPVersion() => 1;

    /// <inheritdoc />
    public override YsmPeekResult Peek()
    {
        var resourceNames = new List<string>();
        byte[]? infoJson = null;
        byte[]? ysmJson = null;

        if (_buffer.Length == 0)
            return new YsmPeekResult(1, 0, null, null, resourceNames, null, null, null, null, null, null, null);

        int offset = 8 + 16;
        while (offset < _buffer.Length)
        {
            uint strSize = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;
            string fileName = Encoding.UTF8.GetString(_buffer, offset, (int)strSize);
            offset += (int)strSize;

            uint dataLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;

            resourceNames.Add(fileName);

            byte[] aesKey = _buffer.AsSpan(offset, 16).ToArray();
            offset += 16;

            byte[] iv = _buffer.AsSpan(offset, 16).ToArray();
            offset += 16;

            byte[] encrypted = _buffer.AsSpan(offset, (int)dataLen).ToArray();
            offset += (int)dataLen;

            if (fileName.Equals("ysm.json", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("info.json", StringComparison.OrdinalIgnoreCase))
            {
                byte[] decrypted = AesUtil.DecryptCbc(encrypted, aesKey, iv);
                byte[] decompressed = ZlibUtil.Decompress(decrypted);

                if (fileName.Equals("ysm.json", StringComparison.OrdinalIgnoreCase))
                    ysmJson = decompressed;
                else
                    infoJson = decompressed;
            }
        }

        return new YsmPeekResult(1, _buffer.Length, infoJson, ysmJson, resourceNames, null, null, null, null, null, null, null);
    }

    /// <inheritdoc />
    public override byte[] GetDecryptedData() => [];

    /// <inheritdoc />
    protected override void Dispose(bool disposing)
    {
        if (!disposing) return;
        _resources.Clear();
        _resources = null!;
        _buffer = null!;
        _key = null!;
    }

    /// <inheritdoc />
    public override void Parse()
    {
        if (_buffer.Length == 0) return;

        int offset = 0;
        // Skip 8-byte header (YSGP magic + crypto version).
        offset += 8;

        Array.Copy(_buffer, offset, _key, 0, 16);
        offset += 16;

        while (offset < _buffer.Length)
        {
            uint strSize = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;
            string fileName = Encoding.UTF8.GetString(_buffer, offset, (int)strSize);
            offset += (int)strSize;

            uint dataLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;

            byte[] aesKey = _buffer.AsSpan(offset, 16).ToArray();
            offset += 16;

            byte[] iv = _buffer.AsSpan(offset, 16).ToArray();
            offset += 16;

            byte[] encrypted = _buffer.AsSpan(offset, (int)dataLen).ToArray();
            offset += (int)dataLen;

            byte[] decrypted = AesUtil.DecryptCbc(encrypted, aesKey, iv);
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
        output.WriteLine($"  Version:      1 (AES-CBC + zlib)");
        output.WriteLine($"  File size:    {_buffer.Length:N0} bytes");

        int offset = 8 + 16; // skip header + key
        output.WriteLine();
        output.WriteLine("  Resources:");

        int index = 0;
        while (offset + 4 < _buffer.Length)
        {
            uint strSize = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4;
            string fileName = Encoding.UTF8.GetString(_buffer, offset, (int)strSize);
            offset += (int)strSize;

            uint dataLen = MemoryUtils.ReadBE<uint>(_buffer.AsSpan(offset));
            offset += 4 + 16 + 16 + (int)dataLen; // skip dataLen + aesKey + iv + encryptedData

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
}

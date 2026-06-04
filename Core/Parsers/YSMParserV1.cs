using System.Text;
using YSMParser.Core.Crypto;
using YSMParser.Core.Utilities;

namespace YSMParser.Core.Parsers;

public sealed class YSMParserV1(byte[] buffer) : YSMParser
{
    private readonly byte[] _buffer = buffer;
    private readonly byte[]? _decryptedData;
    private readonly byte[] _key = new byte[16];
    private readonly Dictionary<string, byte[]> _resources = [];

    public override int GetYSGPVersion() => 1;

    public override byte[] GetDecryptedData() => _decryptedData ?? [];

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
}

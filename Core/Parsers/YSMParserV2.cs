using System.Text;
using YSMParser.Core.Crypto;
using YSMParser.Core.Utilities;

namespace YSMParser.Core.Parsers;

public sealed class YSMParserV2(byte[] buffer) : YSMParser
{
    private readonly byte[] _buffer = buffer;
    private readonly byte[]? _decryptedData;
    private readonly byte[] _key = new byte[16];
    private readonly Dictionary<string, byte[]> _resources = [];

    public override int GetYSGPVersion() => 2;

    public override byte[] GetDecryptedData() => _decryptedData ?? [];

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

    private static string Base64Decode(string input)
    {
        var bytes = Convert.FromBase64String(input);
        return Encoding.UTF8.GetString(bytes);
    }
}

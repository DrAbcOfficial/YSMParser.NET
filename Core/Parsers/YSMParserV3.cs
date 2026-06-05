using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Buffers.Binary;
using YSMParser.Core.Crypto;
using YSMParser.Core.Utilities;

namespace YSMParser.Core.Parsers;

public sealed class YSMParserV3(byte[] buffer) : YSMParser
{
    private readonly byte[] _buffer = buffer;
    private string _header = string.Empty;
    private readonly byte[] _key = new byte[32];
    private readonly byte[] _iv = new byte[24];
    private ulong _fileHash;
    private byte[] _binaryData = [];
    private byte[] _decrypted = [];
    private byte[] _decompressed = [];

    private int _format;
    private readonly Dictionary<string, string> _subEntityCategories = [];

    private readonly List<(string Name, byte[] Data)> _soundFiles = [];
    private readonly List<(string Name, byte[] Data)> _functionFiles = [];
    private readonly List<(string Name, byte[] Data)> _languageFiles = [];
    private readonly List<(string Name, byte[] Data)> _animControllerFiles = [];
    private readonly List<(string Name, byte[] Data)> _textureFiles = [];
    private readonly List<(string Name, byte[] Data)> _avatarFiles = [];
    private readonly List<(string Name, byte[] Data)> _modelFiles = [];
    private readonly List<(string Name, byte[] Data)> _animationFiles = [];
    private readonly List<(string Name, byte[] Data)> _specialImageFiles = [];
    private readonly List<(string Name, byte[] Data)> _backgroundFiles = [];
    private byte[] _infoJsonFile = [];
    private byte[] _ysmJsonFile = [];

    public override int GetYSGPVersion() => 3;
    public override byte[] GetDecryptedData() => _decompressed;

    public override void Parse()
    {
        _binaryData = [];

        // Find the null-terminated boundary in raw bytes.
        int nulIdx = -1;
        for (int i = 0; i < _buffer.Length; i++)
        {
            if (_buffer[i] == 0)
            {
                nulIdx = i;
                break;
            }
        }
        if (nulIdx < 0) throw new ParserInvalidFileFormatException();
        int headerByteEnd = nulIdx;
        _header = Encoding.UTF8.GetString(_buffer, 0, headerByteEnd);

        _format = ExtractFormatFromHeader(_header);
        if (_buffer.Length < 8 + 24 + 32 + 8)
        {
            throw new ParserInvalidFileFormatException();
        }

        int tailStart = _buffer.Length - 64;
        Array.Copy(_buffer, tailStart, _key, 0, 32);
        Array.Copy(_buffer, tailStart + 32, _iv, 0, 24);
        _fileHash = MemoryUtils.ReadLE<ulong>(_buffer.AsSpan(_buffer.Length - 8));

        int binaryStart = headerByteEnd + 1;
        if (binaryStart + 4 > _buffer.Length - 64)
        {
            throw new ParserInvalidFileFormatException();
        }
        uint crypto = MemoryUtils.ReadLE<uint>(_buffer.AsSpan(binaryStart));
        if (crypto != 3) throw new ParserInvalidFileFormatException();

        ulong fileHash = CityHash64.CityHash64WithSeed(_buffer, _buffer.Length - 8, YsmCrypto.SEED_FILE_VERIFICATION);
        if (fileHash != _fileHash) throw new ParserCorruptedDataException();

        int binaryDataStart = binaryStart + 4;
        int binaryDataLength = _buffer.Length - 64 - binaryDataStart;
        _binaryData = new byte[binaryDataLength];
        Array.Copy(_buffer, binaryDataStart, _binaryData, 0, binaryDataLength);

        byte[] chachaDecrypted = YsmCrypto.ModifiedChaChaDecrypt(_binaryData, _key, _iv, YsmCrypto.SEED_RES_VERIFICATION);
        byte[] xorredData = YsmCrypto.MT19937XorDecrypt(chachaDecrypted, _key, _iv);

        ushort n = BinaryPrimitives.ReadUInt16LittleEndian(xorredData);
        n &= 0x3FF;
        _decrypted = new byte[xorredData.Length - 2 - n];
        Array.Copy(xorredData, 2 + n, _decrypted, 0, _decrypted.Length);

        _decompressed = YsmCrypto.DecompressZstd(_decrypted);

        if (Verbose)
        {
            Console.Error.WriteLine($"Start Parse Files (format = {_format})");
        }

        Deserialize(_decompressed, _decompressed.Length);
    }

    private static int ExtractFormatFromHeader(string headerData)
    {
        const string tag = "<format>";
        int pos = headerData.IndexOf(tag, StringComparison.Ordinal);
        if (pos < 0) throw new ParserInvalidFileFormatException();
        pos += tag.Length;
        while (pos < headerData.Length && (headerData[pos] == ' ' || headerData[pos] == '\t'))
        {
            pos++;
        }
        int end = pos;
        while (end < headerData.Length && headerData[end] >= '0' && headerData[end] <= '9')
        {
            end++;
        }
        if (end == pos) throw new ParserInvalidFileFormatException();
        return int.Parse(headerData.AsSpan(pos, end - pos), CultureInfo.InvariantCulture);
    }

    // ============== JSON helpers ==============

    private static string FormatNumber(float v)
    {
        if (MathF.Abs(v) < 1e-9f) return "0.0";
        // Match C++ clean_number: round to 5 decimal places first
        float r = MathF.Round(v * 100000f) / 100000f;
        if (MathF.Abs(r - MathF.Round(r)) < 1e-6f) return MathF.Round(r).ToString("0.0", CultureInfo.InvariantCulture);
        var s = r.ToString("0.######", CultureInfo.InvariantCulture);
        if (!s.Contains('.')) s += ".0";
        return s;
    }

    private static string FormatTime(float v)
    {
        if (MathF.Abs(v) < 1e-6f) return "0.0";
        string s = v.ToString("F6", CultureInfo.InvariantCulture);
        s = s.TrimEnd('0');
        if (s.Length > 0 && s[^1] == '.') s += "0";
        return s;
    }

    private static string DumpJson(JsonNode? node, bool pretty)
    {
        if (node is null) return "null";
        var options = new JsonSerializerOptions
        {
            WriteIndented = pretty,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return node.ToJsonString(options);
    }

    private static void CleanJsonFloats(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            foreach (var kvp in obj.ToList())
            {
                var v = kvp.Value;
                if (v is JsonValue jv && jv.TryGetValue<double>(out var d))
                {
                    obj[kvp.Key] = JsonValue.Create(Math.Round(d * 100000.0) / 100000.0);
                }
                else
                {
                    CleanJsonFloats(v);
                }
            }
        }
        else if (node is JsonArray arr)
        {
            for (int i = 0; i < arr.Count; i++)
            {
                var v = arr[i];
                if (v is JsonValue jv && jv.TryGetValue<double>(out var d))
                {
                    arr[i] = JsonValue.Create(Math.Round(d * 100000.0) / 100000.0);
                }
                else
                {
                    CleanJsonFloats(v);
                }
            }
        }
    }

    private static string SanitizeWindowsFilename(string filename, char replacement = '_')
    {
        var invalid = System.IO.Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(filename.Length);
        foreach (char c in filename)
        {
            sb.Append(invalid.Contains(c) ? replacement : c);
        }
        while (sb.Length > 0 && (sb[^1] == ' ' || sb[^1] == '.'))
        {
            sb.Length--;
        }
        return sb.Length == 0 ? "unnamed_file" : sb.ToString();
    }

    // ============== Animation deserialization ==============

    private enum LerpMode : byte
    {
        Linear = 0,
        Step = 1,
        Catmullrom = 2,
    }

    private enum LoopMode : byte
    {
        Once = 0,
        Loop = 1,
        Unk2 = 2,
        HoldOnLastFrame = 3,
    }

    private sealed class MolangValue
    {
        public float? Float;
        public string? Str;
        public bool IsFloat => Float.HasValue;

        public MolangValue(float f) { Float = f; }
        public MolangValue(string s) { Str = s; }

        public string ToJson()
        {
            if (IsFloat)
            {
                float f = Float!.Value;
                if (MathF.Abs(f) < 1e-6f) return "0.0";
                var s = f.ToString("0.######", CultureInfo.InvariantCulture);
                if (!s.Contains('.')) s += ".0";
                return s;
            }
            return "\"" + EscapeJsonString(Str!) + "\"";
        }
    }

    private static string EscapeJsonString(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append($"\\u{(int)c:x4}");
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    private sealed class MolangPair
    {
        public MolangValue[] M = new MolangValue[3];

        public string ToJson()
        {
            if (M[0].IsFloat && M[1].IsFloat && M[2].IsFloat)
            {
                float f0 = M[0].Float!.Value, f1 = M[1].Float!.Value, f2 = M[2].Float!.Value;
                if (MathF.Abs(f0 - f1) < 1e-6f && MathF.Abs(f1 - f2) < 1e-6f)
                {
                    return M[0].ToJson();
                }
            }
            else if (!M[0].IsFloat && !M[1].IsFloat && !M[2].IsFloat)
            {
                if (M[0].Str == M[1].Str && M[1].Str == M[2].Str)
                {
                    return "\"" + EscapeJsonString(M[0].Str!) + "\"";
                }
            }
            var sb = new StringBuilder("[");
            for (int i = 0; i < 3; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(M[i].ToJson());
            }
            sb.Append(']');
            return sb.ToString();
        }
    }

    private sealed class Keyframe
    {
        public MolangPair Post = new();
        public MolangPair? Pre;
        public LerpMode LerpMode = LerpMode.Linear;
    }

    private sealed class BonesKeyFrame
    {
        public List<(float Time, Keyframe Bone)> Frames = [];
    }

    private sealed class Effects
    {
        public List<(float Time, string Name)> Events = [];
    }

    private sealed class TimeLine
    {
        public List<(float Time, List<string> Events)> Groups = [];
    }

    private static MolangValue ReadMolangValue(BufferReader reader)
    {
        byte type = reader.ReadByte();
        if (type == 0x01) return new MolangValue(reader.ReadFloat());
        if (type == 0x02) return new MolangValue(reader.ReadString());
        throw new ParserUnknownFieldException();
    }

    private static MolangPair ReadMolangPair(BufferReader reader)
    {
        var pair = new MolangPair();
        for (int i = 0; i < 3; i++) pair.M[i] = ReadMolangValue(reader);
        return pair;
    }

    private static BonesKeyFrame? ParseChannel(BufferReader reader)
    {
        uint molangs = (uint)reader.ReadVarint();
        if (molangs == 0) return null;

        var kf = new BonesKeyFrame();
        for (uint i = 0; i < molangs; i++)
        {
            float time = reader.ReadFloat() / 20f;
            LerpMode lerp = (LerpMode)reader.ReadVarint();
            var first = ReadMolangPair(reader);

            uint hasPre = (uint)reader.ReadVarint();
            if (hasPre >= 2) throw new ParserUnknownFieldException();
            if (hasPre == 1)
            {
                var second = ReadMolangPair(reader);
                var key = new Keyframe { Post = second, Pre = first, LerpMode = lerp };
                kf.Frames.Add((time, key));
            }
            else
            {
                var key = new Keyframe { Post = first, LerpMode = lerp };
                kf.Frames.Add((time, key));
            }
        }
        return kf;
    }

    private static Effects? ParseEffect(BufferReader reader)
    {
        uint header = (uint)reader.ReadVarint();
        if (header == 0) return null;
        var eff = new Effects();
        for (uint i = 0; i < header; i++)
        {
            string effect = reader.ReadString();
            float time = reader.ReadFloat() / 20f;
            eff.Events.Add((time, effect));
        }
        return eff;
    }

    private static TimeLine? ParseTimeLine(BufferReader reader)
    {
        uint header = (uint)reader.ReadVarint();
        if (header == 0) return null;
        var tl = new TimeLine();
        for (uint i = 0; i < header; i++)
        {
            uint inner = (uint)reader.ReadVarint();
            var list = new List<string>((int)inner);
            for (uint j = 0; j < inner; j++) list.Add(reader.ReadString());
            float time = reader.ReadFloat() / 20f;
            tl.Groups.Add((time, list));
        }
        return tl;
    }

    private static string ChannelToJson(BonesKeyFrame? channel)
    {
        if (channel == null || channel.Frames.Count == 0) return "null";
        if (channel.Frames.Count == 1 && MathF.Abs(channel.Frames[0].Time) < 1e-6f
            && channel.Frames[0].Bone.Pre == null
            && channel.Frames[0].Bone.LerpMode == LerpMode.Linear)
        {
            return channel.Frames[0].Bone.Post.ToJson();
        }

        var sb = new StringBuilder("{");
        for (int i = 0; i < channel.Frames.Count; i++)
        {
            var (time, kf) = channel.Frames[i];
            if (i > 0) sb.Append(',');
            sb.Append('"').Append(FormatTime(time)).Append("\":");

            if (kf.Pre == null && kf.LerpMode == LerpMode.Linear)
            {
                sb.Append(kf.Post.ToJson());
            }
            else
            {
                sb.Append('{');
                bool first;
                if (kf.Pre != null)
                {
                    sb.Append("\"post\":").Append(kf.Post.ToJson()).Append(",\"pre\":").Append(kf.Pre.ToJson());
                    first = false;
                }
                else
                {
                    sb.Append("\"post\":").Append(kf.Post.ToJson());
                    first = false;
                }
                if (kf.LerpMode == LerpMode.Step)
                {
                    if (!first) sb.Append(',');
                    sb.Append("\"lerp_mode\":\"step\"");
                }
                else if (kf.LerpMode == LerpMode.Catmullrom)
                {
                    if (!first) sb.Append(',');
                    sb.Append("\"lerp_mode\":\"catmullrom\"");
                }
                sb.Append('}');
            }
        }
        sb.Append('}');
        return sb.ToString();
    }

    // ============== Models deserialization ==============

    private sealed class ParsedDescription
    {
        public string Identifier = string.Empty;
        public float TextureWidth, TextureHeight;
        public float VisibleBoundsWidth, VisibleBoundsHeight;
        public List<float> VisibleBoundsOffset = [];
    }

    private sealed class ParsedBone
    {
        public string Parent = string.Empty;
        public string Name = string.Empty;
        public Vector3D Pivot;
        public Vector3D Rotation;
        public List<List<Face>> Cubes = [];
    }

    private sealed class ParsedModel
    {
        public string Sha256 = string.Empty;
        public ParsedDescription Description = new();
        public List<ParsedBone> Bones = [];
    }

    public struct Face
    {
        public Vector3D Normal;
        public Vertex V0, V1, V2, V3;
    }

    public struct Vertex
    {
        public Vector3D Vec;
        public float U;
        public float V;
    }

    private byte[] ParseModels(BufferReader reader)
    {
        var model = new ParsedModel();
        if (_format > 15)
        {
            model.Sha256 = reader.ReadString();
        }
        uint sizeOfBones = (uint)reader.ReadVarint();
        for (uint i = 0; i < sizeOfBones; i++)
        {
            var bone = new ParsedBone { Parent = reader.ReadString() };
            uint cubesSize = (uint)reader.ReadVarint();
            for (uint j = 0; j < cubesSize; j++)
            {
                var faces = new List<Face>();
                uint uvSize = (uint)reader.ReadVarint();
                for (uint k = 0; k < uvSize; k++)
                {
                    var face = new Face
                    {
                        Normal = reader.ReadVector3D(),
                        V0 = new Vertex { Vec = reader.ReadVector3D(), U = reader.ReadFloat(), V = reader.ReadFloat() },
                        V1 = new Vertex { Vec = reader.ReadVector3D(), U = reader.ReadFloat(), V = reader.ReadFloat() },
                        V2 = new Vertex { Vec = reader.ReadVector3D(), U = reader.ReadFloat(), V = reader.ReadFloat() },
                        V3 = new Vertex { Vec = reader.ReadVector3D(), U = reader.ReadFloat(), V = reader.ReadFloat() }
                    };
                    faces.Add(face);
                }
                bone.Cubes.Add(faces);

                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
            }

            bone.Name = reader.ReadString();

            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();

            bone.Pivot = new Vector3D(reader.ReadFloat(), reader.ReadFloat(), reader.ReadFloat());
            bone.Rotation = new Vector3D(reader.ReadFloat(), reader.ReadFloat(), reader.ReadFloat());

            model.Bones.Add(bone);
        }

        model.Description.Identifier = reader.ReadString();
        model.Description.TextureHeight = reader.ReadFloat();
        model.Description.TextureWidth = reader.ReadFloat();
        model.Description.VisibleBoundsHeight = reader.ReadFloat();
        model.Description.VisibleBoundsWidth = reader.ReadFloat();

        uint visibleBoundsOffsetSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < visibleBoundsOffsetSize; i++)
        {
            model.Description.VisibleBoundsOffset.Add(reader.ReadFloat());
        }

        _ = reader.ReadFloat();
        _ = reader.ReadFloat();

        uint hasInfoJson = (uint)reader.ReadVarint();
        if (hasInfoJson > 0)
        {
            ParseLegacyYSMInfo(reader);
        }

        _ = reader.ReadVarint();
        _ = reader.ReadVarint();
        _ = reader.ReadVarint();

        var sb = new StringBuilder();
        sb.Append("{\"format_version\":\"1.12.0\",\"minecraft:geometry\":[{\"description\":{");
        sb.Append("\"identifier\":\"").Append(EscapeJsonString(model.Description.Identifier)).Append("\",");
        sb.Append("\"texture_width\":").Append(FormatNumber(model.Description.TextureWidth)).Append(',');
        sb.Append("\"texture_height\":").Append(FormatNumber(model.Description.TextureHeight)).Append(',');
        sb.Append("\"visible_bounds_width\":").Append(FormatNumber(model.Description.VisibleBoundsWidth)).Append(',');
        sb.Append("\"visible_bounds_height\":").Append(FormatNumber(model.Description.VisibleBoundsHeight)).Append(',');
        sb.Append("\"visible_bounds_offset\":[");
        for (int i = 0; i < model.Description.VisibleBoundsOffset.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(FormatNumber(model.Description.VisibleBoundsOffset[i]));
        }
        sb.Append("]},\"bones\":[");

        for (int bi = 0; bi < model.Bones.Count; bi++)
        {
            var bone = model.Bones[bi];
            if (bi > 0) sb.Append(',');
            sb.Append("{\"name\":\"").Append(EscapeJsonString(bone.Name)).Append("\",");
            sb.Append("\"pivot\":[")
                .Append(FormatNumber(-bone.Pivot.X)).Append(',')
                .Append(FormatNumber(bone.Pivot.Y)).Append(',')
                .Append(FormatNumber(bone.Pivot.Z)).Append(']');

            if (!string.IsNullOrEmpty(bone.Parent))
            {
                sb.Append(",\"parent\":\"").Append(EscapeJsonString(bone.Parent)).Append('"');
            }

            float rx = -bone.Rotation.X * (180f / MathF.PI);
            float ry = -bone.Rotation.Y * (180f / MathF.PI);
            float rz = bone.Rotation.Z * (180f / MathF.PI);
            if (MathF.Abs(rx) > 1e-6f || MathF.Abs(ry) > 1e-6f || MathF.Abs(rz) > 1e-6f)
            {
                sb.Append(",\"rotation\":[")
                    .Append(FormatNumber(rx)).Append(',')
                    .Append(FormatNumber(ry)).Append(',')
                    .Append(FormatNumber(rz)).Append(']');
            }

            var cubes = new List<string>();
            foreach (var cubeFaces in bone.Cubes)
            {
                try
                {
                    var bbCube = RestoreBlockbenchCube(cubeFaces, 0f, (int)model.Description.TextureWidth, (int)model.Description.TextureHeight);
                    var cube = new StringBuilder("{");
                    cube.Append("\"origin\":[")
                        .Append(FormatNumber(bbCube.Origin.X)).Append(',')
                        .Append(FormatNumber(bbCube.Origin.Y)).Append(',')
                        .Append(FormatNumber(bbCube.Origin.Z)).Append("],");
                    cube.Append("\"size\":[")
                        .Append(FormatNumber(bbCube.Size.X)).Append(',')
                        .Append(FormatNumber(bbCube.Size.Y)).Append(',')
                        .Append(FormatNumber(bbCube.Size.Z)).Append("],");
                    cube.Append("\"pivot\":[")
                        .Append(FormatNumber(bbCube.Pivot.X)).Append(',')
                        .Append(FormatNumber(bbCube.Pivot.Y)).Append(',')
                        .Append(FormatNumber(bbCube.Pivot.Z)).Append("],");
                    cube.Append("\"rotation\":[")
                        .Append(FormatNumber(bbCube.Rotation.X)).Append(',')
                        .Append(FormatNumber(bbCube.Rotation.Y)).Append(',')
                        .Append(FormatNumber(bbCube.Rotation.Z)).Append("],");
                    cube.Append("\"uv\":{");
                    int uvi = 0;
                    foreach (var kv in bbCube.Uv)
                    {
                        if (uvi++ > 0) cube.Append(',');
                        cube.Append('"').Append(EscapeJsonString(kv.Key)).Append("\":{\"uv\":[")
                            .Append(FormatNumber(kv.Value.U)).Append(',')
                            .Append(FormatNumber(kv.Value.V)).Append("],\"uv_size\":[")
                            .Append(FormatNumber(kv.Value.USize)).Append(',')
                            .Append(FormatNumber(kv.Value.VSize)).Append("]}");
                    }
                    cube.Append("}}");
                    cubes.Add(cube.ToString());
                }
                catch
                {
                    // Ignore problematic cubes, matching the C++ behavior.
                }
            }
            if (cubes.Count > 0)
            {
                sb.Append(",\"cubes\":[");
                sb.Append(string.Join(",", cubes));
                sb.Append(']');
            }
            sb.Append('}');
        }
        sb.Append("]}]}");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private struct BlockbenchCube
    {
        public Vector3D Origin;
        public Vector3D Size;
        public Vector3D Pivot;
        public Vector3D Rotation;
        public Dictionary<string, UVBox> Uv;
        public float Inflate;

        public BlockbenchCube()
        {
            Uv = [];
        }
    }

    private struct UVBox
    {
        public float U, V, USize, VSize;
        public UVBox(float u, float v, float uSize, float vSize)
        {
            U = u; V = v; USize = uSize; VSize = vSize;
        }
    }

    private static float CleanVal(float v) => MathF.Round(v * 10000f) / 10000f;

    private static float Dot(Vector3D a, Vector3D b) => a.X * b.X + a.Y * b.Y + a.Z * b.Z;

    private static Vector3D Cross(Vector3D a, Vector3D b) =>
        new(a.Y * b.Z - a.Z * b.Y, a.Z * b.X - a.X * b.Z, a.X * b.Y - a.Y * b.X);

    private static float Length(Vector3D a) => MathF.Sqrt(Dot(a, a));

    private static Vector3D Normalize(Vector3D a)
    {
        float l = Length(a);
        return l > 1e-8f ? new Vector3D(a.X / l, a.Y / l, a.Z / l) : Vector3D.Zero;
    }

    private struct FaceInfo
    {
        public Vector3D NW;
        public Vector3D TU;
        public Vector3D TV;
        public Face RawF;
    }

    private struct Matrix3x3
    {
        public Vector3D Col0, Col1, Col2;

        public float Det() => Dot(Col0, Cross(Col1, Col2));

        public Vector3D TransposeMul(Vector3D v) =>
            new(Dot(Col0, v), Dot(Col1, v), Dot(Col2, v));
    }

    private static Vector3D MatrixToEulerXyz(Matrix3x3 m)
    {
        // col0 = R00,R10,R20; col1 = R01,R11,R21; col2 = R02,R12,R22
        float sy = MathF.Sqrt(m.Col0.X * m.Col0.X + m.Col0.Y * m.Col0.Y);
        bool singular = sy < 1e-6f;
        float xRad, yRad, zRad;

        if (!singular)
        {
            xRad = MathF.Atan2(m.Col1.Z, m.Col2.Z);  // atan2(R21, R22)
            yRad = MathF.Atan2(-m.Col0.Z, sy);       // atan2(-R20, sy)
            zRad = MathF.Atan2(m.Col0.Y, m.Col0.X);  // atan2(R10, R00)
        }
        else
        {
            xRad = MathF.Atan2(-m.Col2.Y, m.Col1.Y); // atan2(-R12, R11)
            yRad = MathF.Atan2(-m.Col0.Z, sy);
            zRad = 0f;
        }

        float radToDeg = 180f / MathF.PI;
        return new Vector3D(xRad * radToDeg, yRad * radToDeg, zRad * radToDeg);
    }

    private static void GetExpectedUVDirs(Vector3D localNormal, out Vector3D expU, out Vector3D expV)
    {
        var n = new Vector3D(MathF.Round(localNormal.X), MathF.Round(localNormal.Y), MathF.Round(localNormal.Z));
        if (n.X == -1f) { expU = new Vector3D(0, 0, 1);  expV = new Vector3D(0, -1, 0); return; }
        if (n.X == 1f)  { expU = new Vector3D(0, 0, -1); expV = new Vector3D(0, -1, 0); return; }
        if (n.Y == 1f)  { expU = new Vector3D(-1, 0, 0); expV = new Vector3D(0, 0, -1); return; }
        if (n.Y == -1f) { expU = new Vector3D(-1, 0, 0); expV = new Vector3D(0, 0, 1);  return; }
        if (n.Z == -1f) { expU = new Vector3D(-1, 0, 0); expV = new Vector3D(0, -1, 0); return; }
        if (n.Z == 1f)  { expU = new Vector3D(1, 0, 0);  expV = new Vector3D(0, -1, 0); return; }
        expU = Vector3D.Zero;
        expV = Vector3D.Zero;
    }

    private static BlockbenchCube RestoreBlockbenchCube(List<Face> facesData, float originalInflate, int textureWidth, int textureHeight)
    {
        var uniquePts = new List<(float X, float Y, float Z)>();
        var faceInfos = new List<FaceInfo>();
        var candidateAxes = new List<Vector3D>();

        static bool Vector3DLessThan((float X, float Y, float Z) a, (float X, float Y, float Z) b)
        {
            if (MathF.Abs(a.X - b.X) >= 1e-4f) return a.X < b.X;
            if (MathF.Abs(a.Y - b.Y) >= 1e-4f) return a.Y < b.Y;
            if (MathF.Abs(a.Z - b.Z) >= 1e-4f) return a.Z < b.Z;
            return false;
        }

        static void AddToSortedSet(List<(float X, float Y, float Z)> set, (float X, float Y, float Z) item)
        {
            for (int i = 0; i < set.Count; i++)
            {
                if (!Vector3DLessThan(set[i], item) && !Vector3DLessThan(item, set[i]))
                    return;
                if (Vector3DLessThan(item, set[i]))
                {
                    set.Insert(i, item);
                    return;
                }
            }
            set.Add(item);
        }

        foreach (var f in facesData)
        {
            var verts = new Vector3D[4];
            for (int i = 0; i < 4; i++)
            {
                verts[i] = f.V0.Vec * 16f;
                if (i == 1) verts[i] = f.V1.Vec * 16f;
                if (i == 2) verts[i] = f.V2.Vec * 16f;
                if (i == 3) verts[i] = f.V3.Vec * 16f;
                var p4 = new Vector3D(
                    MathF.Round(verts[i].X * 10000f) / 10000f,
                    MathF.Round(verts[i].Y * 10000f) / 10000f,
                    MathF.Round(verts[i].Z * 10000f) / 10000f);
                AddToSortedSet(uniquePts, (p4.X, p4.Y, p4.Z));
            }

            var nW = f.Normal;
            var tU = Vector3D.Zero;
            var tV = Vector3D.Zero;

            for (int i = 0; i < 4; i++)
            {
                int j = (i + 1) % 4;
                var vi = i == 0 ? f.V0 : i == 1 ? f.V1 : i == 2 ? f.V2 : f.V3;
                var vj = j == 0 ? f.V0 : j == 1 ? f.V1 : j == 2 ? f.V2 : f.V3;
                var viScaled = vi.Vec * 16f;
                var vjScaled = vj.Vec * 16f;
                var dx = viScaled - vjScaled;
                float du = vi.U - vj.U;
                float dv = vi.V - vj.V;
                float lenDx = MathF.Sqrt(dx.X * dx.X + dx.Y * dx.Y + dx.Z * dx.Z);
                if (lenDx < 1e-5f) continue;

                if (MathF.Abs(du) > 1e-5f && MathF.Abs(dv) < 1e-5f)
                {
                    float sign = du > 0 ? 1f : -1f;
                    tU = dx * (sign / lenDx);
                }
                if (MathF.Abs(dv) > 1e-5f && MathF.Abs(du) < 1e-5f)
                {
                    float sign = dv > 0 ? 1f : -1f;
                    tV = dx * (sign / lenDx);
                }
            }

            faceInfos.Add(new FaceInfo { NW = nW, TU = tU, TV = tV, RawF = f });

            candidateAxes.Add(nW);
            if (Length(tU) > 0.5f) candidateAxes.Add(tU);
            if (Length(tV) > 0.5f) candidateAxes.Add(tV);
        }

        // Deduplicate axes (max 3)
        var rawAxes = new List<Vector3D>();
        foreach (var vec in candidateAxes)
        {
            var vecNorm = Normalize(vec);
            if (Length(vecNorm) < 1e-8f) continue;
            bool exists = false;
            foreach (var a in rawAxes)
            {
                if (MathF.Abs(Dot(vecNorm, a)) > 0.95f) { exists = true; break; }
            }
            if (!exists) rawAxes.Add(vecNorm);
            if (rawAxes.Count == 3) break;
        }

        if (rawAxes.Count == 1)
        {
            var n = rawAxes[0];
            var temp = MathF.Abs(n.X) < 0.9f ? new Vector3D(1, 0, 0) : new Vector3D(0, 1, 0);
            var u = Normalize(Cross(n, temp));
            rawAxes.Add(u);
            rawAxes.Add(Normalize(Cross(n, u)));
        }
        else if (rawAxes.Count == 2)
        {
            var w = Cross(rawAxes[0], rawAxes[1]);
            if (Length(w) > 1e-5f) rawAxes.Add(Normalize(w));
        }
        else if (rawAxes.Count == 0)
        {
            rawAxes.Add(new Vector3D(1, 0, 0));
            rawAxes.Add(new Vector3D(0, 1, 0));
            rawAxes.Add(new Vector3D(0, 0, 1));
        }

        // Rotation matrix search (matching C++ score based on UV tangents alignment)
        float bestScore = float.NegativeInfinity;
        Matrix3x3 bestRotMatrix = default;
        Vector3D bestEuler = Vector3D.Zero;
        float minEulerSum = float.PositiveInfinity;

        int[][] perms = { [0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0] };
        float[][] signs = { [1, 1, 1], [1, 1, -1], [1, -1, 1], [1, -1, -1], [-1, 1, 1], [-1, 1, -1], [-1, -1, 1], [-1, -1, -1] };

        foreach (var p in perms)
        {
            foreach (var s in signs)
            {
                Matrix3x3 mat;
                mat.Col0 = rawAxes[p[0]] * s[0];
                mat.Col1 = rawAxes[p[1]] * s[1];
                mat.Col2 = rawAxes[p[2]] * s[2];

                if (mat.Det() < 0.9f) continue;

                Matrix3x3 rotMat;
                rotMat.Col0 = Normalize(mat.Col0);
                var projOn0 = rotMat.Col0 * Dot(mat.Col1, rotMat.Col0);
                rotMat.Col1 = Normalize(mat.Col1 - projOn0);
                rotMat.Col2 = Normalize(Cross(rotMat.Col0, rotMat.Col1));

                float score = 0f;
                foreach (var info in faceInfos)
                {
                    var nLocal = rotMat.TransposeMul(info.NW);
                    var tULocal = rotMat.TransposeMul(info.TU);
                    var tVLocal = rotMat.TransposeMul(info.TV);

                    GetExpectedUVDirs(nLocal, out var expU, out var expV);

                    score += MathF.Abs(Dot(tULocal, expU));
                    score += MathF.Abs(Dot(tVLocal, expV));
                }

                var euler = MatrixToEulerXyz(rotMat);
                float eulerSum = MathF.Abs(euler.X) + MathF.Abs(euler.Y) + MathF.Abs(euler.Z);

                if (score > bestScore + 1e-4f)
                {
                    bestScore = score;
                    bestRotMatrix = rotMat;
                    bestEuler = euler;
                    minEulerSum = eulerSum;
                }
                else if (MathF.Abs(score - bestScore) <= 1e-4f && eulerSum < minEulerSum)
                {
                    bestRotMatrix = rotMat;
                    bestEuler = euler;
                    minEulerSum = eulerSum;
                }
            }
        }

        // Local-space AABB to get center
        float localMinX = float.PositiveInfinity, localMinY = float.PositiveInfinity, localMinZ = float.PositiveInfinity;
        float localMaxX = float.NegativeInfinity, localMaxY = float.NegativeInfinity, localMaxZ = float.NegativeInfinity;

        foreach (var (px, py, pz) in uniquePts)
        {
            var pt = new Vector3D(px, py, pz);
            var lp = bestRotMatrix.TransposeMul(pt);
            localMinX = MathF.Min(localMinX, lp.X);
            localMinY = MathF.Min(localMinY, lp.Y);
            localMinZ = MathF.Min(localMinZ, lp.Z);
            localMaxX = MathF.Max(localMaxX, lp.X);
            localMaxY = MathF.Max(localMaxY, lp.Y);
            localMaxZ = MathF.Max(localMaxZ, lp.Z);
        }

        var localCenter = new Vector3D(
            (localMinX + localMaxX) / 2f,
            (localMinY + localMaxY) / 2f,
            (localMinZ + localMaxZ) / 2f);

        // Forward-rotate local center to world space
        var dumpCenter = bestRotMatrix.Col0 * localCenter.X +
                         bestRotMatrix.Col1 * localCenter.Y +
                         bestRotMatrix.Col2 * localCenter.Z;

        var bbPivot = new Vector3D(-dumpCenter.X, dumpCenter.Y, dumpCenter.Z);

        // Size signs
        var sizeSigns = new Vector3D(1, 1, 1);
        for (int axIdx = 0; axIdx < 3; axIdx++)
        {
            var localAx = axIdx == 0 ? bestRotMatrix.Col0 : axIdx == 1 ? bestRotMatrix.Col1 : bestRotMatrix.Col2;
            foreach (var info in faceInfos)
            {
                var nLocal = bestRotMatrix.TransposeMul(info.NW);
                float nLocalVal = axIdx == 0 ? nLocal.X : axIdx == 1 ? nLocal.Y : nLocal.Z;
                if (MathF.Abs(nLocalVal) > 0.5f)
                {
                    var faceCenter = Vector3D.Zero;
                    var rf = info.RawF;
                    faceCenter += rf.V0.Vec * 16f;
                    faceCenter += rf.V1.Vec * 16f;
                    faceCenter += rf.V2.Vec * 16f;
                    faceCenter += rf.V3.Vec * 16f;
                    faceCenter *= 0.25f;
                    var offset = faceCenter - dumpCenter;
                    float dotOff = Dot(offset, localAx);
                    if (MathF.Abs(dotOff) > 1e-3f)
                    {
                        if (dotOff * nLocalVal < 0)
                        {
                            if (axIdx == 0) sizeSigns = new Vector3D(-1, sizeSigns.Y, sizeSigns.Z);
                            else if (axIdx == 1) sizeSigns = new Vector3D(sizeSigns.X, -1, sizeSigns.Z);
                            else sizeSigns = new Vector3D(sizeSigns.X, sizeSigns.Y, -1);
                        }
                    }
                    break;
                }
            }
        }

        // Compute size: max distance from center in each axis direction, doubled, minus inflate
        float sxMax = 0, syMax = 0, szMax = 0;
        foreach (var (px, py, pz) in uniquePts)
        {
            var pt = new Vector3D(px, py, pz);
            var d = pt - dumpCenter;
            sxMax = MathF.Max(sxMax, MathF.Abs(Dot(d, bestRotMatrix.Col0)));
            syMax = MathF.Max(syMax, MathF.Abs(Dot(d, bestRotMatrix.Col1)));
            szMax = MathF.Max(szMax, MathF.Abs(Dot(d, bestRotMatrix.Col2)));
        }

        var bbSize = new Vector3D(
            (sxMax * 2f - 2f * originalInflate) * sizeSigns.X,
            (syMax * 2f - 2f * originalInflate) * sizeSigns.Y,
            (szMax * 2f - 2f * originalInflate) * sizeSigns.Z);

        var bbOrigin = bbPivot - bbSize * 0.5f;

        var bbRot = new Vector3D(-bestEuler.X, -bestEuler.Y, bestEuler.Z);

        var result = new BlockbenchCube
        {
            Origin = bbOrigin,
            Size = bbSize,
            Inflate = originalInflate,
            Pivot = bbPivot,
            Rotation = bbRot,
            Uv = []
        };

        // UV boxes
        foreach (var info in faceInfos)
        {
            var nLocal = bestRotMatrix.TransposeMul(info.NW);
            var tULocal = bestRotMatrix.TransposeMul(info.TU);
            var tVLocal = bestRotMatrix.TransposeMul(info.TV);

            GetExpectedUVDirs(nLocal, out var rawExpU, out var rawExpV);
            var expU = rawExpU * sizeSigns;
            var expV = rawExpV * sizeSigns;

            float uMin = float.PositiveInfinity, vMin = float.PositiveInfinity;
            float uMax = float.NegativeInfinity, vMax = float.NegativeInfinity;

            var rf = info.RawF;
            float u0 = rf.V0.U * textureWidth, v0 = rf.V0.V * textureHeight;
            float u1 = rf.V1.U * textureWidth, v1 = rf.V1.V * textureHeight;
            float u2 = rf.V2.U * textureWidth, v2 = rf.V2.V * textureHeight;
            float u3 = rf.V3.U * textureWidth, v3 = rf.V3.V * textureHeight;

            uMin = MathF.Min(MathF.Min(u0, u1), MathF.Min(u2, u3));
            uMax = MathF.Max(MathF.Max(u0, u1), MathF.Max(u2, u3));
            vMin = MathF.Min(MathF.Min(v0, v1), MathF.Min(v2, v3));
            vMax = MathF.Max(MathF.Max(v0, v1), MathF.Max(v2, v3));

            float uStart = uMin, vStart = vMin;
            float uSz = uMax - uMin, vSz = vMax - vMin;

            if (Dot(tULocal, expU) < -0.2f) { uStart = uMax; uSz = -uSz; }
            if (Dot(tVLocal, expV) < -0.2f) { vStart = vMax; vSz = -vSz; }

            var box = new UVBox(CleanVal(uStart), CleanVal(vStart), CleanVal(uSz), CleanVal(vSz));

            if (Dot(nLocal, new Vector3D(1, 0, 0)) > 0.9f) result.Uv["east"] = box;
            else if (Dot(nLocal, new Vector3D(-1, 0, 0)) > 0.9f) result.Uv["west"] = box;
            else if (Dot(nLocal, new Vector3D(0, 1, 0)) > 0.9f) result.Uv["up"] = box;
            else if (Dot(nLocal, new Vector3D(0, -1, 0)) > 0.9f) result.Uv["down"] = box;
            else if (Dot(nLocal, new Vector3D(0, 0, 1)) > 0.9f) result.Uv["south"] = box;
            else if (Dot(nLocal, new Vector3D(0, 0, -1)) > 0.9f) result.Uv["north"] = box;
        }

        return result;
    }

    // ============== Animations deserialization ==============

    private byte[] ParseAnimations(BufferReader reader)
    {
        var root = new JsonObject
        {
            ["format_version"] = "1.8.0",
        };
        var animations = new JsonObject();
        root["animations"] = animations;

        if (_format > 15)
        {
            _ = reader.ReadString();
        }
        uint animCount = (uint)reader.ReadVarint();
        for (uint a = 0; a < animCount; a++)
        {
            string animName = reader.ReadString();
            float animLen = reader.ReadFloat() / 20f;
            LoopMode loop = (LoopMode)reader.ReadVarint();

            var animObj = new JsonObject();
            if (animLen > 0f && !float.IsInfinity(animLen))
            {
                animObj["animation_length"] = animLen;
            }
            if (loop == LoopMode.Loop) animObj["loop"] = true;
            else if (loop == LoopMode.HoldOnLastFrame) animObj["loop"] = "hold_on_last_frame";

            if (_format > 9)
            {
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();

                uint blendWeightCount = (uint)reader.ReadVarint();
                for (uint j = 0; j < blendWeightCount; j++)
                {
                    byte type = reader.ReadByte();
                    if (type == 0x01) animObj["blend_weight"] = reader.ReadFloat();
                    else if (type == 0x02) animObj["blend_weight"] = reader.ReadString();
                }
                _ = reader.ReadVarint();
            }

            uint boneCount = (uint)reader.ReadVarint();
            var bonesObj = new JsonObject();
            for (uint b = 0; b < boneCount; b++)
            {
                string boneName = reader.ReadString();
                var rotation = ParseChannel(reader);
                var position = ParseChannel(reader);
                var scale = ParseChannel(reader);

                var boneData = new JsonObject();
                string rotJson = ChannelToJson(rotation);
                if (rotJson != "null") boneData["rotation"] = ParseJsonValue(rotJson);
                string posJson = ChannelToJson(position);
                if (posJson != "null") boneData["position"] = ParseJsonValue(posJson);
                string sclJson = ChannelToJson(scale);
                if (sclJson != "null") boneData["scale"] = ParseJsonValue(sclJson);
                if (boneData.Count > 0) bonesObj[boneName] = boneData;
            }
            if (bonesObj.Count > 0) animObj["bones"] = bonesObj;

            var tl = ParseTimeLine(reader);
            if (tl != null && tl.Groups.Count > 0)
            {
                var tlObj = new JsonObject();
                foreach (var (time, list) in tl.Groups)
                {
                    var arr = new JsonArray();
                    foreach (var s in list) arr.Add((JsonNode)JsonValue.Create(s));
                    tlObj[FormatTime(time)] = arr;
                }
                animObj["timeline"] = tlObj;
            }

            if (_format > 9)
            {
                var se = ParseEffect(reader);
                if (se != null && se.Events.Count > 0)
                {
                    var efObj = new JsonObject();
                    foreach (var (time, name) in se.Events)
                    {
                        efObj[FormatTime(time)] = new JsonObject { ["effect"] = name };
                    }
                    animObj["sound_effects"] = efObj;
                }
            }

            animations[animName] = animObj;
        }

        return Encoding.UTF8.GetBytes(DumpJson(root, FormatJson));
    }

    private static JsonNode? ParseJsonValue(string s)
    {
        return JsonNode.Parse(s);
    }

    private void ParseLegacyYSMInfo(BufferReader reader)
    {
        string infoName = reader.ReadString();
        string infoTips = reader.ReadString();
        uint extraAnims = (uint)reader.ReadVarint();
        var extraNames = new JsonArray();
        for (uint i = 0; i < extraAnims; i++) extraNames.Add((JsonNode)JsonValue.Create(reader.ReadString()));
        uint authorsCount = (uint)reader.ReadVarint();
        var authors = new JsonArray();
        for (uint i = 0; i < authorsCount; i++) authors.Add((JsonNode)JsonValue.Create(reader.ReadString()));
        string infoLicense = reader.ReadString();
        bool infoFree = reader.ReadVarint() != 0;

        var j = new JsonObject
        {
            ["name"] = infoName,
            ["tips"] = infoTips,
            ["authors"] = authors,
            ["license"] = infoLicense,
            ["extra_animation_names"] = extraNames,
            ["free"] = infoFree,
        };
        _infoJsonFile = Encoding.UTF8.GetBytes(DumpJson(j, FormatJson));
    }

    private void ParseYSMJson(BufferReader reader)
    {
        _ = reader.ReadString(); // sha256 placeholder

        var root = new JsonObject { ["spec"] = 2 };
        var properties = new JsonObject();
        var metadata = new JsonObject();
        root["metadata"] = metadata;

        uint isNewVersion = (uint)reader.ReadVarint();
        if (isNewVersion == 0) return;

        if (_format <= 15)
        {
            _ = reader.ReadVarint();
        }

        metadata["name"] = reader.ReadString();
        metadata["tips"] = reader.ReadString();
        metadata["license"] = new JsonObject
        {
            ["type"] = reader.ReadString(),
            ["desc"] = reader.ReadString(),
        };

        uint authorsCount = (uint)reader.ReadVarint();
        if (authorsCount > 0)
        {
            var authors = new JsonArray();
            for (uint j = 0; j < authorsCount; j++)
            {
                string authorName = reader.ReadString();
                string role = reader.ReadString();
                var authorObj = new JsonObject { ["name"] = authorName, ["role"] = role };
                uint contactCount = (uint)reader.ReadVarint();
                if (contactCount > 0)
                {
                    var contacts = new JsonObject();
                    for (uint k = 0; k < contactCount; k++)
                    {
                        contacts[reader.ReadString()] = reader.ReadString();
                    }
                    authorObj["contact"] = contacts;
                }
                authorObj["comment"] = reader.ReadString();
                authorObj["avatar"] = "avatar/" + SanitizeWindowsFilename(authorName + ".png");
                authors.Add((JsonNode)authorObj);
            }
            metadata["authors"] = authors;
        }

        uint linksCount = (uint)reader.ReadVarint();
        if (linksCount > 0)
        {
            var links = new JsonObject();
            for (uint j = 0; j < linksCount; j++) links[reader.ReadString()] = reader.ReadString();
            metadata["link"] = links;
        }

        properties["width_scale"] = reader.ReadFloat();
        properties["height_scale"] = reader.ReadFloat();

        uint extraAnims = (uint)reader.ReadVarint();
        if (extraAnims > 0)
        {
            var extras = new JsonObject();
            for (uint j = 0; j < extraAnims; j++) extras[reader.ReadString()] = reader.ReadString();
            properties["extra_animation"] = extras;
        }

        if (_format > 9)
        {
            uint buttons = (uint)reader.ReadVarint();
            if (buttons > 0)
            {
                var arr = new JsonArray();
                for (uint j = 0; j < buttons; j++)
                {
                    var btn = new JsonObject { ["id"] = reader.ReadString(), ["name"] = reader.ReadString() };
                    _ = reader.ReadVarint();
                    uint configCount = (uint)reader.ReadVarint();
                    if (configCount > 0)
                    {
                        var cfg = new JsonArray();
                        for (uint k = 0; k < configCount; k++)
                        {
                            var form = new JsonObject
                            {
                                ["type"] = reader.ReadString(),
                                ["title"] = reader.ReadString(),
                                ["description"] = reader.ReadString(),
                                ["value"] = reader.ReadString(),
                            };
                            float step = reader.ReadFloat();
                            float minV = reader.ReadFloat();
                            float maxV = reader.ReadFloat();
                            string type = (string)form["type"]!;
                            if (type == "range")
                            {
                                form["step"] = step;
                                form["min"] = minV;
                                form["max"] = maxV;
                            }
                            uint labels = (uint)reader.ReadVarint();
                            if (labels > 0)
                            {
                                var labelsObj = new JsonObject();
                                for (uint l = 0; l < labels; l++) labelsObj[reader.ReadString()] = reader.ReadString();
                                form["labels"] = labelsObj;
                            }
                            cfg.Add((JsonNode)form);
                        }
                        btn["config_forms"] = cfg;
                    }
                    arr.Add((JsonNode)btn);
                }
                properties["extra_animation_buttons"] = arr;
            }

            uint classifyCount = (uint)reader.ReadVarint();
            var classify = new JsonArray();
            for (uint j = 0; j < classifyCount; j++)
            {
                var sig = new JsonObject { ["id"] = reader.ReadString() };
                uint extras = (uint)reader.ReadVarint();
                var exObj = new JsonObject();
                for (uint k = 0; k < extras; k++) exObj[reader.ReadString()] = reader.ReadString();
                sig["extra_animation"] = exObj;
                classify.Add((JsonNode)sig);
            }
            properties["extra_animation_classify"] = classify;
        }

        string defaultTex = reader.ReadString();
        if (!string.IsNullOrEmpty(defaultTex)) properties["default_texture"] = defaultTex;
        string previewAnim = reader.ReadString();
        if (!string.IsNullOrEmpty(previewAnim)) properties["preview_animation"] = previewAnim;
        properties["free"] = reader.ReadVarint() != 0;
        if (_format > 4) properties["render_layers_first"] = reader.ReadVarint() != 0;
        if (_format >= 15)
        {
            properties["all_cutout"] = reader.ReadVarint() != 0;
            properties["disable_preview_rotation"] = reader.ReadVarint() != 0;
        }

        string guiFg = string.Empty, guiBg = string.Empty;
        if (_format > 15)
        {
            properties["gui_no_lighting"] = reader.ReadVarint() != 0;
            if (_format >= 32) properties["merge_multiline_expr"] = reader.ReadVarint() != 0;
            guiFg = reader.ReadString();
            if (!string.IsNullOrEmpty(guiFg)) properties["gui_foreground"] = guiFg;
            guiBg = reader.ReadString();
            if (!string.IsNullOrEmpty(guiBg)) properties["gui_background"] = guiBg;

            uint avatars = (uint)reader.ReadVarint();
            if (avatars > 0)
            {
                var arr = new JsonArray();
                for (uint j = 0; j < avatars; j++)
                {
                    string name = reader.ReadString();
                    var data = reader.ReadByteSequence();
                    _avatarFiles.Add((name, data));
                    var info = new JsonObject
                    {
                        ["name"] = name,
                        ["width"] = (int)reader.ReadVarint(),
                        ["height"] = (int)reader.ReadVarint(),
                    };
                    _ = reader.ReadVarint();
                    _ = reader.ReadVarint();
                    arr.Add((JsonNode)info);
                }
                metadata["avatars"] = arr;
            }
        }

        root["properties"] = properties;
        root["files"] = BuildFilesFromParsedData();

        CleanJsonFloats(root);
        _ysmJsonFile = Encoding.UTF8.GetBytes(DumpJson(root, FormatJson));

        if (_format <= 15) return;

        if (!string.IsNullOrEmpty(guiFg) || !string.IsNullOrEmpty(guiBg))
        {
            uint bgCount = (uint)reader.ReadVarint();
            for (uint j = 0; j < bgCount; j++)
            {
                string name = reader.ReadString();
                var data = reader.ReadByteSequence();
                string rel;
                if (name == "gui_foreground" && !string.IsNullOrEmpty(guiFg)) rel = guiFg;
                else if (name == "gui_background" && !string.IsNullOrEmpty(guiBg)) rel = guiBg;
                else rel = "background/" + SanitizeWindowsFilename(name + ".png");
                _backgroundFiles.Add((rel, data));

                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
            }
        }
    }

    private JsonObject BuildFilesFromParsedData()
    {
        var files = new JsonObject();
        var subEntityModels = new HashSet<string>();
        foreach (var (name, _) in _modelFiles)
        {
            if (name != "main" && name != "arm") subEntityModels.Add(name);
        }

        var player = new JsonObject();
        var playerModels = new JsonObject();
        foreach (var (name, _) in _modelFiles)
        {
            if (name == "main") playerModels["main"] = "models/main.json";
            else if (name == "arm") playerModels["arm"] = "models/arm.json";
        }
        if (playerModels.Count > 0) player["model"] = playerModels;

        var playerAnims = new JsonObject();
        foreach (var (name, _) in _animationFiles)
        {
            if (name.Contains('/')) continue;
            if (subEntityModels.Contains(name)) continue;
            string key = name;
            string component = name;
            if (name == "fp_arm" || name == "fp.arm") { key = "fp_arm"; component = "fp.arm"; }
            else if (name == "iss" || name == "irons_spell_books") { key = "irons_spell_books"; component = "iss"; }
            playerAnims[key] = "animations/" + SanitizeWindowsFilename(component + ".animation.json");
        }
        if (playerAnims.Count > 0) player["animation"] = playerAnims;

        var ac1 = new JsonArray();
        foreach (var (name, _) in _animControllerFiles)
        {
            if (name.Contains('/')) continue;
            if (subEntityModels.Contains(name)) continue;
            ac1.Add((JsonNode)JsonValue.Create("controller/" + SanitizeWindowsFilename(name + ".json")));
        }
        player["animation_controllers"] = ac1;

        var playerTex = new JsonArray();
        foreach (var (name, _) in _textureFiles)
        {
            bool isSub = false;
            foreach (var sn in subEntityModels)
            {
                if (name == sn || name.StartsWith(sn + "_")) { isSub = true; break; }
            }
            if (isSub) continue;
            var texObj = new JsonObject { ["uv"] = "textures/" + SanitizeWindowsFilename(name + ".png") };
            string expectedNormal = name + "_normal";
            string expectedSpecular = name + "_specular";
            foreach (var (Name, Data) in _specialImageFiles)
            {
                if (Name == expectedNormal) texObj["normal"] = "textures/" + SanitizeWindowsFilename(expectedNormal + ".png");
                else if (Name == expectedSpecular) texObj["specular"] = "textures/" + SanitizeWindowsFilename(expectedSpecular + ".png");
            }
            playerTex.Add((JsonNode)texObj);
        }
        if (playerTex.Count > 0) player["texture"] = playerTex;

        files["player"] = player;

        // Sub-entity sections
        var catModels = new Dictionary<string, List<string>>();
        foreach (var mn in subEntityModels)
        {
            string cat;
            if (_subEntityCategories.TryGetValue(mn, out var c))
            {
                if (c == "vehicle") cat = "vehicles";
                else if (c == "SubEntity")
                {
                    cat = mn switch
                    {
                        "arrow" or "trident" => "projectiles",
                        "horse" or "minecart" or "boat" => "vehicles",
                        _ => "sub_entities",
                    };
                }
                else cat = c;
            }
            else
            {
                cat = mn switch
                {
                    "arrow" or "trident" => "projectiles",
                    "horse" or "minecart" or "boat" => "vehicles",
                    _ => "sub_entities",
                };
            }
            if (!catModels.TryGetValue(cat, out var list))
            {
                list = [];
                catModels[cat] = list;
            }
            list.Add(mn);
        }

        foreach (var (cat, models) in catModels)
        {
            var section = new JsonObject();
            foreach (var mn in models)
            {
                var entry = new JsonObject { ["model"] = "models/" + SanitizeWindowsFilename(mn + ".json") };
                foreach (var (an, _) in _animationFiles)
                {
                    if (an.Contains('/'))
                    {
                        int sp = an.IndexOf('/');
                        if (an[(sp + 1)..] == mn)
                        {
                            string catPrefix = an[..(sp + 1)];
                            string baseName = an[(sp + 1)..];
                            entry["animation"] = "animations/" + catPrefix + SanitizeWindowsFilename(baseName + ".animation.json");
                            break;
                        }
                    }
                    else if (an == mn)
                    {
                        entry["animation"] = (cat == "vehicles" ? "animations/vehicle/" : "animations/") + SanitizeWindowsFilename(mn + ".animation.json");
                        break;
                    }
                }
                foreach (var (an, _) in _animControllerFiles)
                {
                    if (an.Contains('/'))
                    {
                        int sp = an.IndexOf('/');
                        if (an[(sp + 1)..] == mn)
                        {
                            string catPrefix = an[..(sp + 1)];
                            string baseName = an[(sp + 1)..];
                            entry["controller"] = "controller/" + catPrefix + SanitizeWindowsFilename(baseName + ".json");
                            break;
                        }
                    }
                    else if (an == mn)
                    {
                        entry["controller"] = (cat == "vehicles" ? "controller/vehicle/" : "controller/") + SanitizeWindowsFilename(mn + ".json");
                        break;
                    }
                }
                foreach (var (tn, _) in _textureFiles)
                {
                    if (tn == mn || tn.StartsWith(mn + "_"))
                    {
                        entry["texture"] = "textures/" + SanitizeWindowsFilename(mn + ".png");
                        break;
                    }
                }
                section[mn] = entry;
            }
            files[cat] = section;
        }

        return files;
    }

    private void ParseSoundFiles(BufferReader reader)
    {
        uint cnt = (uint)reader.ReadVarint();
        for (uint i = 0; i < cnt; i++)
        {
            string name = reader.ReadString();
            if (_format > 15) _ = reader.ReadString();
            var data = reader.ReadByteSequence();
            _soundFiles.Add((name, data));
        }
    }

    private void ParseFunctionFiles(BufferReader reader)
    {
        uint cnt = (uint)reader.ReadVarint();
        for (uint i = 0; i < cnt; i++)
        {
            string name = reader.ReadString();
            _ = reader.ReadString();
            var data = reader.ReadByteSequence();
            _functionFiles.Add((name, data));
        }
    }

    private void ParseLanguageFiles(BufferReader reader)
    {
        uint cnt = (uint)reader.ReadVarint();
        for (uint i = 0; i < cnt; i++)
        {
            string name = reader.ReadString();
            _ = reader.ReadString();
            uint nodes = (uint)reader.ReadVarint();
            var nodesObj = new JsonObject();
            for (uint j = 0; j < nodes; j++) nodesObj[reader.ReadString()] = reader.ReadString();
            _languageFiles.Add((name, Encoding.UTF8.GetBytes(DumpJson(nodesObj, FormatJson))));
        }
    }

    private byte[] ParseAnimationControllers(BufferReader reader)
    {
        var root = new JsonObject { ["format_version"] = "1.19.0" };
        var controllers = new JsonObject();
        root["animation_controllers"] = controllers;

        uint animCount = (uint)reader.ReadVarint();
        for (uint a = 0; a < animCount; a++)
        {
            string animName = reader.ReadString();
            string initialState = reader.ReadString();
            var controllerData = new JsonObject();
            if (!string.IsNullOrEmpty(initialState)) controllerData["initial_state"] = initialState;

            var states = new JsonObject();
            uint statesCount = (uint)reader.ReadVarint();
            for (uint s = 0; s < statesCount; s++)
            {
                string stateName = reader.ReadString();
                var stateObj = new JsonObject();

                uint animsSize = (uint)reader.ReadVarint();
                if (animsSize > 0)
                {
                    var arr = new JsonArray();
                    for (uint j = 0; j < animsSize; j++)
                    {
                        string ak = reader.ReadString();
                        string av = reader.ReadString();
                        if (string.IsNullOrEmpty(av)) arr.Add((JsonNode)JsonValue.Create(ak));
                        else arr.Add((JsonNode)new JsonObject { [ak] = av });
                    }
                    stateObj["animations"] = arr;
                }

                uint transSize = (uint)reader.ReadVarint();
                if (transSize > 0)
                {
                    var arr = new JsonArray();
                    for (uint j = 0; j < transSize; j++)
                    {
                        var item = new JsonObject
                        {
                            [reader.ReadString()] = reader.ReadString()
                        };
                        arr.Add((JsonNode)item);
                    }
                    stateObj["transitions"] = arr;
                }

                uint onEntryCount = (uint)reader.ReadVarint();
                if (onEntryCount > 0)
                {
                    var arr = new JsonArray();
                    for (uint j = 0; j < onEntryCount; j++) arr.Add((JsonNode)JsonValue.Create(reader.ReadString()));
                    stateObj["on_entry"] = arr;
                }

                uint onExitCount = (uint)reader.ReadVarint();
                if (onExitCount > 0)
                {
                    var arr = new JsonArray();
                    for (uint j = 0; j < onExitCount; j++) arr.Add((JsonNode)JsonValue.Create(reader.ReadString()));
                    stateObj["on_exit"] = arr;
                }

                if (reader.ReadVarint() != 0)
                {
                    stateObj["blend_transition"] = reader.ReadFloat();
                }
                else
                {
                    uint blendCount = (uint)reader.ReadVarint();
                    if (blendCount > 0)
                    {
                        var obj = new JsonObject();
                        for (uint j = 0; j < blendCount; j++)
                        {
                            float bk = reader.ReadFloat();
                            float bv = reader.ReadFloat();
                            obj[bk.ToString("0.0", CultureInfo.InvariantCulture)] = bv;
                        }
                        stateObj["blend_transitions"] = obj;
                    }
                }

                if (reader.ReadVarint() != 0)
                {
                    stateObj["blend_via_shortest_path"] = true;
                }

                if (_format > 26)
                {
                    uint soundEffects = (uint)reader.ReadVarint();
                    if (soundEffects > 0)
                    {
                        var arr = new JsonArray();
                        for (uint j = 0; j < soundEffects; j++)
                        {
                            arr.Add((JsonNode)new JsonObject { ["effect"] = reader.ReadString() });
                        }
                        stateObj["sound_effects"] = arr;
                    }
                }
                states[stateName] = stateObj;
            }
            controllerData["states"] = states;
            controllers[animName] = controllerData;
        }
        return Encoding.UTF8.GetBytes(DumpJson(root, FormatJson));
    }

    private void ParseTextureFiles(BufferReader reader)
    {
        uint cnt = (uint)reader.ReadVarint();
        for (uint i = 0; i < cnt; i++)
        {
            string name = reader.ReadString();
            _ = reader.ReadString();
            var data = reader.ReadByteSequence();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            uint subCount = (uint)reader.ReadVarint();
            for (uint j = 0; j < subCount; j++)
            {
                uint specular = (uint)reader.ReadVarint();
                var subData = reader.ReadByteSequence();
                string suffix = specular == 1 ? "_normal" : specular == 2 ? "_specular" : "_special";
                _specialImageFiles.Add((name + suffix, subData));
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
            }
            _textureFiles.Add((name, data));
        }
    }

    private void Deserialize(byte[] data, int size)
    {
        var reader = new BufferReader(data, 0);
        uint version = reader.ReadDword();
        if (version != _format) throw new ParserUnSupportVersionException();
        if (_format < 4)
        {
            DeserializeLegacyV1(reader);
        }
        else if (_format <= 15)
        {
            DeserializeLegacyV15(reader);
        }
        else
        {
            DeserializeModern(reader);
        }
    }

    private void DeserializeLegacyV1(BufferReader reader)
    {
        uint skipBytes = (uint)reader.ReadVarint();
        reader.Offset += (int)skipBytes;

        uint modelCount = (uint)reader.ReadVarint();
        var modelIds = new List<uint>();
        for (uint i = 0; i < modelCount; i++)
        {
            uint modelId = (uint)reader.ReadVarint();
            modelIds.Add(modelId);
            if (reader.ReadVarint() != 1) throw new ParserUnknownFieldException();
            var model = ParseModels(reader);
            string modelName = modelId switch
            {
                1 => "main",
                2 => "arm",
                3 => "arrow",
                _ => throw new ParserUnknownFieldException(),
            };
            _modelFiles.Add((modelName, model));
        }

        uint animationCount = (uint)reader.ReadVarint();
        var animIds = new List<uint>();
        for (uint i = 0; i < animationCount; i++)
        {
            uint id = (uint)reader.ReadVarint();
            animIds.Add(id);
            _ = reader.ReadVarint();
            var anim = ParseAnimations(reader);
            string name = id switch
            {
                1 => "main",
                2 => "arm",
                3 => "extra",
                4 => "tac",
                5 => "arrow",
                6 => "carryon",
                7 => "parcool",
                8 => "swem",
                9 => "slashblade",
                10 => "tlm",
                11 => "fp.arm",
                12 => "immersive_melodies",
                13 => "iss",
                _ => throw new ParserUnknownFieldException(),
            };
            _animationFiles.Add((name, anim));
        }

        uint customTextureCount = (uint)reader.ReadVarint();
        for (uint i = 0; i < customTextureCount; i++)
        {
            string textureName = reader.ReadString();
            if (textureName == "/ARROW\\") textureName = "arrow";
            if (_format < 4)
            {
                if (reader.ReadVarint() != 0x01) throw new ParserUnknownFieldException();
            }
            var data = reader.ReadByteSequence();
            uint width = (uint)reader.ReadVarint();
            uint height = (uint)reader.ReadVarint();
            byte[] png = FpngEncoder.EncodeRgbaToPng(data, (int)width, (int)height);
            if (png.Length == 0) throw new ParserUnknownFieldException();
            _textureFiles.Add((textureName, png));
        }

        // Hash tables (skipped - they don't affect export).
        uint modelTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < modelTableSize; i++) { _ = reader.ReadVarint(); _ = reader.ReadString(); }

        uint animTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < animTableSize; i++) { _ = reader.ReadVarint(); _ = reader.ReadString(); }

        uint textureTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < textureTableSize; i++) { _ = reader.ReadString(); _ = reader.ReadString(); }
    }

    private void DeserializeLegacyV15(BufferReader reader)
    {
        uint skipBytes = (uint)reader.ReadVarint();
        reader.Offset += (int)skipBytes;

        uint modelCount = (uint)reader.ReadVarint();
        var modelIds = new List<uint>();
        for (uint i = 0; i < modelCount; i++)
        {
            uint id = (uint)reader.ReadVarint();
            modelIds.Add(id);
            _ = reader.ReadVarint();
            var model = ParseModels(reader);
            string name = id switch
            {
                1 => "main",
                2 => "arm",
                3 => "arrow",
                _ => throw new ParserUnknownFieldException(),
            };
            _modelFiles.Add((name, model));
        }

        uint animationCount = (uint)reader.ReadVarint();
        var animIds = new List<uint>();
        for (uint i = 0; i < animationCount; i++)
        {
            uint id = (uint)reader.ReadVarint();
            animIds.Add(id);
            _ = reader.ReadVarint();
            var anim = ParseAnimations(reader);
            string name = id switch
            {
                1 => "main",
                2 => "arm",
                3 => "extra",
                4 => "tac",
                5 => "arrow",
                6 => "carryon",
                7 => "parcool",
                8 => "swem",
                9 => "slashblade",
                10 => "tlm",
                11 => "fp_arm",
                12 => "immersive_melodies",
                13 => "irons_spell_books",
                _ => throw new ParserUnknownFieldException(),
            };
            _animationFiles.Add((name, anim));
        }

        if (_format > 9)
        {
            uint animControllerCount = (uint)reader.ReadVarint();
            for (uint i = 0; i < animControllerCount; i++)
            {
                string controllerName;
                if (_format <= 15)
                {
                    controllerName = "controller";
                    _ = reader.ReadVarint();
                }
                else
                {
                    controllerName = reader.ReadString();
                    _ = reader.ReadString();
                }
                var data = ParseAnimationControllers(reader);
                _animControllerFiles.Add((controllerName, data));
            }

            uint controllerTable = (uint)reader.ReadVarint();
            for (uint i = 0; i < controllerTable; i++) { _ = reader.ReadString(); _ = reader.ReadString(); }
        }

        uint customTextureCount = (uint)reader.ReadVarint();
        for (uint i = 0; i < customTextureCount; i++)
        {
            string textureName = reader.ReadString();
            if (textureName == "/ARROW\\") textureName = "arrow";
            var data = reader.ReadByteSequence();
            uint width = (uint)reader.ReadVarint();
            uint height = (uint)reader.ReadVarint();
            byte[] png = FpngEncoder.EncodeRgbaToPng(data, (int)width, (int)height);
            if (png.Length == 0) throw new ParserUnknownFieldException();
            _textureFiles.Add((textureName, png));

            uint subCount = (uint)reader.ReadVarint();
            for (uint j = 0; j < subCount; j++)
            {
                uint specular = (uint)reader.ReadVarint();
                var subData = reader.ReadByteSequence();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                byte[] subPng = FpngEncoder.EncodeRgbaToPng(subData, (int)width, (int)height);
                if (subPng.Length == 0) throw new ParserUnknownFieldException();
                string suffix = specular == 1 ? "_normal" : specular == 2 ? "_specular" : "_special";
                _specialImageFiles.Add((textureName + suffix, subPng));
            }
        }

        if (_format > 9)
        {
            ParseSoundFiles(reader);
            uint soundTable = (uint)reader.ReadVarint();
            for (uint i = 0; i < soundTable; i++) { _ = reader.ReadString(); _ = reader.ReadString(); }
        }

        uint extraTextureCount = (uint)reader.ReadVarint();
        for (uint i = 0; i < extraTextureCount; i++)
        {
            string textureName = reader.ReadString();
            var data = reader.ReadByteSequence();
            uint width = (uint)reader.ReadVarint();
            uint height = (uint)reader.ReadVarint();
            byte[] png = FpngEncoder.EncodeRgbaToPng(data, (int)width, (int)height);
            if (png.Length == 0) throw new ParserUnknownFieldException();
            _avatarFiles.Add((textureName, png));
        }

        uint modelTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < modelTableSize; i++) { _ = reader.ReadVarint(); _ = reader.ReadString(); }

        uint animTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < animTableSize; i++) { _ = reader.ReadVarint(); _ = reader.ReadString(); }

        uint textureTableSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < textureTableSize; i++)
        {
            _ = reader.ReadString();
            _ = reader.ReadString();
            uint subCount = (uint)reader.ReadVarint();
            for (uint j = 0; j < subCount; j++)
            {
                _ = reader.ReadVarint();
                _ = reader.ReadString();
            }
        }

        ParseYSMJson(reader);
    }

    private void DeserializeModern(BufferReader reader)
    {
        ParseSoundFiles(reader);
        ParseFunctionFiles(reader);
        ParseLanguageFiles(reader);

        // Sub-entities: read each as (controller, anim, base texture, sub textures, model)
        // For format < 26 there is one sub-entity list; for >= 26 there are two (vehicles, projectiles).
        void ParseSubEntity(string categoryName)
        {
            string subModuleName = string.Empty;
            if (_format <= 26) subModuleName = reader.ReadString();
            bool hasSubAnim = reader.ReadVarint() != 0;
            byte[] anim = hasSubAnim ? ParseAnimations(reader) : [];

            bool hasSubController = reader.ReadVarint() != 0;
            byte[] subController = [];
            if (hasSubController)
            {
                _ = reader.ReadString();
                subController = ParseAnimationControllers(reader);
            }

            byte[] baseTex = ParseSpecialImage(reader);
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();
            _ = reader.ReadVarint();

            uint subCount = (uint)reader.ReadVarint();
            var subTextures = new List<(string Name, byte[] Data)>();
            for (uint i = 0; i < subCount; i++)
            {
                uint specular = (uint)reader.ReadVarint();
                var data = ParseSpecialImage(reader);
                if (specular == 1) subTextures.Add(("normal", data));
                else if (specular == 2) subTextures.Add(("specular", data));
                else throw new ParserUnknownFieldException();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
                _ = reader.ReadVarint();
            }

            byte[] model = ParseModels(reader);

            if (_format > 26)
            {
                uint subModels = (uint)reader.ReadVarint();
                for (uint j = 0; j < subModels; j++)
                {
                    subModuleName = reader.ReadString();
                    if (subModuleName.Contains(':')) subModuleName = subModuleName[(subModuleName.IndexOf(':') + 1)..];
                    _subEntityCategories[subModuleName] = categoryName;
                    _modelFiles.Add((subModuleName, model));
                    foreach (var (n, d) in subTextures) _textureFiles.Add((subModuleName + "_" + n, d));
                    _textureFiles.Add((subModuleName, baseTex));
                    if (hasSubAnim) _animationFiles.Add((categoryName + "/" + subModuleName, anim));
                    if (hasSubController) _animControllerFiles.Add((categoryName + "/" + subModuleName, subController));
                }
                return;
            }
            if (subModuleName.Contains(':')) subModuleName = subModuleName[(subModuleName.IndexOf(':') + 1)..];
            _subEntityCategories[subModuleName] = categoryName;
            _modelFiles.Add((subModuleName, model));
            foreach (var (n, d) in subTextures) _textureFiles.Add((subModuleName + "_" + n, d));
            _textureFiles.Add((subModuleName, baseTex));
            if (hasSubAnim) _animationFiles.Add((categoryName + "/" + subModuleName, anim));
            if (hasSubController) _animControllerFiles.Add((categoryName + "/" + subModuleName, subController));
        }

        if (_format < 26)
        {
            uint subEntitySize = (uint)reader.ReadVarint();
            for (uint i = 0; i < subEntitySize; i++) ParseSubEntity("SubEntity");
            _ = reader.ReadVarint();
        }
        else
        {
            uint vehiclesSize = (uint)reader.ReadVarint();
            for (uint i = 0; i < vehiclesSize; i++) ParseSubEntity("vehicle");
            uint projectilesSize = (uint)reader.ReadVarint();
            for (uint i = 0; i < projectilesSize; i++) ParseSubEntity("projectiles");
        }

        if (reader.ReadVarint() != 1) throw new ParserUnknownFieldException();

        uint animCount = (uint)reader.ReadVarint();
        for (uint i = 0; i < animCount; i++)
        {
            uint id = (uint)reader.ReadVarint();
            var anim = ParseAnimations(reader);
            string name = id switch
            {
                1 => "main",
                2 => "arm",
                3 => "extra",
                4 => "tac",
                5 => "arrow",
                6 => "carryon",
                7 => "parcool",
                8 => "swem",
                9 => "slashblade",
                10 => "tlm",
                11 => "fp.arm",
                12 => "immersive_melodies",
                13 => "iss",
                _ => throw new ParserUnknownFieldException(),
            };
            _animationFiles.Add((name, anim));
        }

        uint animControllerCount = (uint)reader.ReadVarint();
        for (uint i = 0; i < animControllerCount; i++)
        {
            string controllerName;
            if (_format <= 15) { controllerName = "controller"; _ = reader.ReadVarint(); }
            else { controllerName = reader.ReadString(); _ = reader.ReadString(); }
            var data = ParseAnimationControllers(reader);
            _animControllerFiles.Add((controllerName, data));
        }

        ParseTextureFiles(reader);

        uint modelSize = (uint)reader.ReadVarint();
        for (uint i = 0; i < modelSize; i++)
        {
            uint id = (uint)reader.ReadVarint();
            var model = ParseModels(reader);
            string name = id switch
            {
                1 => "main",
                2 => "arm",
                _ => throw new ParserUnknownFieldException(),
            };
            _modelFiles.Add((name, model));
        }

        ParseYSMJson(reader);
    }

    private static byte[] ParseSpecialImage(BufferReader reader)
    {
        _ = reader.ReadString();
        return reader.ReadByteSequence();
    }

    public override void PrintInfo(TextWriter output)
    {
        output.WriteLine($"  Version:      3");
        output.WriteLine($"  File size:    {_buffer.Length:N0} bytes");

        // Parse header on the fly if not yet done
        if (_header.Length == 0)
        {
            int nulIdx = -1;
            for (int i = 0; i < _buffer.Length; i++)
                if (_buffer[i] == 0) { nulIdx = i; break; }
            if (nulIdx < 0) { output.WriteLine("  (no header found)"); return; }
            _header = Encoding.UTF8.GetString(_buffer, 0, nulIdx);
        }

        var header = _header;
        output.WriteLine();
        output.WriteLine("  Header metadata:");

        foreach (var line in header.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.AsSpan().Trim();
            if (trimmed.Length == 0) continue;
            if (trimmed[0] != '<') continue;

            if (trimmed.StartsWith("<name>"))
                PrintTag(output, "Name", trimmed, "<name>");
            else if (trimmed.StartsWith("<authors>"))
                PrintTag(output, "Authors", trimmed, "<authors>");
            else if (trimmed.StartsWith("<license>"))
                PrintTag(output, "License", trimmed, "<license>");
            else if (trimmed.StartsWith("<free>"))
                PrintTag(output, "Free", trimmed, "<free>");
            else if (trimmed.StartsWith("<format>"))
                PrintTag(output, "Format version", trimmed, "<format>");
            else if (trimmed.StartsWith("<crypto>"))
                PrintTag(output, "Crypto version", trimmed, "<crypto>");
            else if (trimmed.StartsWith("<hash>"))
                PrintTag(output, "Hash", trimmed, "<hash>");
            else if (trimmed.StartsWith("<main-model>"))
                PrintTag(output, "Main model hash", trimmed, "<main-model>");
            else if (trimmed.StartsWith("<arm-model>"))
                PrintTag(output, "Arm model hash", trimmed, "<arm-model>");
            else if (trimmed.StartsWith("<arrow-model>"))
                PrintTag(output, "Arrow model hash", trimmed, "<arrow-model>");
            else if (trimmed.StartsWith("<main-animation>"))
                PrintTag(output, "Main animation hash", trimmed, "<main-animation>");
            else if (trimmed.StartsWith("<arm-animation>"))
                PrintTag(output, "Arm animation hash", trimmed, "<arm-animation>");
            else if (trimmed.StartsWith("<extra-animation>"))
                PrintTag(output, "Extra animation hash", trimmed, "<extra-animation>");
            else if (trimmed.StartsWith("<tac-animation>"))
                PrintTag(output, "TAC animation hash", trimmed, "<tac-animation>");
            else if (trimmed.StartsWith("<arrow-animation>"))
                PrintTag(output, "Arrow animation hash", trimmed, "<arrow-animation>");
            else if (trimmed.StartsWith("<texture"))
                PrintTag(output, "Texture", trimmed, ">");
            else if (trimmed.StartsWith("<animation-controller>"))
                PrintTag(output, "Animation controller", trimmed, "<animation-controller>");
            else if (trimmed.StartsWith("<player-model>") || trimmed.StartsWith("<projectile-model>") || trimmed.StartsWith("<vehicle-model>"))
                output.WriteLine($"    {trimmed}");
        }
    }

    private static void PrintTag(TextWriter output, string label, ReadOnlySpan<char> line, string tag)
    {
        var idx = line.IndexOf(tag.AsSpan(), StringComparison.Ordinal);
        if (idx < 0) return;
        var value = line.Slice(idx + tag.Length).Trim();
        output.WriteLine($"    {label}: {value}");
    }

    public override void SaveToDirectory(string outputDirectory)
    {
        Directory.CreateDirectory(outputDirectory);
        bool useLegacyRootLayout = _ysmJsonFile.Length == 0;

        bool ResolveRelative(string rel, out string outRel)
        {
            outRel = useLegacyRootLayout ? Path.GetFileName(rel) : rel;
            return true;
        }

        if (useLegacyRootLayout)
        {
            if (_infoJsonFile.Length > 0)
            {
                File.WriteAllBytes(Path.Combine(outputDirectory, "info.json"), _infoJsonFile);
            }
        }
        else if (_ysmJsonFile.Length > 0)
        {
            File.WriteAllBytes(Path.Combine(outputDirectory, "ysm.json"), _ysmJsonFile);
        }

        if (Debug)
        {
            File.WriteAllBytes(Path.Combine(outputDirectory, "_debug_m_decompressed.bin"), _decompressed);
            File.WriteAllBytes(Path.Combine(outputDirectory, "_debug_m_decrypted.bin"), _decrypted);
            File.WriteAllBytes(Path.Combine(outputDirectory, "_debug_m_binaryData.bin"), _binaryData);
        }

        void ExportMapped(List<(string Name, byte[] Data)> items, string defaultFolder, string extension)
        {
            foreach (var (name, data) in items)
            {
                string raw = name;
                if (!raw.EndsWith(extension)) raw += extension;

                var normalized = raw.Replace('\\', '/');
                var lastSlash = normalized.LastIndexOf('/');
                var parentPath = lastSlash >= 0 ? normalized[..lastSlash] : "";
                var fileName = lastSlash >= 0 ? normalized[(lastSlash + 1)..] : normalized;
                var safeFileName = SanitizeWindowsFilename(fileName);
                var safeRelativePath = string.IsNullOrEmpty(parentPath) ? safeFileName : parentPath + "/" + safeFileName;

                string rel;
                if (useLegacyRootLayout)
                {
                    rel = safeFileName;
                }
                else
                {
                    rel = defaultFolder + "/" + safeRelativePath;
                }

                var filePath = Path.Combine(outputDirectory, rel);
                var dir = Path.GetDirectoryName(filePath);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllBytes(filePath, data);
            }
        }

        ExportMapped(_soundFiles, "sounds", ".ogg");
        ExportMapped(_functionFiles, "functions", ".molang");
        ExportMapped(_languageFiles, "lang", ".json");
        ExportMapped(_animControllerFiles, "controller", ".json");
        ExportMapped(_modelFiles, "models", ".json");
        ExportMapped(_animationFiles, "animations", ".animation.json");
        ExportMapped(_textureFiles, "textures", ".png");
        ExportMapped(_specialImageFiles, "textures", ".png");

        foreach (var (name, data) in _avatarFiles)
        {
            var filePath = Path.Combine(outputDirectory, useLegacyRootLayout ? Path.Combine("avatar", SanitizeWindowsFilename(name + ".png")) : Path.Combine("avatar", SanitizeWindowsFilename(name + ".png")));
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllBytes(filePath, data);
        }

        foreach (var (name, data) in _backgroundFiles)
        {
            string rel = name;
            if (!Path.HasExtension(rel)) rel += ".png";
            ResolveRelative(rel, out var finalRel);
            var filePath = Path.Combine(outputDirectory, finalRel);
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllBytes(filePath, data);
        }
    }

    public override YsmResourceData GetResources()
    {
        static List<YsmResourceEntry> Convert(List<(string Name, byte[] Data)> source)
            => source.ConvertAll(x => new YsmResourceEntry(x.Name, x.Data));

        return new YsmResourceData(
            Convert(_modelFiles),
            Convert(_textureFiles),
            Convert(_animationFiles),
            Convert(_animControllerFiles),
            Convert(_soundFiles),
            Convert(_functionFiles),
            Convert(_languageFiles),
            Convert(_avatarFiles),
            Convert(_backgroundFiles),
            Convert(_specialImageFiles),
            _infoJsonFile.Length > 0 ? _infoJsonFile.ToArray() : null,
            _ysmJsonFile.Length > 0 ? _ysmJsonFile.ToArray() : null);
    }
}

namespace YSMParser.Core;

using System.Buffers.Binary;

/// <summary>
/// Sequential byte buffer reader, mirroring the C++ <c>BufferReader</c>.
/// </summary>
public sealed class BufferReader
{
    public ReadOnlySpan<byte> Data => _data;
    public int Size => _data.Length;
    public int Offset { get; set; }

    private readonly byte[] _data;

    public BufferReader(ReadOnlySpan<byte> data)
    {
        _data = data.ToArray();
        Offset = 0;
    }

    public BufferReader(byte[] data, int offset = 0)
    {
        _data = data;
        Offset = offset;
    }

    public byte PeekByte()
    {
        if (Offset >= _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        return _data[Offset];
    }

    public byte ReadByte()
    {
        if (Offset >= _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        return _data[Offset++];
    }

    public ushort ReadWordLE()
    {
        if (Offset + 1 >= _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        ushort result = BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan(Offset));
        Offset += 2;
        return result;
    }

    public ulong ReadVarint()
    {
        ulong value = 0;
        ulong shift = 0;
        byte b;
        do
        {
            b = ReadByte();
            value |= ((ulong)(b & 0x7F) << (int)shift);
            shift += 7;
        } while ((b & 0x80) != 0);
        return value;
    }

    public Vector3D ReadVector3D()
    {
        float x = ReadFloat();
        float y = ReadFloat();
        float z = ReadFloat();
        return new Vector3D(x, y, z);
    }

    public float ReadFloat()
    {
        if (Offset + 4 > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        float value = BinaryPrimitives.ReadSingleLittleEndian(_data.AsSpan(Offset));
        Offset += 4;
        return value;
    }

    public uint ReadDword()
    {
        if (Offset + 4 > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan(Offset));
        Offset += 4;
        return value;
    }

    public string ReadString()
    {
        uint len = (uint)ReadVarint();
        if (len == 0) return string.Empty;
        if (Offset + len > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        string s = System.Text.Encoding.UTF8.GetString(_data, Offset, (int)len);
        Offset += (int)len;
        return s;
    }

    public byte[] ReadByteSequence()
    {
        uint len = (uint)ReadVarint();
        if (Offset + len > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        if (len == 0) return Array.Empty<byte>();
        byte[] s = new byte[len];
        Array.Copy(_data, Offset, s, 0, (int)len);
        Offset += (int)len;
        return s;
    }

    public byte[] ReadBytesExactly(int len)
    {
        if (Offset + len > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        if (len == 0) return Array.Empty<byte>();
        byte[] s = new byte[len];
        Array.Copy(_data, Offset, s, 0, len);
        Offset += len;
        return s;
    }

    public bool IsEof() => Offset >= _data.Length;
}

public struct Vector3D
{
    public float X, Y, Z;

    public Vector3D(float x, float y, float z)
    {
        X = x; Y = y; Z = z;
    }

    public static Vector3D operator -(Vector3D a, Vector3D b) => new(a.X - b.X, a.Y - b.Y, a.Z - b.Z);
    public static Vector3D operator +(Vector3D a, Vector3D b) => new(a.X + b.X, a.Y + b.Y, a.Z + b.Z);
    public static Vector3D operator *(Vector3D a, float s) => new(a.X * s, a.Y * s, a.Z * s);
    public static Vector3D operator /(Vector3D a, float s) => new(a.X / s, a.Y / s, a.Z / s);
    public static Vector3D operator *(Vector3D a, Vector3D b) => new(a.X * b.X, a.Y * b.Y, a.Z * b.Z);

    public static readonly Vector3D Zero = new(0f, 0f, 0f);
}

namespace YSMParser.Core.Parsers;

using System.Buffers.Binary;

/// <summary>
/// Sequential byte buffer reader, mirroring the C++ <c>BufferReader</c>.
/// </summary>
public sealed class BufferReader
{
    /// <summary>The underlying byte buffer.</summary>
    public ReadOnlySpan<byte> Data => _data;
    /// <summary>The total size of the buffer in bytes.</summary>
    public int Size => _data.Length;
    /// <summary>The current read position.</summary>
    public int Offset { get; set; }

    private readonly byte[] _data;

    /// <summary>
    /// Creates a new reader from a read-only byte span. The data is copied.
    /// </summary>
    /// <param name="data">The source bytes.</param>
    public BufferReader(ReadOnlySpan<byte> data)
    {
        _data = data.ToArray();
        Offset = 0;
    }

    /// <summary>
    /// Creates a new reader from an existing byte array, optionally at an offset.
    /// </summary>
    /// <param name="data">The source byte array.</param>
    /// <param name="offset">The initial read offset. Defaults to 0.</param>
    public BufferReader(byte[] data, int offset = 0)
    {
        _data = data;
        Offset = offset;
    }

    /// <summary>
    /// Returns the byte at the current position without advancing the offset.
    /// </summary>
    /// <returns>The byte at the current offset.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if at end of buffer.</exception>
    public byte PeekByte()
    {
        if (Offset >= _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        return _data[Offset];
    }

    /// <summary>
    /// Reads a single byte and advances the offset.
    /// </summary>
    /// <returns>The byte at the current position.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if at end of buffer.</exception>
    public byte ReadByte()
    {
        if (Offset >= _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        return _data[Offset++];
    }

    /// <summary>
    /// Reads a 16-bit unsigned integer in little-endian order.
    /// </summary>
    /// <returns>The <see cref="ushort"/> value.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if insufficient bytes remain.</exception>
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

    /// <summary>
    /// Reads a variable-length encoded unsigned 64-bit integer (LEB128-like).
    /// </summary>
    /// <returns>The decoded <see cref="ulong"/> value.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if buffer ends mid-varint.</exception>
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

    /// <summary>
    /// Reads three consecutive floats and returns them as a <see cref="Vector3D"/>.
    /// </summary>
    /// <returns>The parsed 3D vector.</returns>
    public Vector3D ReadVector3D()
    {
        float x = ReadFloat();
        float y = ReadFloat();
        float z = ReadFloat();
        return new Vector3D(x, y, z);
    }

    /// <summary>
    /// Reads a 32-bit IEEE 754 single-precision float in little-endian order.
    /// </summary>
    /// <returns>The <see cref="float"/> value.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if fewer than 4 bytes remain.</exception>
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

    /// <summary>
    /// Reads a 32-bit unsigned integer in little-endian order.
    /// </summary>
    /// <returns>The <see cref="uint"/> value.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if fewer than 4 bytes remain.</exception>
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

    /// <summary>
    /// Reads a length-prefixed UTF-8 string. The length is encoded as a varint.
    /// </summary>
    /// <returns>The decoded string, or <see cref="string.Empty"/> if length is zero.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if the buffer ends prematurely.</exception>
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

    /// <summary>
    /// Reads a length-prefixed byte sequence. The length is encoded as a varint.
    /// </summary>
    /// <returns>The byte array, or an empty array if length is zero.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if the buffer ends prematurely.</exception>
    public byte[] ReadByteSequence()
    {
        uint len = (uint)ReadVarint();
        if (Offset + len > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        if (len == 0)
            return [];
        byte[] s = new byte[len];
        Array.Copy(_data, Offset, s, 0, (int)len);
        Offset += (int)len;
        return s;
    }

    /// <summary>
    /// Reads an exact number of bytes from the buffer.
    /// </summary>
    /// <param name="len">The number of bytes to read.</param>
    /// <returns>A byte array of the specified length.</returns>
    /// <exception cref="ParserIndexOutOfBoundException">Thrown if insufficient bytes remain.</exception>
    public byte[] ReadBytesExactly(int len)
    {
        if (Offset + len > _data.Length)
        {
            throw new ParserIndexOutOfBoundException();
        }
        if (len == 0)
            return [];
        byte[] s = new byte[len];
        Array.Copy(_data, Offset, s, 0, len);
        Offset += len;
        return s;
    }

    /// <summary>
    /// Returns <c>true</c> if the reader has reached the end of the buffer.
    /// </summary>
    public bool IsEof() => Offset >= _data.Length;
}

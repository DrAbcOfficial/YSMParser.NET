using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace YSMParser.Core.Utilities;

/// <summary>
/// Low-level memory read/write utilities for endian-aware integer access.
/// Supports byte, ushort, uint, and ulong in both little-endian and big-endian order.
/// </summary>
public static class MemoryUtils
{
    /// <summary>
    /// Reads a value of type <typeparamref name="T"/> from the buffer in little-endian order.
    /// Supports <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, and <see cref="ulong"/>.
    /// </summary>
    /// <typeparam name="T">The unmanaged type to read.</typeparam>
    /// <param name="buffer">The source byte buffer.</param>
    /// <returns>The value read from the buffer.</returns>
    /// <exception cref="NotSupportedException">Thrown for unsupported types.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T ReadLE<T>(ReadOnlySpan<byte> buffer) where T : unmanaged
    {
        if (typeof(T) == typeof(byte)) return ByteCast<T>(buffer[0]);
        if (typeof(T) == typeof(ushort)) return ByteCast<T>(BinaryPrimitives.ReadUInt16LittleEndian(buffer));
        if (typeof(T) == typeof(uint)) return ByteCast<T>(BinaryPrimitives.ReadUInt32LittleEndian(buffer));
        if (typeof(T) == typeof(ulong)) return ByteCast<T>(BinaryPrimitives.ReadUInt64LittleEndian(buffer));
        throw new NotSupportedException();
    }

    /// <summary>
    /// Reads a value of type <typeparamref name="T"/> from the buffer in big-endian order.
    /// Supports <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, and <see cref="ulong"/>.
    /// </summary>
    /// <typeparam name="T">The unmanaged type to read.</typeparam>
    /// <param name="buffer">The source byte buffer.</param>
    /// <returns>The value read from the buffer.</returns>
    /// <exception cref="NotSupportedException">Thrown for unsupported types.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T ReadBE<T>(ReadOnlySpan<byte> buffer) where T : unmanaged
    {
        if (typeof(T) == typeof(byte)) return ByteCast<T>(buffer[0]);
        if (typeof(T) == typeof(ushort)) return ByteCast<T>(BinaryPrimitives.ReadUInt16BigEndian(buffer));
        if (typeof(T) == typeof(uint)) return ByteCast<T>(BinaryPrimitives.ReadUInt32BigEndian(buffer));
        if (typeof(T) == typeof(ulong)) return ByteCast<T>(BinaryPrimitives.ReadUInt64BigEndian(buffer));
        throw new NotSupportedException();
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the buffer in little-endian order.
    /// Supports <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, and <see cref="ulong"/>.
    /// </summary>
    /// <typeparam name="T">The unmanaged type to write.</typeparam>
    /// <param name="buffer">The destination byte buffer.</param>
    /// <param name="value">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported types.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteLE<T>(Span<byte> buffer, T value) where T : unmanaged
    {
        if (typeof(T) == typeof(byte)) buffer[0] = AsByte(value);
        else if (typeof(T) == typeof(ushort)) BinaryPrimitives.WriteUInt16LittleEndian(buffer, AsU16(value));
        else if (typeof(T) == typeof(uint)) BinaryPrimitives.WriteUInt32LittleEndian(buffer, AsU32(value));
        else if (typeof(T) == typeof(ulong)) BinaryPrimitives.WriteUInt64LittleEndian(buffer, AsU64(value));
        else throw new NotSupportedException();
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the buffer in big-endian order.
    /// Supports <see cref="byte"/>, <see cref="ushort"/>, <see cref="uint"/>, and <see cref="ulong"/>.
    /// </summary>
    /// <typeparam name="T">The unmanaged type to write.</typeparam>
    /// <param name="buffer">The destination byte buffer.</param>
    /// <param name="value">The value to write.</param>
    /// <exception cref="NotSupportedException">Thrown for unsupported types.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteBE<T>(Span<byte> buffer, T value) where T : unmanaged
    {
        if (typeof(T) == typeof(byte)) buffer[0] = AsByte(value);
        else if (typeof(T) == typeof(ushort)) BinaryPrimitives.WriteUInt16BigEndian(buffer, AsU16(value));
        else if (typeof(T) == typeof(uint)) BinaryPrimitives.WriteUInt32BigEndian(buffer, AsU32(value));
        else if (typeof(T) == typeof(ulong)) BinaryPrimitives.WriteUInt64BigEndian(buffer, AsU64(value));
        else throw new NotSupportedException();
    }

    /// <summary>
    /// Reads a 24-bit unsigned integer in little-endian order.
    /// Used for reading the UTF-8 BOM prefix in YSM V3 files.
    /// </summary>
    /// <param name="buffer">The source byte buffer (must have at least 3 bytes).</param>
    /// <returns>The 24-bit value as a <see cref="uint"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint ReadLE24(ReadOnlySpan<byte> buffer)
    {
        return (uint)buffer[0]
            | ((uint)buffer[1] << 8)
            | ((uint)buffer[2] << 16);
    }

    /// <summary>
    /// Writes a 24-bit unsigned integer in little-endian order.
    /// </summary>
    /// <param name="buffer">The destination byte buffer (must have at least 3 bytes).</param>
    /// <param name="value">The 24-bit value to write (only the lower 24 bits are used).</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WriteLE24(Span<byte> buffer, uint value)
    {
        buffer[0] = (byte)(value & 0xFF);
        buffer[1] = (byte)((value >> 8) & 0xFF);
        buffer[2] = (byte)((value >> 16) & 0xFF);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static T ByteCast<T>(byte v) where T : unmanaged
    {
        if (typeof(T) == typeof(byte)) return Unsafe.As<byte, T>(ref v);
        throw new NotSupportedException();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static T ByteCast<T>(ushort v) where T : unmanaged
    {
        if (typeof(T) == typeof(ushort)) return Unsafe.As<ushort, T>(ref v);
        throw new NotSupportedException();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static T ByteCast<T>(uint v) where T : unmanaged
    {
        if (typeof(T) == typeof(uint)) return Unsafe.As<uint, T>(ref v);
        throw new NotSupportedException();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static T ByteCast<T>(ulong v) where T : unmanaged
    {
        if (typeof(T) == typeof(ulong)) return Unsafe.As<ulong, T>(ref v);
        throw new NotSupportedException();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte AsByte<T>(T v) where T : unmanaged => Unsafe.As<T, byte>(ref v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ushort AsU16<T>(T v) where T : unmanaged => Unsafe.As<T, ushort>(ref v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint AsU32<T>(T v) where T : unmanaged => Unsafe.As<T, uint>(ref v);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong AsU64<T>(T v) where T : unmanaged => Unsafe.As<T, ulong>(ref v);
}

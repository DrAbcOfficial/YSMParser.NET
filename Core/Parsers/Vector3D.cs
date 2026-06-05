namespace YSMParser.Core.Parsers;

/// <summary>
/// Represents a 3D vector with single-precision floating-point components.
/// Used for positions, normals, rotations, and pivots throughout the YSM format.
/// </summary>
public struct Vector3D(float x, float y, float z)
{
    /// <summary>The X component.</summary>
    public float X = x;
    /// <summary>The Y component.</summary>
    public float Y = y;
    /// <summary>The Z component.</summary>
    public float Z = z;

    /// <summary>Subtracts two vectors component-wise.</summary>
    public static Vector3D operator -(Vector3D a, Vector3D b) => new(a.X - b.X, a.Y - b.Y, a.Z - b.Z);
    /// <summary>Adds two vectors component-wise.</summary>
    public static Vector3D operator +(Vector3D a, Vector3D b) => new(a.X + b.X, a.Y + b.Y, a.Z + b.Z);
    /// <summary>Scales a vector by a scalar.</summary>
    public static Vector3D operator *(Vector3D a, float s) => new(a.X * s, a.Y * s, a.Z * s);
    /// <summary>Divides a vector by a scalar.</summary>
    public static Vector3D operator /(Vector3D a, float s) => new(a.X / s, a.Y / s, a.Z / s);
    /// <summary>Multiplies two vectors component-wise.</summary>
    public static Vector3D operator *(Vector3D a, Vector3D b) => new(a.X * b.X, a.Y * b.Y, a.Z * b.Z);

    /// <summary>A vector with all components set to zero.</summary>
    public static readonly Vector3D Zero = new(0f, 0f, 0f);
}

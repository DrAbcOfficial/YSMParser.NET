namespace YSMParser.Core.Parsers;

public struct Vector3D(float x, float y, float z)
{
    public float X = x, Y = y, Z = z;

    public static Vector3D operator -(Vector3D a, Vector3D b) => new(a.X - b.X, a.Y - b.Y, a.Z - b.Z);
    public static Vector3D operator +(Vector3D a, Vector3D b) => new(a.X + b.X, a.Y + b.Y, a.Z + b.Z);
    public static Vector3D operator *(Vector3D a, float s) => new(a.X * s, a.Y * s, a.Z * s);
    public static Vector3D operator /(Vector3D a, float s) => new(a.X / s, a.Y / s, a.Z / s);
    public static Vector3D operator *(Vector3D a, Vector3D b) => new(a.X * b.X, a.Y * b.Y, a.Z * b.Z);

    public static readonly Vector3D Zero = new(0f, 0f, 0f);
}

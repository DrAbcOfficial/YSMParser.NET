using System.Text.Json.Serialization;

namespace YSMParser.Export;

internal sealed record MinecraftGeometryFile(
    [property: JsonPropertyName("format_version")] string FormatVersion,
    [property: JsonPropertyName("minecraft:geometry")] List<MinecraftGeometry> Geometries);

internal sealed record MinecraftGeometry(
    MinecraftGeometryDescription Description,
    List<MinecraftBone> Bones);

internal sealed record MinecraftGeometryDescription(
    string Identifier,
    [property: JsonPropertyName("texture_width")] float TextureWidth = 64,
    [property: JsonPropertyName("texture_height")] float TextureHeight = 64);

internal sealed record MinecraftBone(
    string Name,
    string? Parent = null,
    List<float>? Pivot = null,
    List<float>? Rotation = null,
    List<MinecraftCube>? Cubes = null);

internal sealed record MinecraftCube(
    List<float>? Origin = null,
    List<float>? Size = null,
    List<float>? Pivot = null,
    List<float>? Rotation = null,
    MinecraftCubeUV? Uv = null,
    float Inflate = 0f);

internal sealed record MinecraftCubeUV(
    MinecraftCubeFaceUV? North = null,
    MinecraftCubeFaceUV? South = null,
    MinecraftCubeFaceUV? East = null,
    MinecraftCubeFaceUV? West = null,
    MinecraftCubeFaceUV? Up = null,
    MinecraftCubeFaceUV? Down = null);

internal sealed record MinecraftCubeFaceUV(
    [property: JsonPropertyName("uv")] List<float>? UvCoords = null,
    [property: JsonPropertyName("uv_size")] List<float>? UvSize = null);

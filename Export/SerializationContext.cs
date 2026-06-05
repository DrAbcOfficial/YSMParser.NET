using System.Text.Json.Serialization;

namespace YSMParser.Export;

[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = true)]
[JsonSerializable(typeof(GltfRoot))]
[JsonSerializable(typeof(MinecraftGeometryFile))]
[JsonSerializable(typeof(MinecraftCubeFaceUV))]
internal sealed partial class SerializationContext : JsonSerializerContext
{
}

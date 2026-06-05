using System.Text.Json.Serialization;

namespace YSMParser.Export;

internal sealed class GltfRoot
{
    [JsonPropertyName("asset")]
    public GltfAsset Asset { get; set; } = new();

    [JsonPropertyName("scene")]
    public int Scene { get; set; }

    [JsonPropertyName("scenes")]
    public List<GltfScene> Scenes { get; set; } = [];

    [JsonPropertyName("nodes")]
    public List<GltfNode> Nodes { get; set; } = [];

    [JsonPropertyName("meshes")]
    public List<GltfMesh> Meshes { get; set; } = [];

    [JsonPropertyName("accessors")]
    public List<GltfAccessor> Accessors { get; set; } = [];

    [JsonPropertyName("bufferViews")]
    public List<GltfBufferView> BufferViews { get; set; } = [];

    [JsonPropertyName("buffers")]
    public List<GltfBuffer> Buffers { get; set; } = [];

    [JsonPropertyName("images")]
    public List<GltfImage>? Images { get; set; }

    [JsonPropertyName("textures")]
    public List<GltfTexture>? Textures { get; set; }

    [JsonPropertyName("materials")]
    public List<GltfMaterial>? Materials { get; set; }

    [JsonPropertyName("samplers")]
    public List<GltfSampler>? Samplers { get; set; }
}

internal sealed class GltfAsset
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "2.0";

    [JsonPropertyName("generator")]
    public string Generator { get; set; } = "YSMParser.Export";
}

internal sealed class GltfScene
{
    [JsonPropertyName("nodes")]
    public List<int> Nodes { get; set; } = [];
}

internal sealed class GltfNode
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("mesh")]
    public int? Mesh { get; set; }

    [JsonPropertyName("children")]
    public List<int>? Children { get; set; }

    [JsonPropertyName("translation")]
    public float[]? Translation { get; set; }

    [JsonPropertyName("rotation")]
    public float[]? Rotation { get; set; }

    [JsonPropertyName("scale")]
    public float[]? Scale { get; set; }

    [JsonPropertyName("skin")]
    public int? Skin { get; set; }
}

internal sealed class GltfMesh
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("primitives")]
    public List<GltfPrimitive> Primitives { get; set; } = [];
}

internal sealed class GltfPrimitive
{
    [JsonPropertyName("attributes")]
    public Dictionary<string, int> Attributes { get; set; } = [];

    [JsonPropertyName("indices")]
    public int? Indices { get; set; }

    [JsonPropertyName("material")]
    public int? Material { get; set; }

    [JsonPropertyName("mode")]
    public int Mode { get; set; } = 4;
}

internal sealed class GltfAccessor
{
    [JsonPropertyName("bufferView")]
    public int? BufferView { get; set; }

    [JsonPropertyName("componentType")]
    public int ComponentType { get; set; }

    [JsonPropertyName("count")]
    public int Count { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = "SCALAR";

    [JsonPropertyName("max")]
    public float[]? Max { get; set; }

    [JsonPropertyName("min")]
    public float[]? Min { get; set; }

    [JsonPropertyName("byteOffset")]
    public int ByteOffset { get; set; }
}

internal sealed class GltfBufferView
{
    [JsonPropertyName("buffer")]
    public int Buffer { get; set; }

    [JsonPropertyName("byteOffset")]
    public int ByteOffset { get; set; }

    [JsonPropertyName("byteLength")]
    public int ByteLength { get; set; }

    [JsonPropertyName("target")]
    public int? Target { get; set; }

    [JsonPropertyName("byteStride")]
    public int? ByteStride { get; set; }
}

internal sealed class GltfBuffer
{
    [JsonPropertyName("byteLength")]
    public int ByteLength { get; set; }

    [JsonPropertyName("uri")]
    public string? Uri { get; set; }
}

internal sealed class GltfImage
{
    [JsonPropertyName("mimeType")]
    public string? MimeType { get; set; }

    [JsonPropertyName("bufferView")]
    public int? BufferView { get; set; }

    [JsonPropertyName("uri")]
    public string? Uri { get; set; }
}

internal sealed class GltfTexture
{
    [JsonPropertyName("sampler")]
    public int? Sampler { get; set; }

    [JsonPropertyName("source")]
    public int? Source { get; set; }
}

internal sealed class GltfMaterial
{
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    [JsonPropertyName("pbrMetallicRoughness")]
    public GltfPbrMetallicRoughness? PbrMetallicRoughness { get; set; }

    [JsonPropertyName("doubleSided")]
    public bool DoubleSided { get; set; }

    [JsonPropertyName("alphaMode")]
    public string? AlphaMode { get; set; }
}

internal sealed class GltfPbrMetallicRoughness
{
    [JsonPropertyName("baseColorTexture")]
    public GltfTextureInfo? BaseColorTexture { get; set; }

    [JsonPropertyName("baseColorFactor")]
    public float[] BaseColorFactor { get; set; } = [1f, 1f, 1f, 1f];

    [JsonPropertyName("metallicFactor")]
    public float MetallicFactor { get; set; } = 0f;

    [JsonPropertyName("roughnessFactor")]
    public float RoughnessFactor { get; set; } = 1f;
}

internal sealed class GltfTextureInfo
{
    [JsonPropertyName("index")]
    public int Index { get; set; }
}

internal sealed class GltfSampler
{
    [JsonPropertyName("magFilter")]
    public int? MagFilter { get; set; }

    [JsonPropertyName("minFilter")]
    public int? MinFilter { get; set; }

    [JsonPropertyName("wrapS")]
    public int WrapS { get; set; } = 10497;

    [JsonPropertyName("wrapT")]
    public int WrapT { get; set; } = 10497;
}

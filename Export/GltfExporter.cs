using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace YSMParser.Export;

/// <summary>
/// Specifies which planes to mirror when exporting geometry to glTF.
/// </summary>
[Flags]
public enum MirrorPlane
{
    /// <summary>No mirroring.</summary>
    None = 0,
    /// <summary>Mirror across the XY plane (negate Z).</summary>
    XY = 1,
    /// <summary>Mirror across the XZ plane (negate Y).</summary>
    XZ = 2,
    /// <summary>Mirror across the YZ plane (negate X).</summary>
    YZ = 4,
}

/// <summary>
/// Exports Minecraft Bedrock geometry JSON to glTF 2.0 format (.glb binary or .gltf JSON).
/// Handles coordinate system conversion, pivot/rotation translation, and cuboid-to-triangle mesh generation.
/// </summary>
public static class GltfExporter
{
    private const int GlbMagic = 0x46546C67;
    private const int GlbVersion = 2;
    private const int ChunkJson = 0x4E4F534A;
    private const int ChunkBin = 0x004E4942;
    private const float ExportScale = 1f / 16f;

    /// <summary>
    /// Exports Minecraft geometry JSON to a glTF 2.0 binary (.glb) byte array.
    /// The texture is embedded directly in the buffer if provided.
    /// </summary>
    /// <param name="geometryJson">The Minecraft Bedrock geometry JSON bytes.</param>
    /// <param name="texturePng">Optional PNG texture data to embed.</param>
    /// <param name="mirror">Optional mirror plane flags.</param>
    /// <returns>The complete .glb file as a byte array.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the geometry JSON cannot be deserialized.</exception>
    public static byte[] ToGlb(byte[] geometryJson, byte[]? texturePng, MirrorPlane mirror = MirrorPlane.None)
    {
        var geom = DeserializeGeometry(geometryJson);
        var model = geom.Geometries[0];

        using var binStream = new MemoryStream();
        var writer = new GltfBufferWriter(binStream);

        BuildGltfModel(model, writer, texturePng, mirror, out var root, embedTextureInBuffer: true, textureMimeType: "image/png");

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(root, SerializationContext.Default.GltfRoot);
        var paddedJson = PadTo4Bytes(jsonBytes);

        uint totalLength = (uint)(12 + 8 + paddedJson.Length + 8 + binStream.Length);

        using var ms = new MemoryStream((int)totalLength);
        WriteU32LE(ms, (uint)GlbMagic);
        WriteU32LE(ms, GlbVersion);
        WriteU32LE(ms, totalLength);

        WriteU32LE(ms, (uint)paddedJson.Length);
        WriteU32LE(ms, (uint)ChunkJson);
        ms.Write(paddedJson, 0, paddedJson.Length);

        WriteU32LE(ms, (uint)binStream.Length);
        WriteU32LE(ms, (uint)ChunkBin);
        binStream.Position = 0;
        binStream.CopyTo(ms);

        return ms.ToArray();
    }

    /// <summary>
    /// Exports Minecraft geometry JSON to a glTF 2.0 binary (.glb) as a <see cref="MemoryStream"/>.
    /// </summary>
    /// <param name="geometryJson">The Minecraft Bedrock geometry JSON bytes.</param>
    /// <param name="texturePng">Optional PNG texture data to embed.</param>
    /// <param name="mirror">Optional mirror plane flags.</param>
    /// <returns>A <see cref="MemoryStream"/> containing the .glb file data.</returns>
    public static MemoryStream ToGlbStream(byte[] geometryJson, byte[]? texturePng, MirrorPlane mirror = MirrorPlane.None)
    {
        return new MemoryStream(ToGlb(geometryJson, texturePng, mirror));
    }

    /// <summary>
    /// Exports Minecraft geometry JSON to a glTF 2.0 binary (.glb) file on disk.
    /// </summary>
    /// <param name="outputPath">The output file path (should end with .glb).</param>
    /// <param name="geometryJson">The Minecraft Bedrock geometry JSON bytes.</param>
    /// <param name="texturePng">Optional PNG texture data to embed.</param>
    /// <param name="mirror">Optional mirror plane flags.</param>
    public static void ToGlb(string outputPath, byte[] geometryJson, byte[]? texturePng, MirrorPlane mirror = MirrorPlane.None)
    {
        var data = ToGlb(geometryJson, texturePng, mirror);
        File.WriteAllBytes(outputPath, data);
    }

    /// <summary>
    /// Exports Minecraft geometry JSON to glTF 2.0 separate files (.gltf + .bin + optional .png texture).
    /// All output files share the same base name.
    /// </summary>
    /// <param name="outputDir">The output directory path.</param>
    /// <param name="baseName">The base file name (without extension) for the output files.</param>
    /// <param name="geometryJson">The Minecraft Bedrock geometry JSON bytes.</param>
    /// <param name="texturePng">Optional PNG texture data to write as a separate file.</param>
    /// <param name="mirror">Optional mirror plane flags.</param>
    /// <exception cref="InvalidOperationException">Thrown if the geometry JSON cannot be deserialized.</exception>
    public static void ToGltf(string outputDir, string baseName, byte[] geometryJson, byte[]? texturePng, MirrorPlane mirror = MirrorPlane.None)
    {
        Directory.CreateDirectory(outputDir);
        var geom = DeserializeGeometry(geometryJson);
        var model = geom.Geometries[0];

        using var binStream = new MemoryStream();
        var writer = new GltfBufferWriter(binStream);
        var binFileName = baseName + ".bin";

        BuildGltfModel(model, writer, texturePng, mirror, out var root, embedTextureInBuffer: false, textureMimeType: null);

        if (texturePng is { Length: > 0 })
        {
            var texFileName = baseName + ".png";
            File.WriteAllBytes(Path.Combine(outputDir, texFileName), texturePng);
            root.Images = [new GltfImage { Uri = texFileName }];
            root.Textures = [new GltfTexture { Source = 0 }];
            root.Samplers = [new GltfSampler()];
            root.Materials![0].PbrMetallicRoughness!.BaseColorTexture = new GltfTextureInfo { Index = 0 };
        }

        File.WriteAllBytes(Path.Combine(outputDir, binFileName), binStream.ToArray());

        if (root.Buffers.Count > 0)
            root.Buffers[0].Uri = binFileName;

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(root, SerializationContext.Default.GltfRoot);
        File.WriteAllBytes(Path.Combine(outputDir, baseName + ".gltf"), jsonBytes);
    }

    private static void BuildGltfModel(
        MinecraftGeometry geometry,
        GltfBufferWriter writer,
        byte[]? texturePng,
        MirrorPlane mirror,
        out GltfRoot root,
        bool embedTextureInBuffer,
        string? textureMimeType)
    {
        root = new GltfRoot();
        var nodes = new List<GltfNode>();
        var meshes = new List<GltfMesh>();
        var accessors = new List<GltfAccessor>();
        var bufferViews = new List<GltfBufferView>();
        var materials = new List<GltfMaterial>();
        var boneNodeIndex = new Dictionary<string, int>();

        int textureWidth = (int)(geometry.Description.TextureWidth > 0 ? geometry.Description.TextureWidth : 64);
        int textureHeight = (int)(geometry.Description.TextureHeight > 0 ? geometry.Description.TextureHeight : 64);

        int imageBufferViewIndex = -1;
        if (texturePng is { Length: > 0 } && embedTextureInBuffer)
        {
            var imageByteOffset = writer.WriteAlignedBytes(texturePng, 4);
            imageBufferViewIndex = bufferViews.Count;
            bufferViews.Add(new GltfBufferView
            {
                Buffer = 0,
                ByteOffset = imageByteOffset,
                ByteLength = texturePng.Length,
            });
        }

        foreach (var bone in geometry.Bones)
        {
            int nodeIdx = nodes.Count;
            var node = new GltfNode { Name = bone.Name };
            boneNodeIndex[bone.Name] = nodeIdx;

            if (bone.Rotation is { Count: >= 3 })
            {
                var euler = ConvertBedrockRotation(bone.Rotation);
                var q = CreateBlockbenchQuaternion(euler);
                node.Rotation = [q.X, q.Y, q.Z, q.W];
            }

            if (bone.Pivot is { Count: >= 3 })
            {
                var pivot = ConvertBedrockPivot(bone.Pivot);
                node.Translation = [pivot.X * ExportScale, pivot.Y * ExportScale, pivot.Z * ExportScale];
            }

            nodes.Add(node);
        }

        foreach (var bone in geometry.Bones)
        {
            if (bone.Parent is not null && boneNodeIndex.TryGetValue(bone.Parent, out var parentIdx))
            {
                var childIdx = boneNodeIndex[bone.Name];
                nodes[parentIdx].Children ??= [];
                nodes[parentIdx].Children!.Add(childIdx);

                if (bone.Pivot is { Count: >= 3 } &&
                    geometry.Bones.FirstOrDefault(b => b.Name == bone.Parent) is { Pivot.Count: >= 3 } parentBone)
                {
                    var parentPivot = ConvertBedrockPivot(parentBone.Pivot);
                    var childPivot = ConvertBedrockPivot(bone.Pivot);
                    var relativeOffset = childPivot - parentPivot;
                    nodes[childIdx].Translation = [relativeOffset.X * ExportScale, relativeOffset.Y * ExportScale, relativeOffset.Z * ExportScale];
                }
            }
        }

        var boneWorldPos = new Dictionary<string, Vector3>();
        var boneWorldRot = new Dictionary<string, Quaternion>();
        foreach (var bone in geometry.Bones)
        {
            var localRot = bone.Rotation is { Count: >= 3 }
                ? CreateBlockbenchQuaternion(ConvertBedrockRotation(bone.Rotation))
                : Quaternion.Identity;
            var localTrans = nodes[boneNodeIndex[bone.Name]].Translation is { Length: >= 3 } t
                ? new Vector3(t[0], t[1], t[2])
                : Vector3.Zero;

            if (bone.Parent is null)
            {
                boneWorldPos[bone.Name] = new Vector3(
                    bone.Pivot is { Count: >= 3 } ? -bone.Pivot[0] : 0,
                    bone.Pivot is { Count: >= 3 } ? bone.Pivot[1] : 0,
                    bone.Pivot is { Count: >= 3 } ? bone.Pivot[2] : 0);
                boneWorldRot[bone.Name] = localRot;
            }
            else
            {
                var pWPos = boneWorldPos[bone.Parent];
                var pWRot = boneWorldRot[bone.Parent];
                boneWorldPos[bone.Name] = pWPos + Vector3.Transform(localTrans / ExportScale, pWRot);
                boneWorldRot[bone.Name] = Quaternion.Multiply(pWRot, localRot);
            }
        }

        var rootNodes = new List<int>();
        foreach (var bone in geometry.Bones)
        {
            if (bone.Parent is null)
                rootNodes.Add(boneNodeIndex[bone.Name]);
        }

        int matIndex;
        if (texturePng is { Length: > 0 })
        {
            var mat = new GltfMaterial { Name = "material", DoubleSided = false };
            mat.PbrMetallicRoughness = new GltfPbrMetallicRoughness();
            if (embedTextureInBuffer)
            {
                mat.PbrMetallicRoughness.BaseColorTexture = new GltfTextureInfo { Index = 0 };
            }
            matIndex = materials.Count;
            materials.Add(mat);
        }
        else
        {
            materials.Add(new GltfMaterial { Name = "material", DoubleSided = false });
            matIndex = 0;
        }

        foreach (var bone in geometry.Bones)
        {
            if (bone.Cubes is null or { Count: 0 }) continue;

            int boneIdx = boneNodeIndex[bone.Name];
            var bonePivot = bone.Pivot is { Count: >= 3 }
                ? ConvertBedrockPivot(bone.Pivot)
                : Vector3.Zero;

            foreach (var cube in bone.Cubes)
            {
                if (cube.Origin is not { Count: >= 3 } || cube.Size is not { Count: >= 3 })
                    continue;

                var (from, to) = ConvertBedrockCubeBounds(cube);
                var cubePivot = ConvertBedrockCubePivot(cube);
                float inflate = cube.Inflate;

                var center = (from + to) * 0.5f;
                var halfSize = (to - from) * 0.5f;
                var min = center - new Vector3(halfSize.X + inflate, halfSize.Y + inflate, halfSize.Z + inflate) - cubePivot;
                var max = center + new Vector3(halfSize.X + inflate, halfSize.Y + inflate, halfSize.Z + inflate) - cubePivot;
                if (min.X == max.X) max.X += 0.001f;
                if (min.Y == max.Y) max.Y += 0.001f;
                if (min.Z == max.Z) max.Z += 0.001f;

                float lx = min.X * ExportScale;
                float ly = min.Y * ExportScale;
                float lz = min.Z * ExportScale;
                float hx = max.X * ExportScale;
                float hy = max.Y * ExportScale;
                float hz = max.Z * ExportScale;

                var (posBuf, normBuf, uvBuf, idxBuf) = BuildCubeMeshData(
                    cube, textureWidth, textureHeight, lx, ly, lz, hx, hy, hz);

                int posView = writer.WriteFloatsAligned(posBuf);
                int normView = writer.WriteFloatsAligned(normBuf);
                int uvView = writer.WriteFloatsAligned(uvBuf);
                int idxView = writer.WriteIndicesAligned(idxBuf);

                int vertCount = posBuf.Count / 3;

                int posAcc = accessors.Count;
                accessors.Add(new GltfAccessor
                {
                    BufferView = bufferViews.Count,
                    ComponentType = 5126,
                    Count = vertCount,
                    Type = "VEC3",
                    Min = ComputeMin(posBuf),
                    Max = ComputeMax(posBuf),
                });
                bufferViews.Add(new GltfBufferView
                {
                    Buffer = 0,
                    ByteOffset = posView,
                    ByteLength = posBuf.Count * 4,
                    Target = 34962,
                });

                int normAcc = accessors.Count;
                accessors.Add(new GltfAccessor
                {
                    BufferView = bufferViews.Count,
                    ComponentType = 5126,
                    Count = vertCount,
                    Type = "VEC3",
                });
                bufferViews.Add(new GltfBufferView
                {
                    Buffer = 0,
                    ByteOffset = normView,
                    ByteLength = normBuf.Count * 4,
                    Target = 34962,
                });

                int uvAcc = accessors.Count;
                accessors.Add(new GltfAccessor
                {
                    BufferView = bufferViews.Count,
                    ComponentType = 5126,
                    Count = vertCount,
                    Type = "VEC2",
                });
                bufferViews.Add(new GltfBufferView
                {
                    Buffer = 0,
                    ByteOffset = uvView,
                    ByteLength = uvBuf.Count * 4,
                    Target = 34962,
                });

                int idxAcc = accessors.Count;
                accessors.Add(new GltfAccessor
                {
                    BufferView = bufferViews.Count,
                    ComponentType = 5125,
                    Count = idxBuf.Count,
                    Type = "SCALAR",
                });
                bufferViews.Add(new GltfBufferView
                {
                    Buffer = 0,
                    ByteOffset = idxView,
                    ByteLength = idxBuf.Count * 4,
                    Target = 34963,
                });

                var prim = new GltfPrimitive { Material = matIndex };
                prim.Attributes["POSITION"] = posAcc;
                prim.Attributes["NORMAL"] = normAcc;
                prim.Attributes["TEXCOORD_0"] = uvAcc;
                prim.Indices = idxAcc;

                int meshIdx = meshes.Count;
                meshes.Add(new GltfMesh { Name = $"cube_{bone.Name}", Primitives = [prim] });

                int cubeNodeIdx = nodes.Count;
                var cubeNode = new GltfNode
                {
                    Name = $"cube_{bone.Name}",
                    Mesh = meshIdx,
                };

                var txLocal = cubePivot - bonePivot;
                cubeNode.Translation = [txLocal.X * ExportScale, txLocal.Y * ExportScale, txLocal.Z * ExportScale];

                if (cube.Rotation is { Count: >= 3 })
                {
                    var euler = ConvertBedrockRotation(cube.Rotation);
                    var q = CreateBlockbenchQuaternion(euler);
                    cubeNode.Rotation = [q.X, q.Y, q.Z, q.W];
                }

                nodes.Add(cubeNode);
                nodes[boneIdx].Children ??= [];
                nodes[boneIdx].Children!.Add(cubeNodeIdx);
            }
        }

        if (mirror != MirrorPlane.None)
        {
            float sx = mirror.HasFlag(MirrorPlane.YZ) ? -1f : 1f;
            float sy = mirror.HasFlag(MirrorPlane.XZ) ? -1f : 1f;
            float sz = mirror.HasFlag(MirrorPlane.XY) ? -1f : 1f;

            int mirrorRootIdx = nodes.Count;
            nodes.Add(new GltfNode
            {
                Name = "_mirror_root",
                Scale = [sx, sy, sz],
                Children = rootNodes,
            });

            int negCount = (mirror.HasFlag(MirrorPlane.XY) ? 1 : 0)
                         + (mirror.HasFlag(MirrorPlane.XZ) ? 1 : 0)
                         + (mirror.HasFlag(MirrorPlane.YZ) ? 1 : 0);
            if (negCount % 2 == 1)
            {
                foreach (var mat in materials)
                    mat.DoubleSided = true;
            }

            rootNodes = [mirrorRootIdx];
        }

        root.Scenes.Add(new GltfScene { Nodes = rootNodes });
        root.Scene = 0;
        root.Nodes = nodes;
        root.Meshes = meshes;
        root.Accessors = accessors;
        root.BufferViews = bufferViews;
        root.Buffers.Add(new GltfBuffer { ByteLength = (int)writer.Length });
        root.Materials = materials;

        if (embedTextureInBuffer && texturePng is { Length: > 0 })
        {
            root.Images = [new GltfImage { MimeType = textureMimeType, BufferView = imageBufferViewIndex }];
            root.Textures = [new GltfTexture { Source = 0 }];
            root.Samplers = [new GltfSampler()];
        }
    }

    private static (List<float> pos, List<float> norm, List<float> uv, List<uint> idx) BuildCubeMeshData(
        MinecraftCube cube, float texW, float texH,
        float minX, float minY, float minZ, float maxX, float maxY, float maxZ)
    {
        var positions = new List<float>();
        var normals = new List<float>();
        var uvs = new List<float>();
        var indices = new List<uint>();

        float tw = texW > 0 ? texW : 64f;
        float th = texH > 0 ? texH : 64f;

        var cubeUV = cube.Uv;
        if (cubeUV?.IsBoxUV == true && cube.Size is { Count: >= 3 })
            cubeUV = cubeUV.Expand(cube.Size[0], cube.Size[1], cube.Size[2]);

        // East (x = max)
        AddFace(positions, normals, uvs, indices,
            maxX, maxY, maxZ, maxX, maxY, minZ, maxX, minY, maxZ, maxX, minY, minZ,
            1, 0, 0,
            GetFaceUV(cubeUV?.East, tw, th));

        // West (x = min)
        AddFace(positions, normals, uvs, indices,
            minX, maxY, minZ, minX, maxY, maxZ, minX, minY, minZ, minX, minY, maxZ,
            -1, 0, 0,
            GetFaceUV(cubeUV?.West, tw, th));

        // Up (y = max)
        AddFace(positions, normals, uvs, indices,
            minX, maxY, minZ, maxX, maxY, minZ, minX, maxY, maxZ, maxX, maxY, maxZ,
            0, 1, 0,
            GetFaceUV(cubeUV?.Up, tw, th));

        // Down (y = min)
        AddFace(positions, normals, uvs, indices,
            minX, minY, maxZ, maxX, minY, maxZ, minX, minY, minZ, maxX, minY, minZ,
            0, -1, 0,
            GetFaceUV(cubeUV?.Down, tw, th));

        // South (z = max)
        AddFace(positions, normals, uvs, indices,
            minX, maxY, maxZ, maxX, maxY, maxZ, minX, minY, maxZ, maxX, minY, maxZ,
            0, 0, 1,
            GetFaceUV(cubeUV?.South, tw, th));

        // North (z = min)
        AddFace(positions, normals, uvs, indices,
            maxX, maxY, minZ, minX, maxY, minZ, maxX, minY, minZ, minX, minY, minZ,
            0, 0, -1,
            GetFaceUV(cubeUV?.North, tw, th));

        return (positions, normals, uvs, indices);
    }

    private static void AddFace(
        List<float> positions, List<float> normals, List<float> uvs, List<uint> indices,
        float x0, float y0, float z0, float x1, float y1, float z1,
        float x2, float y2, float z2, float x3, float y3, float z3,
        float nx, float ny, float nz,
        (float u0, float v0, float u1, float v1, float u2, float v2, float u3, float v3) faceUV)
    {
        uint baseIndex = (uint)(positions.Count / 3);

        positions.AddRange([x0, y0, z0]);
        positions.AddRange([x1, y1, z1]);
        positions.AddRange([x2, y2, z2]);
        positions.AddRange([x3, y3, z3]);

        for (int i = 0; i < 4; i++)
            normals.AddRange([nx, ny, nz]);

        uvs.AddRange([faceUV.u0, faceUV.v0]);
        uvs.AddRange([faceUV.u1, faceUV.v1]);
        uvs.AddRange([faceUV.u2, faceUV.v2]);
        uvs.AddRange([faceUV.u3, faceUV.v3]);

        indices.AddRange([baseIndex, baseIndex + 2, baseIndex + 1]);
        indices.AddRange([baseIndex + 2, baseIndex + 3, baseIndex + 1]);
    }

    private static (float u0, float v0, float u1, float v1, float u2, float v2, float u3, float v3) GetFaceUV(
        MinecraftCubeFaceUV? faceUv, float texW, float texH)
    {
        if (faceUv?.UvCoords is { Count: >= 2 })
        {
            float fu = faceUv.UvCoords[0];
            float fv = faceUv.UvCoords[1];
            float du = faceUv.UvSize is { Count: >= 2 } ? faceUv.UvSize[0] : 0f;
            float dv = faceUv.UvSize is { Count: >= 2 } ? faceUv.UvSize[1] : 0f;

            float u0 = fu / texW;
            float v0 = fv / texH;
            float u1 = (fu + du) / texW;
            float v1 = (fv + dv) / texH;

            return (u0, v0, u1, v0, u0, v1, u1, v1);
        }

        return (0f, 0f, 0f, 0f, 0f, 0f, 0f, 0f);
    }

    private static MinecraftGeometryFile DeserializeGeometry(byte[] geometryJson)
    {
        return JsonSerializer.Deserialize(geometryJson, SerializationContext.Default.MinecraftGeometryFile)
            ?? throw new InvalidOperationException("Failed to deserialize geometry JSON.");
    }

    private static Vector3 ConvertBedrockPivot(List<float> pivot)
    {
        return new Vector3(-pivot[0], pivot[1], pivot[2]);
    }

    private static Vector3 ConvertBedrockRotation(List<float> rotation)
    {
        return new Vector3(-rotation[0], -rotation[1], rotation[2]);
    }

    private static Vector3 ConvertBedrockCubePivot(MinecraftCube cube)
    {
        return cube.Pivot is { Count: >= 3 }
            ? ConvertBedrockPivot(cube.Pivot)
            : Vector3.Zero;
    }

    private static (Vector3 From, Vector3 To) ConvertBedrockCubeBounds(MinecraftCube cube)
    {
        var origin = cube.Origin!;
        var size = cube.Size!;
        var from = new Vector3(-(origin[0] + size[0]), origin[1], origin[2]);
        var to = new Vector3(from.X + size[0], from.Y + size[1], from.Z + size[2]);
        return (from, to);
    }

    internal static Quaternion CreateBlockbenchQuaternion(Vector3 eulerDegrees)
    {
        float rx = eulerDegrees.X * MathF.PI / 180f;
        float ry = eulerDegrees.Y * MathF.PI / 180f;
        float rz = eulerDegrees.Z * MathF.PI / 180f;
        var m = Matrix4x4.CreateRotationX(rx)
              * Matrix4x4.CreateRotationY(ry)
              * Matrix4x4.CreateRotationZ(rz);
        return Quaternion.CreateFromRotationMatrix(m);
    }

    private static float[] ComputeMin(List<float> data)
    {
        float minX = float.MaxValue, minY = float.MaxValue, minZ = float.MaxValue;
        for (int i = 0; i < data.Count; i += 3)
        {
            minX = MathF.Min(minX, data[i]);
            minY = MathF.Min(minY, data[i + 1]);
            minZ = MathF.Min(minZ, data[i + 2]);
        }
        return [minX, minY, minZ];
    }

    private static float[] ComputeMax(List<float> data)
    {
        float maxX = float.MinValue, maxY = float.MinValue, maxZ = float.MinValue;
        for (int i = 0; i < data.Count; i += 3)
        {
            maxX = MathF.Max(maxX, data[i]);
            maxY = MathF.Max(maxY, data[i + 1]);
            maxZ = MathF.Max(maxZ, data[i + 2]);
        }
        return [maxX, maxY, maxZ];
    }

    private static byte[] PadTo4Bytes(byte[] data)
    {
        int rem = data.Length % 4;
        if (rem == 0) return data;
        int pad = 4 - rem;
        var result = new byte[data.Length + pad];
        Array.Copy(data, result, data.Length);
        for (int i = data.Length; i < result.Length; i++)
            result[i] = 0x20;
        return result;
    }

    private static void WriteU32LE(Stream s, uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        buf[0] = (byte)(value & 0xFF);
        buf[1] = (byte)((value >> 8) & 0xFF);
        buf[2] = (byte)((value >> 16) & 0xFF);
        buf[3] = (byte)((value >> 24) & 0xFF);
        s.Write(buf);
    }
}

internal sealed class GltfBufferWriter(Stream stream)
{
    public long Length => stream.Length;

    public int WriteFloatsAligned(List<float> data)
    {
        int byteOffset = (int)stream.Length;
        var bytes = new byte[data.Count * 4];
        Buffer.BlockCopy(data.ToArray(), 0, bytes, 0, bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
        return byteOffset;
    }

    public int WriteIndicesAligned(List<uint> data)
    {
        AlignTo(4);
        int byteOffset = (int)stream.Length;
        var bytes = new byte[data.Count * 4];
        Buffer.BlockCopy(data.ToArray(), 0, bytes, 0, bytes.Length);
        stream.Write(bytes, 0, bytes.Length);
        return byteOffset;
    }

    public int WriteAlignedBytes(byte[] data, int alignment)
    {
        AlignTo(alignment);
        int byteOffset = (int)stream.Length;
        stream.Write(data, 0, data.Length);
        return byteOffset;
    }

    private void AlignTo(int alignment)
    {
        long pos = stream.Length;
        int rem = (int)(pos % alignment);
        if (rem != 0)
        {
            int pad = alignment - rem;
            stream.Write(new byte[pad], 0, pad);
        }
    }
}

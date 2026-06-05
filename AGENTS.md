# AGENTS.md — YSMParser.Net

## Build & Test

```powershell
# Build the entire solution
dotnet build

# Run all tests (xunit v3 via Microsoft.TestingPlatform)
dotnet test

# Run a single test
dotnet test --filter "FullyQualifiedName~TestName"

# Run the CLI (--project required: output assembly name is YSMParser, not the project name)
dotnet run --project CLI -- -i <input-dir> -o <output-dir>
```

## Project Map

| Project | Type | Purpose |
|---|---|---|
| `Core/` | Library | Parses `.ysm` binary files. Crypto (AES, XChaCha20, MT19937, zstd), binary reader, custom JSON serialization. |
| `CLI/` | Exe | Console entrypoint. Discovers `*.ysm` in an input directory tree and runs the parser. |
| `Export/` | Library | Standalone GLB/glTF 2.0 exporter from Minecraft Bedrock geometry JSON. **Not consumed by any parser code.** |
| `Tests/` | Tests | xunit.v3 unit tests for Core utilities and crypto. |

## Solution & Toolchain

- **SDK**: .NET 10.0.300 (pinned in `global.json`)
- **Solution format**: `.slnx` (new XML-based format, not the legacy `.sln`)
- **Test framework**: xunit.v3 (`3.2.2`) with `UseMicrosoftTestingPlatformRunner` and `TestingPlatformDotnetTestSupport` — not the classic v2 runner
- **Test runner config**: `Tests/xunit.runner.json` is copied to output (`PreserveNewest`)
- **InternalsVisibleTo**: `Core` exposes internals to `YSMParser.Tests`

## Architecture Notes

### Parser versions

The `YSMParserFactory.Create()` / `CreateFromBytes()` detects the version from magic bytes and crypto tag:

- **V1** (`YSMParserV1`): magic `YSGP` at offset 0, crypto byte `1` at offset 4. AES-CBC + zlib per file entry.
- **V2** (`YSMParserV2`): magic `YSGP` at offset 0, crypto byte `2` at offset 4. Adds JavaRandom-based key derivation.
- **V3** (`YSMParserV3`): magic `YSGP` at offset 3, with a 3-byte UTF-8 BOM prefix (`0xBFBBEF`). XChaCha20 with dynamic rounds + MT19937 XOR + zstd. Has its own `format` version header and supports format upgrades 1–32+.

### Global usings in Core

The Core project has `<Using>` directives, so `using` is auto-applied for:
- `YSMParser.Core.Crypto`
- `YSMParser.Core.Parsers`
- `YSMParser.Core.Utilities`

### Legacy vs modern layout (V3)

When V3 has no `ysm.json` (no `_ysmJsonFile`), it uses a flat legacy output layout. Otherwise it produces a structured directory tree with `models/`, `textures/`, `animations/`, `controller/`, `sounds/`, `functions/`, `lang/` subdirectories.

### GLB/glTF export

The `Export` project is a standalone library. It deserializes Minecraft Bedrock geometry JSON and produces glTF 2.0 `.glb` (binary) or `.gltf` (separate JSON + .bin + texture). It handles pivot/rotation conversion from Bedrock coordinate space and cuboid to triangle-mesh conversion, including UV reconstruction.

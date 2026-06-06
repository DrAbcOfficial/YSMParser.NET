# YSMParser.Net

A pure .NET parser for `.ysm` model files — a encrypted binary format used for Minecraft player models.

[Example](https://github.com/DrAbcOfficial/YSMViewer)

## Quick Start

```powershell
dotnet build
dotnet run --project CLI -- -i ./input -o ./output
```

- **SDK**: .NET 10.0.300 (see `global.json`)
- **Test**: `dotnet test` (xunit v3)

## CLI Usage

```
YSMParser -i <input> -o <output> [options]
YSMParser -i <input> -n [--info]
```

| Flag | Description |
|---|---|
| `-i, --input <dir>` | Input directory (required). |
| `-o, --output <dir>` | Output directory. |
| `-n, --info` | Print model details without extracting. |
| `-v, --verbose` | Verbose logging. |
| `-d, --debug` | Export all raw binary products (V3 only). |
| `-f, --format` | Pretty-print JSON output. |
| `-j, --threads <n>` | Parallel worker count (default 1). |
| `--version` | Print version and exit. |
| `-h, --help` | Show help. |

## Supported Formats

- **V1** — AES-CBC + zlib
- **V2** — AES-CBC + JavaRandom key derivation + zlib
- **V3** — XChaCha20 (dynamic rounds) + MT19937 XOR + zstd, with structured output layout

## Acknowlegements

[YSMParser](https://github.com/OpenYSM/YSMParser)

## Project Structure

| Project | Purpose |
|---|---|
| `Core/` | Parsing, crypto, binary reading, JSON generation. |
| `CLI/` | Console entrypoint, file discovery, batch processing. |
| `Export/` | Standalone GLB/glTF exporter from Bedrock geometry JSON. |
| `Tests/` | Unit tests for crypto and utilities. |

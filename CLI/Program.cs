using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using YSMParser.Core.Parsers;

namespace YSMParser.CLI;

internal static class Program
{
    private const string Version = "0.3.5-net";

    private static int Main(string[] args)
    {
        if (args.Length == 0 || IsFlag(args, "--help") || IsFlag(args, "-h"))
        {
            PrintUsage();
            return 0;
        }
        if (IsFlag(args, "--version"))
        {
            Console.WriteLine(Version);
            return 0;
        }

        string? inputPath = GetOption(args, "-i", "--input");
        string? outputDir = GetOption(args, "-o", "--output");
        bool infoOnly = HasFlag(args, "-n", "--info");
        bool peek = HasFlag(args, "-p", "--peek");
        bool verbose = HasFlag(args, "-v", "--verbose");
        bool debug = HasFlag(args, "-d", "--debug");
        bool formatJson = HasFlag(args, "-f", "--format");
        int threads = 1;
        string? threadsArg = GetOption(args, "-j", "--threads");
        if (threadsArg != null && int.TryParse(threadsArg, out var t) && t > 0)
        {
            threads = t;
        }

        if (string.IsNullOrEmpty(inputPath))
        {
            Console.Error.WriteLine("[ YSMParser ] --input is required.");
            PrintUsage();
            return 1;
        }
        if (!infoOnly && !peek && string.IsNullOrEmpty(outputDir))
        {
            Console.Error.WriteLine("[ YSMParser ] --output is required when not using --info or --peek.");
            PrintUsage();
            return 1;
        }

        try
        {
            if (!File.Exists(inputPath) && !Directory.Exists(inputPath))
            {
                throw new FileNotFoundException($"Input path does not exist: {inputPath}");
            }
            if (!infoOnly && !peek && outputDir is not null && !Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            var tasks = CollectTasks(inputPath, outputDir ?? string.Empty, infoOnly || peek);
            if (tasks.Count == 0)
            {
                Console.WriteLine($"[ YSMParser ] No .ysm files found in {inputPath}");
                return 0;
            }

            int workerCount = Math.Min(threads, tasks.Count);
            if (verbose && workerCount > 1)
            {
                Console.Error.WriteLine("[ YSMParser ] Verbose mode requires ordered output; forcing --threads 1.");
                workerCount = 1;
            }

            int succeeded = 0;
            int failed = 0;
            var sw = Stopwatch.StartNew();

            for (int i = 0; i < tasks.Count; i++)
            {
                var task = tasks[i];
                var fileStart = Stopwatch.StartNew();
                bool ok = false;
                string error = string.Empty;
                try
                {
                    var parser = YSMParserFactory.Create(task.InputPath);
                    parser.Verbose = verbose;
                    parser.Debug = debug;
                    parser.FormatJson = formatJson;
                    int version = parser.GetYSGPVersion();

                    if (peek)
                    {
                        using (parser)
                        {
                            var fi = new FileInfo(task.InputPath);
                            Console.WriteLine($"[ {task.FileName} ]  ({fi.Length:N0} bytes, V{version})");
                            var result = parser.Peek();
                            PrintPeekResult(result);
                        }
                        ok = true;
                    }
                    else if (infoOnly)
                    {
                        var fi = new FileInfo(task.InputPath);
                        Console.WriteLine($"[ {task.FileName} ]  ({fi.Length:N0} bytes, V{version})");
                        parser.PrintInfo(Console.Out);
                        ok = true;
                    }
                    else
                    {
                        Directory.CreateDirectory(task.OutputDir);
                        if (verbose)
                            Console.WriteLine($"[ YSMParser ] Detected version: {version}");
                        parser.Parse();
                        if (verbose)
                            Console.WriteLine("[ YSMParser ] Exporting resources...");
                        parser.SaveToDirectory(task.OutputDir);
                        ok = true;
                    }
                }
                catch (Exception ex)
                {
                    error = ex.Message + "\n" + ex.StackTrace;
                }
                fileStart.Stop();
                if (ok)
                {
                    succeeded++;
                    if (verbose)
                    {
                        Console.WriteLine($"[ OK ] {task.FileName} -> {task.OutputDir} ({fileStart.Elapsed.TotalSeconds:F2}s)");
                    }
                }
                else
                {
                    failed++;
                    Console.Error.WriteLine($"[ FAIL ] {task.FileName}: {error}");
                }
            }
            sw.Stop();

            Console.WriteLine();
            Console.WriteLine($"[ YSMParser ] Total: {tasks.Count}, Success: {succeeded}, Failed: {failed}, Threads: {workerCount}, Duration: {sw.Elapsed.TotalSeconds:F2}s");
            return failed == 0 ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ YSMParser ] Critical Error: {ex.Message}");
            return 1;
        }
    }

    private static void PrintPeekResult(YsmPeekResult result)
    {
        if (result.HeaderName != null)
            Console.WriteLine($"  Name:     {result.HeaderName}");
        if (result.HeaderAuthors != null)
            Console.WriteLine($"  Authors:  {result.HeaderAuthors}");
        if (result.HeaderFormat.HasValue)
            Console.WriteLine($"  Format:   {result.HeaderFormat}");
        if (result.HeaderLicense != null)
            Console.WriteLine($"  License:  {result.HeaderLicense}");
        if (result.HeaderIsFree.HasValue)
            Console.WriteLine($"  Free:     {result.HeaderIsFree}");

        if (result.ResourceNames is { Count: > 0 })
        {
            Console.WriteLine($"  Resources: ({result.ResourceNames.Count} files)");
            for (int i = 0; i < result.ResourceNames.Count; i++)
                Console.WriteLine($"    [{i + 1}] {result.ResourceNames[i]}");
        }

        if (result.InfoJson is { Length: > 0 })
        {
            Console.WriteLine("  info.json:");
            PrintJson(result.InfoJson);
        }

        if (result.YsmJson is { Length: > 0 })
        {
            Console.WriteLine("  ysm.json:");
            PrintJson(result.YsmJson);
        }
    }

    private static void PrintJson(byte[] raw)
    {
        try
        {
            var node = JsonNode.Parse(raw);
            if (node != null)
            {
                var opts = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                };
                Console.WriteLine(node.ToJsonString(opts));
                return;
            }
        }
        catch { }
        Console.WriteLine(Encoding.UTF8.GetString(raw));
    }

    private static List<FileTask> CollectTasks(string inputPath, string outputDir, bool readOnly)
    {
        if (File.Exists(inputPath))
        {
            string fileName = Path.GetFileName(inputPath);
            string name = Path.GetFileNameWithoutExtension(inputPath);
            string outputSubdir = readOnly ? string.Empty : Path.Combine(outputDir, name);
            return [new FileTask(inputPath, fileName, outputSubdir, fileName)];
        }

        var tasks = new List<FileTask>();
        foreach (var path in Directory.EnumerateFiles(inputPath, "*.ysm", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(inputPath, path);
            string outputSubdir = readOnly ? string.Empty : Path.Combine(outputDir, Path.GetFileNameWithoutExtension(path));
            tasks.Add(new FileTask(path, Path.GetFileName(path), outputSubdir, relative));
        }
        tasks.Sort((a, b) => string.Compare(a.InputPath, b.InputPath, StringComparison.Ordinal));
        return tasks;
    }

    private static string? GetOption(string[] args, string shortName, string longName)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == shortName || args[i] == longName)
                return args[i + 1];
        }
        return null;
    }

    private static bool HasFlag(string[] args, string shortName, string longName)
    {
        foreach (var a in args)
            if (a == shortName || a == longName) return true;
        return false;
    }

    private static bool IsFlag(string[] args, string name)
    {
        foreach (var a in args)
            if (a == name) return true;
        return false;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("YSMParser CLI - parses .ysm model files");
        Console.WriteLine();
        Console.WriteLine("Usage: YSMParser -i <input> -o <output> [options]");
        Console.WriteLine("       YSMParser -i <input> -n             (info only)");
        Console.WriteLine("       YSMParser -i <input> -p             (peek metadata)");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -i, --input <path>   Input file or directory (required).");
        Console.WriteLine("  -o, --output <dir>   Output directory.");
        Console.WriteLine("  -p, --peek           Print structured model metadata (ysm.json/info.json).");
        Console.WriteLine("  -n, --info           Print file header info without extracting.");
        Console.WriteLine("  -v, --verbose        Verbose logging.");
        Console.WriteLine("  -d, --debug          Export all binary products (V3 only).");
        Console.WriteLine("  -f, --format         Pretty-print JSON output.");
        Console.WriteLine("  -j, --threads <n>    Parallel worker count (default 1).");
        Console.WriteLine("  --version            Print version and exit.");
        Console.WriteLine("  -h, --help           Show this message.");
    }

    private readonly record struct FileTask(string InputPath, string FileName, string OutputDir, string Relative);
}

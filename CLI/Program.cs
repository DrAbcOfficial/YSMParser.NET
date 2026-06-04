using System.Diagnostics;
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

        string? inputDir = GetOption(args, "-i", "--input");
        string? outputDir = GetOption(args, "-o", "--output");
        bool verbose = HasFlag(args, "-v", "--verbose");
        bool debug = HasFlag(args, "-d", "--debug");
        bool formatJson = HasFlag(args, "-f", "--format");
        int threads = 1;
        string? threadsArg = GetOption(args, "-j", "--threads");
        if (threadsArg != null && int.TryParse(threadsArg, out var t) && t > 0)
        {
            threads = t;
        }

        if (string.IsNullOrEmpty(inputDir) || string.IsNullOrEmpty(outputDir))
        {
            Console.Error.WriteLine("[ YSMParser ] Both --input and --output are required.");
            PrintUsage();
            return 1;
        }

        try
        {
            if (!Directory.Exists(inputDir))
            {
                throw new DirectoryNotFoundException($"Input directory does not exist: {inputDir}");
            }
            if (!Directory.Exists(outputDir))
            {
                Directory.CreateDirectory(outputDir);
            }

            var tasks = CollectFileTasks(inputDir, outputDir);
            if (tasks.Count == 0)
            {
                Console.WriteLine($"[ YSMParser ] No .ysm files found in {inputDir}");
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
                    Directory.CreateDirectory(task.OutputDir);
                    var parser = YSMParserFactory.Create(task.InputPath);
                    parser.Verbose = verbose;
                    parser.Debug = debug;
                    parser.FormatJson = formatJson;
                    int version = parser.GetYSGPVersion();
                    if (verbose)
                    {
                        Console.WriteLine($"[ YSMParser ] Detected version: {version}");
                    }
                    parser.Parse();
                    if (verbose)
                    {
                        Console.WriteLine("[ YSMParser ] Exporting resources...");
                    }
                    parser.SaveToDirectory(task.OutputDir);
                    ok = true;
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

    private static List<FileTask> CollectFileTasks(string inputDir, string outputDir)
    {
        var tasks = new List<FileTask>();
        foreach (var path in Directory.EnumerateFiles(inputDir, "*.ysm", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(inputDir, path);
            string outputSubdir = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(path));
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
            {
                return args[i + 1];
            }
        }
        return null;
    }

    private static bool HasFlag(string[] args, string shortName, string longName)
    {
        foreach (var a in args)
        {
            if (a == shortName || a == longName) return true;
        }
        return false;
    }

    private static bool IsFlag(string[] args, string name)
    {
        foreach (var a in args)
        {
            if (a == name) return true;
        }
        return false;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("YSMParser CLI - parses .ysm model files");
        Console.WriteLine();
        Console.WriteLine("Usage: YSMParser -i <input> -o <output> [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -i, --input <dir>     Input directory (required).");
        Console.WriteLine("  -o, --output <dir>    Output directory (required).");
        Console.WriteLine("  -v, --verbose         Verbose logging.");
        Console.WriteLine("  -d, --debug           Export all binary products (V3 only).");
        Console.WriteLine("  -f, --format          Pretty-print JSON output.");
        Console.WriteLine("  -j, --threads <n>     Parallel worker count (default 1).");
        Console.WriteLine("  --version             Print version and exit.");
        Console.WriteLine("  -h, --help            Show this message.");
    }

    private readonly record struct FileTask(string InputPath, string FileName, string OutputDir, string Relative);
}

using System.ComponentModel;
using SentinelSecurity.Core;

namespace SentinelSecurity.Engine;

internal sealed class ExternalDetectors
{
    private readonly SemaphoreSlim clamSlot = new(1, 1);
    private readonly SemaphoreSlim yaraSlots = new(2, 2);
    private static readonly TimeSpan ClamTimeout = TimeSpan.FromSeconds(90);
    private static readonly TimeSpan YaraTimeout = TimeSpan.FromSeconds(15);

    public async Task<IReadOnlyList<EngineStatus>> GetStatusAsync(EngineConfiguration config, CancellationToken ct) =>
        await Task.WhenAll(GetClamStatusAsync(config, ct), GetYaraStatusAsync(config, ct));

    public async Task<(List<Detection> Detections, List<string> Errors)> ScanAsync(string path, EngineConfiguration config, CancellationToken ct)
    {
        var detections = new List<Detection>();
        var errors = new List<string>();
        if (!string.IsNullOrWhiteSpace(config.ClamScan))
            await CaptureAsync("ClamAV", () => ScanClamAsync(path, config, ct), detections, errors);
        if (!string.IsNullOrWhiteSpace(config.Yara))
            await CaptureAsync("YARA", () => ScanYaraAsync(path, config, ct), detections, errors);
        return (detections, errors);
    }

    public async Task<EngineStatus> GetClamStatusAsync(EngineConfiguration config, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.ClamScan))
            return new EngineStatus("ClamAV", false, "Seleccione clamscan.exe en Configuración.");

        var temp = Path.Combine(Path.GetTempPath(), $"sentinel-clam-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(temp, "Comprobación de disponibilidad de Sentinel Security", ct);
            await clamSlot.WaitAsync(ct);
            try
            {
                var result = await RunClamAsync(config.ClamScan, config.ClamDatabase, temp, ct);
                if (!ClamInspectedProbe(result))
                    throw new IOException(result.FirstError("No se pudo validar la base de ClamAV."));
                var version = await ToolProcess.RunAsync(config.ClamScan,
                    AddDatabase(config.ClamDatabase, ["--version"]), TimeSpan.FromSeconds(10), ct);
                return new EngineStatus("ClamAV", true, version.ExitCode == 0 && !string.IsNullOrWhiteSpace(version.StandardOutput)
                    ? version.StandardOutput.Trim().Split('\n')[0] : "Motor y base validados con un archivo benigno.");
            }
            finally
            {
                clamSlot.Release();
            }
        }
        catch (Exception error) when (IsToolFailure(error))
        {
            return new EngineStatus("ClamAV", false, error.Message);
        }
        finally
        {
            DeleteTemporaryFile(temp);
        }
    }

    public async Task<EngineStatus> GetYaraStatusAsync(EngineConfiguration config, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.Yara) || string.IsNullOrWhiteSpace(config.YaraRules))
            return new EngineStatus("YARA", false, "Seleccione yara.exe y configure reglas de una fuente verificada.");

        var temp = Path.Combine(Path.GetTempPath(), $"sentinel-yara-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(temp, "Comprobación de disponibilidad de Sentinel Security", ct);
            await ScanYaraAsync(temp, config, ct);
            return new EngineStatus("YARA", true, "Motor y reglas fuente validados.");
        }
        catch (Exception error) when (IsToolFailure(error))
        {
            return new EngineStatus("YARA", false, error.Message);
        }
        finally
        {
            DeleteTemporaryFile(temp);
        }
    }

    private async Task<IReadOnlyList<Detection>> ScanClamAsync(string path, EngineConfiguration config, CancellationToken ct)
    {
        await clamSlot.WaitAsync(ct);
        try
        {
            if (new FileInfo(path).Length > 128L * 1024 * 1024)
                throw new IOException("El archivo supera el límite de exploración de ClamAV de 128 MiB.");
            var result = await RunClamAsync(config.ClamScan!, config.ClamDatabase, path, ct);
            if (result.ExitCode == 0) return [];
            if (result.ExitCode != 1) throw new IOException(result.FirstError("ClamAV no pudo completar el análisis."));

            var matches = new List<Detection>();
            var prefix = path + ": ";
            foreach (var line in result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                const string suffix = " FOUND";
                if (!line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !line.EndsWith(suffix, StringComparison.Ordinal)) continue;
                var name = line[prefix.Length..^suffix.Length];
                if (name.Length is 0 or > 512) continue;
                var isAdvisory = name.StartsWith("Heuristics.", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("PUA.", StringComparison.OrdinalIgnoreCase);
                matches.Add(new Detection("ClamAV", name, isAdvisory ? Verdict.Suspicious : Verdict.Malware));
            }
            if (matches.Count == 0) throw new IOException("ClamAV informó una detección sin un resultado interpretable.");
            return matches;
        }
        finally
        {
            clamSlot.Release();
        }
    }

    internal static Task<ToolResult> RunClamAsync(string executable, string? database, string path, CancellationToken ct) =>
        ToolProcess.RunAsync(executable, AddDatabase(database,
            ["--stdout", "--no-summary", "--official-db-only=yes", "--follow-dir-symlinks=0", "--follow-file-symlinks=0",
                "--max-filesize=128M", "--max-scansize=160M", "--max-files=1000", "--max-recursion=12",
                "--max-scantime=30000", "--alert-exceeds-max=yes", "--alert-encrypted=yes", "--", path]), ClamTimeout, ct);

    internal static bool ClamInspectedProbe(ToolResult result) => result.ExitCode == 0 &&
        result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(line => line.EndsWith(".txt: OK", StringComparison.Ordinal));

    private static IEnumerable<string> AddDatabase(string? database, string[] arguments)
    {
        if (string.IsNullOrWhiteSpace(database)) return arguments;
        var normalized = ScanPath.Normalize(database);
        ScanPath.CheckRegularPath(normalized);
        return ["--database=" + normalized, .. arguments];
    }

    private async Task<IReadOnlyList<Detection>> ScanYaraAsync(string path, EngineConfiguration config, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.YaraRules)) throw new IOException("No hay reglas locales configuradas.");
        await yaraSlots.WaitAsync(ct);
        try
        {
            var result = await RunYaraAsync(config.Yara!, config.YaraRules, path, ct);
            if (result.ExitCode != 0) throw new IOException(result.FirstError("YARA no pudo completar el análisis."));
            var matches = new List<Detection>();
            var suffix = " " + path;
            foreach (var line in result.StandardOutput.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                if (!line.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) continue;
                var name = line[..^suffix.Length];
                if (name.Length is 0 or > 128 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')) continue;
                matches.Add(new Detection("YARA", name, Verdict.Suspicious));
            }
            if (matches.Count == 0 && !string.IsNullOrWhiteSpace(result.StandardOutput))
                throw new IOException("YARA devolvió un resultado inesperado.");
            return matches;
        }
        finally
        {
            yaraSlots.Release();
        }
    }

    internal static async Task<ToolResult> RunYaraAsync(string executable, string rules, string target, CancellationToken ct)
    {
        var source = ScanPath.Normalize(rules);
        ScanPath.CheckRegularPath(source);
        if (Path.GetExtension(source).ToLowerInvariant() is not (".yar" or ".yara"))
            throw new IOException("Seleccione reglas fuente con extensión .yar o .yara.");
        await using var stableRules = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        await EngineUpdates.ReadYaraSourceAsync(stableRules, ct);
        // YARA's argument parser has no end-of-options marker. Both input paths are absolute.
        return await ToolProcess.RunAsync(executable, ["-N", "-a", "10", "-l", "32", source, target], YaraTimeout, ct);
    }

    private static async Task CaptureAsync(string name, Func<Task<IReadOnlyList<Detection>>> action,
        List<Detection> detections, List<string> errors)
    {
        try { detections.AddRange(await action()); }
        catch (Exception error) when (IsToolFailure(error)) { errors.Add($"{name}: {error.Message}"); }
    }

    internal static void DeleteTemporaryFile(string path)
    {
        try { File.Delete(path); }
        catch (Exception error) when (ScanPath.Expected(error)) { }
    }

    private static bool IsToolFailure(Exception error) => ScanPath.Expected(error) || error is Win32Exception or TimeoutException;
}

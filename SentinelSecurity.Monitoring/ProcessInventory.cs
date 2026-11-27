using System.Diagnostics;
using System.Security.Cryptography;
using SentinelSecurity.Engine;

namespace SentinelSecurity.Monitoring;

public sealed record ProcessItem(string Name, int Id, string? Path, string Publisher, string Signature,
    double? CpuPercent, double? MemoryMegabytes, string? Sha256 = null, string Result = "Sin analizar");

public static class ProcessInventory
{
    public static async Task<IReadOnlyList<ProcessItem>> LoadAsync(CancellationToken ct)
    {
        var first = CaptureCpu(ct);
        var start = Stopwatch.GetTimestamp();
        await Task.Delay(400, ct);
        var processes = Process.GetProcesses();
        var elapsed = Stopwatch.GetElapsedTime(start);
        var rows = new List<ProcessItem>(processes.Length);
        var files = new Dictionary<string, (string Publisher, string Trust, string? Sha256)>(StringComparer.OrdinalIgnoreCase);
        var hashBudget = 128 * 1024 * 1024L;
        try
        {
            foreach (var process in processes)
            {
                ct.ThrowIfCancellationRequested();
                var name = Safe(() => process.ProcessName, "Proceso sin nombre");
                var path = Safe(() => process.MainModule?.FileName, null);
                var memory = Safe<double?>(() => Math.Round(process.WorkingSet64 / 1048576d, 1), null);
                var cpu = double.NaN;
                if (first.TryGetValue(process.Id, out var initial) &&
                    Safe(() => process.StartTime, DateTime.MinValue) == initial.Start)
                {
                    var after = Safe(() => process.TotalProcessorTime, TimeSpan.MinValue);
                    if (after >= initial.Cpu)
                        cpu = 100 * (after - initial.Cpu).TotalMilliseconds /
                            (elapsed.TotalMilliseconds * Environment.ProcessorCount);
                }

                var metadata = (Publisher: "No disponible", Trust: "No disponible", Sha256: (string?)null);
                if (path is not null && PathSafety.IsLocalWithoutLinks(path, directory: false) &&
                    !files.TryGetValue(path, out metadata))
                {
                    var publisher = Safe(() => FileVersionInfo.GetVersionInfo(path).CompanyName, null);
                    string? sha256 = null;
                    if (hashBudget > 0)
                    {
                        try
                        {
                            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                                65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
                            var length = stream.Length;
                            if (length <= Math.Min(8 * 1024 * 1024L, hashBudget))
                            {
                                hashBudget -= length;
                                sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
                            }
                        }
                        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
                    }
                    metadata = (publisher ?? "No declarado", TrustLabel(ExecutableTrust.Inspect(path)), sha256);
                    files.Add(path, metadata);
                }
                rows.Add(new ProcessItem(name, process.Id, path, metadata.Publisher, metadata.Trust,
                    double.IsNaN(cpu) ? null : Math.Round(Math.Clamp(cpu, 0, 100), 1), memory, metadata.Sha256));
            }
        }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }

        return rows.OrderBy(row => row.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(row => row.Id).ToArray();
    }

    private static Dictionary<int, (DateTime Start, TimeSpan Cpu)> CaptureCpu(CancellationToken ct)
    {
        var processes = Process.GetProcesses();
        var readings = new Dictionary<int, (DateTime, TimeSpan)>();
        try
        {
            foreach (var process in processes)
            {
                ct.ThrowIfCancellationRequested();
                var reading = Safe<(DateTime, TimeSpan)?>(() => (process.StartTime, process.TotalProcessorTime), null);
                if (reading is { } value)
                    readings[process.Id] = value;
            }
        }
        finally
        {
            foreach (var process in processes)
                process.Dispose();
        }
        return readings;
    }

    private static T Safe<T>(Func<T> query, T fallback)
    {
        try { return query(); }
        catch (Exception error) when (error is System.ComponentModel.Win32Exception or InvalidOperationException
            or NotSupportedException or UnauthorizedAccessException or IOException)
        {
            return fallback;
        }
    }

    private static string TrustLabel(TrustResult trust) => trust switch
    {
        TrustResult.Trusted => "Firma validada",
        TrustResult.NoEmbeddedSignature => "Firma no encontrada",
        TrustResult.Unverified => "Firma sin validar",
        _ => "No disponible"
    };
}

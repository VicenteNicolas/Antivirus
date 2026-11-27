using System.ComponentModel;
using System.Diagnostics;
using System.Text;

namespace SentinelSecurity.Engine;

internal static class ToolProcess
{
    public static string ValidateExecutable(string configuredPath)
    {
        var fullPath = ScanPath.Normalize(configuredPath);
        if (!Path.IsPathFullyQualified(configuredPath) ||
            (OperatingSystem.IsWindows() && !Path.GetExtension(fullPath).Equals(".exe", StringComparison.OrdinalIgnoreCase)) ||
            (ScanPath.CheckRegularPath(fullPath) & FileAttributes.Directory) != 0)
            throw new IOException("Seleccione la ruta absoluta al ejecutable instalado.");
        return fullPath;
    }

    public static async Task<ToolResult> RunAsync(string executable, IEnumerable<string> arguments,
        TimeSpan timeout, CancellationToken ct)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo(ValidateExecutable(executable))
        {
            WorkingDirectory = Path.GetDirectoryName(executable)!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            process.StartInfo.ArgumentList.Add(argument);

        ct.ThrowIfCancellationRequested();
        if (!process.Start()) throw new IOException("No se pudo iniciar el motor externo.");

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutSource.CancelAfter(timeout);
        var token = timeoutSource.Token;
        var stdout = DrainAsync(process.StandardOutput, token);
        var stderr = DrainAsync(process.StandardError, token);
        try
        {
            await process.WaitForExitAsync(token);
            await Task.WhenAll(stdout, stderr).WaitAsync(token);
            return new ToolResult(process.ExitCode, await stdout, await stderr);
        }
        catch (OperationCanceledException)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException) { }
            catch (Win32Exception) { }
            ct.ThrowIfCancellationRequested();
            throw new TimeoutException("El motor externo alcanzó su límite de tiempo.");
        }
    }

    private static async Task<string> DrainAsync(StreamReader stream, CancellationToken ct)
    {
        const int maximum = 32 * 1024;
        var kept = new StringBuilder();
        var buffer = new char[2048];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (kept.Length < maximum)
                kept.Append(buffer, 0, Math.Min(read, maximum - kept.Length));
        }
        return kept.ToString();
    }
}

internal sealed record ToolResult(int ExitCode, string StandardOutput, string StandardError)
{
    public string FirstError(string fallback)
    {
        var text = string.IsNullOrWhiteSpace(StandardError) ? StandardOutput : StandardError;
        var first = text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return first is null ? fallback : first[..Math.Min(first.Length, 300)];
    }
}

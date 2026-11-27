using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SentinelSecurity.Engine;

public sealed record EngineUpdateResult(string Path, string Version, DateTimeOffset Updated);

public static partial class EngineUpdates
{
    private const int MaxYaraSourceBytes = 2 * 1024 * 1024;
    private static readonly SemaphoreSlim UpdateSlot = new(1, 1);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<EngineUpdateResult> UpdateClamAsync(string freshClam, string clamScan, string databaseRoot,
        CancellationToken ct)
    {
        await UpdateSlot.WaitAsync(ct);
        string? staging = null;
        try
        {
            ToolProcess.ValidateExecutable(freshClam);
            ToolProcess.ValidateExecutable(clamScan);
            var root = PrepareRoot(databaseRoot);
            var suffix = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
            staging = Path.Combine(root, $"staging-{suffix}");
            var destination = Path.Combine(root, $"db-{suffix}");
            Directory.CreateDirectory(staging);
            var configuration = Path.Combine(staging, "freshclam.conf");
            const string settings = "DatabaseMirror database.clamav.net\nScriptedUpdates no\nTestDatabases yes\nConnectTimeout 20\nReceiveTimeout 90\nMaxAttempts 2\n";
            await File.WriteAllTextAsync(configuration, settings, ct);

            var update = await ToolProcess.RunAsync(freshClam, [$"--config-file={configuration}", $"--datadir={staging}"],
                TimeSpan.FromMinutes(8), ct);
            if (update.ExitCode != 0)
                throw new IOException(update.FirstError("FreshClam no pudo actualizar las bases oficiales."));

            var daily = await ReadClamVersionAsync(Path.Combine(staging, "daily.cvd"), ct);
            var main = await ReadClamVersionAsync(Path.Combine(staging, "main.cvd"), ct);
            var bytecode = await ReadClamVersionAsync(Path.Combine(staging, "bytecode.cvd"), ct);
            var probe = Path.Combine(staging, "sentinel-probe.txt");
            await File.WriteAllTextAsync(probe, "Muestra benigna de validación de Sentinel Security", ct);
            var validation = await ExternalDetectors.RunClamAsync(clamScan, staging, probe, ct);
            if (validation.ExitCode != 0)
                throw new IOException(validation.FirstError("ClamAV no pudo cargar la base descargada."));
            File.Delete(configuration);
            File.Delete(probe);
            ct.ThrowIfCancellationRequested();
            Directory.Move(staging, destination);
            staging = null;
            return new EngineUpdateResult(destination, $"daily {daily}, main {main}, bytecode {bytecode}", DateTimeOffset.UtcNow);
        }
        finally
        {
            if (staging is not null)
            {
                try
                {
                    if (Directory.Exists(staging) && (File.GetAttributes(staging) & FileAttributes.ReparsePoint) == 0)
                        Directory.Delete(staging, recursive: true);
                }
                catch (Exception error) when (ScanPath.Expected(error)) { }
            }
            UpdateSlot.Release();
        }
    }

    public static async Task<EngineUpdateResult> ImportYaraAsync(string yara, string source, string expectedSha256, string rulesRoot,
        CancellationToken ct)
    {
        if (expectedSha256 is null || expectedSha256.Trim().Length != 64 || !expectedSha256.Trim().All(Uri.IsHexDigit))
            throw new ArgumentException("Introduzca el SHA-256 de la fuente verificada.", nameof(expectedSha256));
        var input = ScanPath.Normalize(source);
        ScanPath.CheckRegularPath(input);
        await using var stream = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var bytes = await ReadYaraSourceAsync(stream, ct);
        var sha256 = Convert.ToHexString(SHA256.HashData(bytes));
        if (!string.Equals(sha256, expectedSha256.Trim(), StringComparison.OrdinalIgnoreCase))
            throw new IOException("El SHA-256 de las reglas no coincide con el valor esperado.");

        var root = PrepareRoot(rulesRoot);
        var destination = Path.Combine(root, $"rules-{sha256}-{Guid.NewGuid():N}.yar");
        var staging = Path.Combine(root, $"staging-{Guid.NewGuid():N}.yar");
        var probe = Path.Combine(root, $"probe-{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllBytesAsync(staging, bytes, ct);
            await File.WriteAllTextAsync(probe, "Muestra benigna de validación de Sentinel Security", ct);
            var validation = await ExternalDetectors.RunYaraAsync(yara, staging, probe, ct);
            if (validation.ExitCode != 0)
                throw new IOException(validation.FirstError("YARA no pudo validar las reglas de origen."));
            ct.ThrowIfCancellationRequested();
            File.Move(staging, destination);
            return new EngineUpdateResult(destination, sha256, DateTimeOffset.UtcNow);
        }
        finally
        {
            ExternalDetectors.DeleteTemporaryFile(staging);
            ExternalDetectors.DeleteTemporaryFile(probe);
        }
    }

    internal static async Task<byte[]> ReadYaraSourceAsync(FileStream stream, CancellationToken ct)
    {
        if (stream.Length is <= 0 or > MaxYaraSourceBytes) throw new IOException("Las reglas fuente deben ocupar entre 1 byte y 2 MiB.");
        var bytes = new byte[checked((int)stream.Length)];
        await stream.ReadExactlyAsync(bytes, ct);
        string source;
        try { source = StrictUtf8.GetString(bytes); }
        catch (DecoderFallbackException error) { throw new IOException("Las reglas YARA deben estar en formato UTF-8.", error); }
        if (source.Any(character => char.IsControl(character) && character is not ('\r' or '\n' or '\t')) ||
            source.TrimStart('\uFEFF').StartsWith("YARA", StringComparison.Ordinal) || IncludeDirective().IsMatch(source))
            throw new IOException("Use reglas fuente YARA autocontenidas sin directivas include ni contenido compilado.");
        return bytes;
    }

    private static string PrepareRoot(string path)
    {
        var root = ScanPath.Normalize(path);
        var existing = root;
        while (!Directory.Exists(existing))
            existing = Path.GetDirectoryName(existing) ?? throw new IOException("La ubicación de actualizaciones no es válida.");
        ScanPath.CheckRegularPath(existing);
        Directory.CreateDirectory(root);
        ScanPath.CheckRegularPath(root);
        return root;
    }

    private static async Task<string> ReadClamVersionAsync(string path, CancellationToken ct)
    {
        ScanPath.CheckRegularPath(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
        var header = new byte[512];
        await stream.ReadExactlyAsync(header, ct);
        var fields = Encoding.ASCII.GetString(header).Split(':');
        if (fields.Length < 4 || fields[0] != "ClamAV-VDB" || !uint.TryParse(fields[2], out var version))
            throw new IOException("Formato no válido en la base oficial descargada.");
        return version.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    [GeneratedRegex("include[ \\t]+\"", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex IncludeDirective();
}

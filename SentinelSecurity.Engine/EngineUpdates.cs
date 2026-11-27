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
    private static readonly string[] ClamDatabaseFiles = ["daily.cvd", "main.cvd", "bytecode.cvd"];

    public static Task<EngineUpdateResult> UpdateClamAsync(string freshClam, string clamScan, string databaseRoot,
        CancellationToken ct) => UpdateClamAsync(freshClam, clamScan, databaseRoot, null, ct);

    public static async Task<EngineUpdateResult> UpdateClamAsync(string freshClam, string clamScan, string databaseRoot,
        string? activeDatabase, CancellationToken ct)
    {
        await UpdateSlot.WaitAsync(ct);
        string? staging = null;
        string? cooldown = null;
        try
        {
            ToolProcess.ValidateExecutable(freshClam);
            ToolProcess.ValidateExecutable(clamScan);
            var root = PrepareRoot(databaseRoot);
            cooldown = Path.Combine(root, "freshclam.dat");
            var previous = GetPreviousDatabase(root, activeDatabase);
            var suffix = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
            staging = Path.Combine(root, $"staging-{suffix}");
            var destination = Path.Combine(root, $"db-{suffix}");
            Directory.CreateDirectory(staging);
            if (previous is not null)
            {
                foreach (var name in ClamDatabaseFiles)
                    await CopyIfPresentAsync(Path.Combine(previous, name), Path.Combine(staging, name), ct);
                foreach (var name in ClamDetachedSignatures(previous))
                    await CopyIfPresentAsync(Path.Combine(previous, name), Path.Combine(staging, name), ct);
            }
            await CopyIfPresentAsync(cooldown, Path.Combine(staging, "freshclam.dat"), ct);
            var configuration = Path.Combine(staging, "freshclam.conf");
            const string settings = "DatabaseMirror database.clamav.net\nScriptedUpdates no\nTestDatabases yes\nConnectTimeout 20\nReceiveTimeout 90\nMaxAttempts 2\n";
            await File.WriteAllTextAsync(configuration, settings, ct);

            var update = await ToolProcess.RunAsync(freshClam, [$"--config-file={configuration}", $"--datadir={staging}"],
                TimeSpan.FromMinutes(8), ct);
            if (update.ExitCode != 0)
            {
                var output = update.StandardError + "\n" + update.StandardOutput;
                if (output.Contains("cool-down", StringComparison.OrdinalIgnoreCase) ||
                    output.Contains("429", StringComparison.Ordinal) || output.Contains("403", StringComparison.Ordinal))
                    throw new IOException("El servidor oficial limitó temporalmente las descargas de FreshClam. Espera al siguiente intento y conserva las firmas existentes.");
                throw new IOException($"FreshClam no pudo actualizar las bases oficiales ({update.ExitCode}). " +
                    update.FirstError("Verifica la conexión con database.clamav.net."));
            }

            var daily = await ReadClamVersionAsync(Path.Combine(staging, "daily.cvd"), ct);
            var main = await ReadClamVersionAsync(Path.Combine(staging, "main.cvd"), ct);
            var bytecode = await ReadClamVersionAsync(Path.Combine(staging, "bytecode.cvd"), ct);
            var probe = Path.Combine(staging, "sentinel-probe.txt");
            await File.WriteAllTextAsync(probe, "Muestra benigna de validación de Sentinel Security", ct);
            var validation = await ExternalDetectors.RunClamAsync(clamScan, staging, probe, ct);
            if (!ExternalDetectors.ClamInspectedProbe(validation))
                throw new IOException(validation.FirstError("ClamAV no pudo cargar la base descargada."));
            SaveFreshClamState(staging, cooldown);
            File.Delete(configuration);
            File.Delete(probe);
            ct.ThrowIfCancellationRequested();
            var version = $"daily {daily}, main {main}, bytecode {bytecode}";
            if (previous is not null && await HasSameDatabasesAsync(previous, staging, ct))
                return new EngineUpdateResult(previous, version, DateTimeOffset.UtcNow);
            Directory.Move(staging, destination);
            staging = null;
            return new EngineUpdateResult(destination, version, DateTimeOffset.UtcNow);
        }
        finally
        {
            if (staging is not null)
            {
                if (cooldown is not null)
                    SaveFreshClamState(staging, cooldown);
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

    private static string? GetPreviousDatabase(string root, string? configured)
    {
        if (string.IsNullOrWhiteSpace(configured)) return null;
        var full = ScanPath.Normalize(configured);
        if (!string.Equals(Path.GetDirectoryName(full), root, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(full).StartsWith("db-", StringComparison.Ordinal) || !Directory.Exists(full))
            return null;
        ScanPath.CheckRegularPath(full);
        return full;
    }

    private static async Task CopyIfPresentAsync(string source, string destination, CancellationToken ct)
    {
        if (!File.Exists(source)) return;
        ScanPath.CheckRegularPath(source);
        await using var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true);
        await using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true);
        await input.CopyToAsync(output, ct);
    }

    private static void SaveFreshClamState(string staging, string destination)
    {
        var source = Path.Combine(staging, "freshclam.dat");
        try
        {
            if (!File.Exists(source)) return;
            ScanPath.CheckRegularPath(source);
            File.Move(source, destination, overwrite: true);
        }
        catch (Exception error) when (ScanPath.Expected(error)) { }
    }

    private static async Task<bool> HasSameDatabasesAsync(string oldDirectory, string newDirectory, CancellationToken ct)
    {
        var files = ClamDatabaseFiles.Concat(ClamDetachedSignatures(oldDirectory))
            .Concat(ClamDetachedSignatures(newDirectory)).Distinct(StringComparer.OrdinalIgnoreCase);
        foreach (var name in files)
        {
            var oldFile = Path.Combine(oldDirectory, name);
            var newFile = Path.Combine(newDirectory, name);
            if (!File.Exists(oldFile) || !File.Exists(newFile)) return false;
            ScanPath.CheckRegularPath(oldFile);
            await using var oldStream = File.OpenRead(oldFile);
            await using var newStream = File.OpenRead(newFile);
            if (oldStream.Length != newStream.Length)
                return false;
            var oldHash = await SHA256.HashDataAsync(oldStream, ct);
            var newHash = await SHA256.HashDataAsync(newStream, ct);
            if (!oldHash.AsSpan().SequenceEqual(newHash))
                return false;
        }
        return true;
    }

    private static IEnumerable<string> ClamDetachedSignatures(string directory) =>
        Directory.EnumerateFiles(directory, "*.cvd.sign")
            .Select(path => Path.GetFileName(path))
            .Where(name => ClamSignatureName().IsMatch(name));

    [GeneratedRegex(@"^(daily|main|bytecode)-[0-9]+\.cvd\.sign$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)]
    private static partial Regex ClamSignatureName();

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

    internal static string PrepareRoot(string path)
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

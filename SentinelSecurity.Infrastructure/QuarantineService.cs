using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SentinelSecurity.Core;

namespace SentinelSecurity.Infrastructure;

public sealed class QuarantineService
{
    private readonly SqliteStore _store;
    private readonly string _dataDirectory;
    private readonly string _vault;

    public QuarantineService(SqliteStore store, string dataDirectory)
    {
        _store = store;
        _dataDirectory = Path.TrimEndingDirectorySeparator(Path.GetFullPath(dataDirectory));
        _vault = Path.Combine(_dataDirectory, "quarantine");
    }

    public async Task<QuarantineItem> IsolateAsync(FileResult result, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La cuarentena requiere Windows.");
        ArgumentNullException.ThrowIfNull(result);
        if (result.Verdict is not (Verdict.Malware or Verdict.Suspicious or Verdict.HighRisk) || !SqliteStore.IsSha256(result.Sha256))
            throw new ArgumentException("Selecciona un hallazgo con un hash SHA-256 válido.", nameof(result));
        if (result.Size is < 0 or > QuarantineEnvelope.MaximumBytes)
            throw new IOException("El tamaño del archivo supera el límite de cuarentena de 512 MiB.");

        var original = ValidateOriginal(result.Path);
        var reason = string.Join(" · ", result.Detections.Take(32).Select(d => $"{d.Engine}: {d.Name}"));
        if (string.IsNullOrWhiteSpace(reason)) reason = "Hallazgo seleccionado para revisión.";
        if (reason.Length > 4096) reason = reason[..4096];
        var item = new QuarantineItem(Guid.NewGuid(), original, result.Sha256!.ToUpperInvariant(), reason, DateTimeOffset.UtcNow);
        var destination = VaultPath(item.Id);
        var staging = destination + ".part";
        var staged = false;
        var published = false;
        var recorded = false;
        var removeRequested = false;
        using var safeOriginal = new QuarantinePaths(Path.GetDirectoryName(original)!);
        using var safeVault = OpenVault();
        try
        {
            using (var source = QuarantinePaths.OpenRead(original, allowDelete: true))
            {
                if (source.Length != result.Size) throw new InvalidDataException("El tamaño del archivo cambió después del análisis.");
                QuarantinePaths.RejectOtherStreams(source);
                await using (var output = CreateStaging(staging))
                {
                    staged = true;
                    await QuarantineEnvelope.EncryptAsync(source, output, item, result.Size, ct).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                ct.ThrowIfCancellationRequested();
                File.Move(staging, destination, overwrite: false);
                staged = false;
                published = true;
                await using var verification = QuarantinePaths.OpenRead(destination, allowDelete: false);
                await QuarantineEnvelope.DecryptAsync(verification, Stream.Null, item, ct).ConfigureAwait(false);
                await _store.RememberQuarantineAsync(item, ct).ConfigureAwait(false);
                recorded = true;

                ct.ThrowIfCancellationRequested();
                QuarantinePaths.RemoveOnClose(source);
                removeRequested = true;
            }

            await _store.ConfirmQuarantineAsync(item.Id, CancellationToken.None).ConfigureAwait(false);
            return item;
        }
        catch
        {
            if (!removeRequested && published)
                await UndoPublicationAsync(item.Id, destination, recorded).ConfigureAwait(false);
            throw;
        }
        finally { if (staged) TryDelete(staging); }
    }

    public async Task<bool> VerifyAsync(Guid id, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La cuarentena requiere Windows.");
        var item = await _store.FindQuarantineAsync(id, ct).ConfigureAwait(false);
        if (item is null || item.Id != id || !SqliteStore.IsSha256(item.Sha256)) return false;
        using var safeVault = OpenVault();
        try
        {
            await using var source = QuarantinePaths.OpenRead(VaultPath(id), allowDelete: false);
            await QuarantineEnvelope.DecryptAsync(source, Stream.Null, item, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception e) when (e is InvalidDataException or CryptographicException or FileNotFoundException or EndOfStreamException)
        {
            return false;
        }
    }

    public async Task RestoreAsync(Guid id, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La cuarentena requiere Windows.");
        var item = await RequireItemAsync(id, ct).ConfigureAwait(false);
        var destination = ValidateOriginal(item.OriginalPath);
        var directory = Path.GetDirectoryName(destination)!;
        using var safeOriginal = new QuarantinePaths(directory);
        using var safeVault = OpenVault();
        var staging = Path.Combine(directory, $".sentinel-restore-{Guid.NewGuid():N}.part");
        var staged = false;
        try
        {
            using (var source = QuarantinePaths.OpenRead(VaultPath(id), allowDelete: true))
            {
                if (File.Exists(destination) || Directory.Exists(destination))
                    throw new IOException("La ruta original está ocupada. Libérala antes de restaurar.");
                await using (var output = CreateStaging(staging))
                {
                    staged = true;
                    await QuarantineEnvelope.DecryptAsync(source, output, item, ct).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }

                await File.WriteAllTextAsync(staging + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n", ct).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
                File.Move(staging, destination, overwrite: false);
                staged = false;
                QuarantinePaths.RemoveOnClose(source);
            }
            await _store.ForgetQuarantineAsync(id, CancellationToken.None).ConfigureAwait(false);
        }
        finally { if (staged) TryDelete(staging); }
    }

    public async Task DeleteAsync(Guid id, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La cuarentena requiere Windows.");
        await RequireItemAsync(id, ct).ConfigureAwait(false);
        using var safeVault = OpenVault();
        try
        {
            using var source = QuarantinePaths.OpenRead(VaultPath(id), allowDelete: true);
            ct.ThrowIfCancellationRequested();
            QuarantinePaths.RemoveOnClose(source);
        }
        catch (FileNotFoundException)
        {
            // An interrupted operation may already have removed the ciphertext.
        }
        await _store.ForgetQuarantineAsync(id, CancellationToken.None).ConfigureAwait(false);
    }

    private string ValidateOriginal(string path)
    {
        var fullPath = QuarantinePaths.NormalizeFile(path);
        if (fullPath.StartsWith(_dataDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || string.Equals(fullPath, _dataDirectory, StringComparison.OrdinalIgnoreCase))
            throw new IOException("La cuarentena no modifica sus propios archivos de datos.");
        return fullPath;
    }

    private QuarantinePaths OpenVault()
    {
        Directory.CreateDirectory(_vault);
        return new QuarantinePaths(_vault);
    }

    private async Task<QuarantineItem> RequireItemAsync(Guid id, CancellationToken ct)
    {
        var item = await _store.FindQuarantineAsync(id, ct).ConfigureAwait(false);
        if (item is null) throw new KeyNotFoundException("El elemento ya no está en cuarentena.");
        if (item.Id != id || !SqliteStore.IsSha256(item.Sha256)) throw new InvalidDataException("Metadatos de cuarentena no válidos.");
        return item;
    }

    private async Task UndoPublicationAsync(Guid id, string path, bool recorded)
    {
        if (recorded)
        {
            try { await _store.ForgetQuarantineAsync(id, CancellationToken.None).ConfigureAwait(false); }
            catch (SqliteException) { return; } // Preserve the referenced copy if the metadata cannot be removed.
        }
        TryDelete(path);
    }

    private string VaultPath(Guid id) => Path.Combine(_vault, $"{id:N}.sealed");

    private static FileStream CreateStaging(string path) =>
        new(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous);

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}

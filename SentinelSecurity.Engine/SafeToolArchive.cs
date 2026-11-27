using System.IO.Compression;

namespace SentinelSecurity.Engine;

internal static class SafeToolArchive
{
    private const int MaximumEntries = 4096;
    private const int UnixLink = 0xA000;
    private const int UnixFileTypeMask = 0xF000;
    private static readonly char[] InvalidNameCharacters = ['<', '>', ':', '"', '|', '?', '*'];

    public static async Task ExtractAsync(string archive, string directory, long maxExpandedBytes, CancellationToken ct)
    {
        using var zip = ZipFile.OpenRead(archive);
        if (zip.Entries.Count is <= 0 or > MaximumEntries)
            throw new IOException("El ZIP oficial tiene un número de entradas inválido.");

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new byte[131072];
        long expandedBytes = 0;
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var normalized = entry.FullName.Replace('\\', '/');
            if (((entry.ExternalAttributes >> 16) & UnixFileTypeMask) == UnixLink ||
                (entry.ExternalAttributes & (int)FileAttributes.ReparsePoint) != 0)
                throw new IOException("El ZIP oficial contiene un enlace no permitido.");
            var isDirectory = normalized.EndsWith('/');
            var parts = normalized.TrimEnd('/').Split('/');
            if (parts.Any(IsUnsafeName))
                throw new IOException("El ZIP oficial contiene una ruta no permitida.");

            var target = Path.GetFullPath(Path.Combine(directory, Path.Combine(parts)));
            if (!target.StartsWith(Path.TrimEndingDirectorySeparator(directory) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase) || !seen.Add(target))
                throw new IOException("El ZIP oficial contiene una ruta duplicada o fuera de la carpeta de motores.");
            if (isDirectory)
            {
                Directory.CreateDirectory(target);
                continue;
            }
            if (entry.Length > maxExpandedBytes - expandedBytes)
                throw new IOException("El ZIP oficial excede el tamaño permitido una vez extraído.");

            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            await using var input = entry.Open();
            await using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
            long entryBytes = 0;
            int read;
            while ((read = await input.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                entryBytes += read;
                if (entryBytes > entry.Length)
                    throw new IOException("Una entrada del ZIP excede su tamaño declarado.");
                await output.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            }
            if (entryBytes != entry.Length)
                throw new IOException("Una entrada del ZIP está incompleta.");
            expandedBytes += entryBytes;
        }
    }

    private static bool IsUnsafeName(string name)
    {
        if (name.Length == 0 || name[^1] is ' ' or '.' || name.IndexOfAny(InvalidNameCharacters) >= 0 ||
            name.Any(char.IsControl))
            return true;
        var deviceName = name.Split('.', 2)[0].TrimEnd(' ').ToUpperInvariant();
        return deviceName is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
            (deviceName.Length == 4 && (deviceName.StartsWith("COM", StringComparison.Ordinal) ||
                deviceName.StartsWith("LPT", StringComparison.Ordinal)) && "123456789¹²³".Contains(deviceName[3]));
    }
}

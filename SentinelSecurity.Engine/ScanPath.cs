namespace SentinelSecurity.Engine;

internal static class ScanPath
{
    private static readonly StringComparison PathComparison = OperatingSystem.IsWindows()
        ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
    public static StringComparer Comparer { get; } = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    public static string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("La ruta está vacía.", nameof(path));

        var fullPath = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows())
        {
            if (fullPath.StartsWith("\\\\", StringComparison.Ordinal) || fullPath.IndexOf(':', 2) >= 0)
                throw new ArgumentException("Solo se admiten rutas locales y flujos de archivo principales.", nameof(path));
        }
        return fullPath;
    }

    public static FileAttributes CheckRegularPath(string path)
    {
        var attrs = File.GetAttributes(path);
        CheckAttributes(attrs);
        for (var directory = Path.GetDirectoryName(path); directory is not null; directory = Path.GetDirectoryName(directory))
            CheckAttributes(File.GetAttributes(directory));
        return attrs;
    }

    public static void CheckAttributes(FileAttributes attrs)
    {
        if ((attrs & (FileAttributes.ReparsePoint | FileAttributes.Offline | FileAttributes.Device)) != 0)
            throw new IOException("Se omitió un enlace, punto de montaje, dispositivo o archivo sin conexión.");
    }

    public static string[] GetExclusions(IReadOnlyList<string>? paths) => paths is null
        ? [] : paths.Select(Normalize).Select(Path.TrimEndingDirectorySeparator).Distinct(Comparer).ToArray();

    public static bool IsExcluded(string path, string[] exclusions)
    {
        foreach (var exclusion in exclusions)
        {
            if (path.Equals(exclusion, PathComparison))
                return true;
            if (path.StartsWith(exclusion, PathComparison) && path.Length > exclusion.Length &&
                (Path.EndsInDirectorySeparator(exclusion) || path[exclusion.Length] == Path.DirectorySeparatorChar ||
                path[exclusion.Length] == Path.AltDirectorySeparatorChar))
                return true;
        }
        return false;
    }

    public static bool Expected(Exception error) => error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException;
}

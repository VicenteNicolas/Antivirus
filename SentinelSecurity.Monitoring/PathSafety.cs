namespace SentinelSecurity.Monitoring;

public static class PathSafety
{
    public static bool IsLocalWithoutLinks(string path, bool directory)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
                return false;

            var fullPath = Path.GetFullPath(path);
            var root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrEmpty(root) || fullPath.AsSpan(root.Length).Contains(':'))
                return false;
            if (new DriveInfo(root).DriveType is DriveType.Network or DriveType.Unknown)
                return false;
            var attributes = File.GetAttributes(fullPath);
            if (attributes.HasFlag(FileAttributes.ReparsePoint) ||
                attributes.HasFlag(FileAttributes.Directory) != directory)
                return false;

            for (var parent = Path.GetDirectoryName(fullPath); parent is not null; parent = Path.GetDirectoryName(parent))
                if (File.GetAttributes(parent).HasFlag(FileAttributes.ReparsePoint))
                    return false;

            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or ArgumentException
            or NotSupportedException)
        {
            return false;
        }
    }

    public static bool IsWithin(string path, string root)
    {
        var relative = Path.GetRelativePath(root, path);
        return !Path.IsPathRooted(relative) && relative is not ".." &&
            !relative.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }
}

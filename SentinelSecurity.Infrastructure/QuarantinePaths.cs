using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SentinelSecurity.Infrastructure;

internal sealed class QuarantinePaths : IDisposable
{
    private const uint GenericRead = 0x80000000;
    private const uint DeleteAccess = 0x00010000;
    private const uint ReadAttributes = 0x80;
    private const uint OpenExisting = 3;
    private const uint Overlapped = 0x40000000;
    private const uint SequentialScan = 0x08000000;
    private const uint BackupSemantics = 0x02000000;
    private const uint OpenReparsePoint = 0x00200000;
    private const int FileDispositionInfo = 4;
    private const int FileStreamInfo = 7;
    private readonly List<SafeFileHandle> _directories = [];

    internal QuarantinePaths(string directory)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La cuarentena requiere Windows.");
        var paths = new Stack<string>();
        for (var current = directory; current is not null; current = Path.GetDirectoryName(current)) paths.Push(current);
        try
        {
            foreach (var current in paths)
            {
                var handle = Open(current, ReadAttributes, FileShare.ReadWrite, BackupSemantics | OpenReparsePoint);
                _directories.Add(handle);
                var info = RequireCanonical(handle, current);
                if ((info.Attributes & FileAttributes.Directory) == 0)
                    throw new IOException("Un componente de la ruta no es una carpeta.");
            }
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal static string NormalizeFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Path.IsPathFullyQualified(path))
            throw new IOException("La cuarentena necesita una ruta de archivo local absoluta.");
        var fullPath = Path.GetFullPath(path);
        if (fullPath.Length < 4 || !char.IsAsciiLetter(fullPath[0]) || fullPath[1] != ':' || fullPath[2] != '\\'
            || fullPath.AsSpan(3).Contains(':'))
            throw new IOException("La cuarentena admite archivos locales con una ruta ordinaria de unidad.");

        foreach (var component in fullPath[3..].Split('\\'))
        {
            if (component.Length == 0 || component.EndsWith(' ') || component.EndsWith('.') || Path.GetInvalidFileNameChars().Any(component.Contains))
                throw new IOException("La ruta contiene un nombre de archivo no válido.");
        }
        return fullPath;
    }

    internal static FileStream OpenRead(string path, bool allowDelete)
    {
        var access = GenericRead | (allowDelete ? DeleteAccess : 0);
        var handle = Open(path, access, FileShare.None, Overlapped | SequentialScan | OpenReparsePoint);
        try
        {
            var info = RequireCanonical(handle, path);
            if ((info.Attributes & FileAttributes.Directory) != 0 || info.LinkCount != 1)
                throw new IOException("La cuarentena necesita un archivo regular sin enlaces físicos adicionales.");
            return new FileStream(handle, FileAccess.Read, 64 * 1024, isAsync: true);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal static void RemoveOnClose(FileStream stream)
    {
        if (!GetFileInformationByHandle(stream.SafeFileHandle, out var info)) throw Error("No se pudo comprobar el archivo");
        if (info.LinkCount != 1) throw new IOException("El archivo adquirió enlaces físicos mientras se preparaba el aislamiento.");

        byte remove = 1;
        if (!SetFileInformationByHandle(stream.SafeFileHandle, FileDispositionInfo, ref remove, 1))
            throw Error("Windows no permitió quitar el archivo original");
    }

    // Only the unnamed data stream is stored. The restore step applies a conservative Zone.Identifier.
    internal static void RejectOtherStreams(FileStream source)
    {
        const int bufferSize = 16384;
        const int nameOffset = 24;
        var buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            if (!GetFileInformationByHandleEx(source.SafeFileHandle, FileStreamInfo, buffer, bufferSize))
                throw Error("No se pudieron comprobar los flujos de datos adicionales");

            var offset = 0;
            while (true)
            {
                var nextOffset = Marshal.ReadInt32(buffer, offset);
                var length = Marshal.ReadInt32(buffer, offset + 4);
                if (length <= 0 || (length & 1) != 0 || length > bufferSize - offset - nameOffset)
                    throw new IOException("Windows devolvió un nombre de flujo de datos no válido.");
                var name = Marshal.PtrToStringUni(IntPtr.Add(buffer, offset + nameOffset), length / 2);
                if (name != "::$DATA" && !string.Equals(name, ":Zone.Identifier:$DATA", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("El archivo tiene flujos de datos adicionales que no se pueden preservar en la cuarentena.");
                if (nextOffset == 0) break;
                if (nextOffset < nameOffset + length || nextOffset > bufferSize - offset - nameOffset)
                    throw new IOException("Windows devolvió un descriptor de flujo de datos no válido.");
                offset += nextOffset;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static SafeFileHandle Open(string path, uint access, FileShare share, uint flags)
    {
        var handle = CreateFileW(@"\\?\" + path, access, share, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (!handle.IsInvalid) return handle;
        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        if (error is 2 or 3) throw new FileNotFoundException("No se encontró el archivo o la carpeta.", path);
        throw Error("Windows no permitió abrir la ruta de manera segura", error);
    }

    private static NativeFileInfo RequireCanonical(SafeFileHandle handle, string expected)
    {
        if (!GetFileInformationByHandle(handle, out var info)) throw Error("No se pudo comprobar la ruta");
        if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new IOException("No se admiten enlaces simbólicos, uniones ni otros puntos de reanálisis.");

        var buffer = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handle, buffer, buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity) throw Error("No se pudo comprobar la ruta real");
        if (!string.Equals(buffer.ToString().TrimEnd('\\'), (@"\\?\" + expected).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            throw new IOException("La ruta resolvió a una ubicación distinta del archivo solicitado.");
        return info;
    }

    private static IOException Error(string message, int? code = null) =>
        new(message, new Win32Exception(code ?? Marshal.GetLastWin32Error()));

    public void Dispose()
    {
        for (var i = _directories.Count - 1; i >= 0; i--) _directories[i].Dispose();
        _directories.Clear();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileInfo
    {
        public FileAttributes Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint LinkCount;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, FileShare share, IntPtr security,
        uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder name, int size, uint flags);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out NativeFileInfo info);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int infoClass, IntPtr info, uint size);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int infoClass, ref byte info, uint size);

}

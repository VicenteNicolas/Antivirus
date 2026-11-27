using System.Buffers;
using System.Buffers.Binary;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;

namespace SentinelSecurity.Engine;

public sealed record FileFeatures(
    string Type, double Entropy, long Bytes, int Sections, int ImportedLibraries,
    int WritableExecutableSections, int HasDoubleExtension, int ExecutableTypeMismatch,
    int SuspiciousScriptPatterns, TrustResult Trust);

internal sealed record FileInspection(string Sha256, FileFeatures Features, IReadOnlyList<string> Imports);

internal static class FileInspector
{
    private const int SampleLimit = 64 * 1024;
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx"
    };
    private static readonly HashSet<string> ActiveExtensions = new(ExecutableExtensions, StringComparer.OrdinalIgnoreCase)
    {
        ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".ps1", ".msi", ".lnk", ".hta"
    };
    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".txt", ".zip"
    };

    public static async Task<FileInspection> InspectAsync(FileStream stream, string path, long maximum, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(SampleLimit);
        try
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var sampleBytes = await stream.ReadAtLeastAsync(buffer.AsMemory(0, SampleLimit), SampleLimit, false, ct);
            var length = (long)sampleBytes;
            if (length > maximum)
                throw new IOException("El archivo excede el límite de tamaño configurado.");
            hash.AppendData(buffer, 0, sampleBytes);
            var type = Identify(buffer.AsSpan(0, sampleBytes));
            var entropy = Entropy(buffer.AsSpan(0, sampleBytes));
            var extension = Path.GetExtension(path);
            var previous = Path.GetExtension(Path.GetFileNameWithoutExtension(path));
            var scriptPatterns = ActiveExtensions.Contains(extension) && type is "Texto" or "Script" ? CountScriptPatterns(buffer.AsSpan(0, sampleBytes)) : 0;

            int bytesRead;
            while ((bytesRead = await stream.ReadAsync(buffer.AsMemory(0, SampleLimit), ct)) != 0)
            {
                length += bytesRead;
                if (length > maximum)
                    throw new IOException("El archivo excede el límite de tamaño configurado.");
                hash.AppendData(buffer, 0, bytesRead);
            }

            var (sections, executableWritable, imports) = type == "MZ" ? InspectPe(stream, ct) : (0, 0, Array.Empty<string>());
            if (sections > 0)
                type = "PE";
            var trust = type == "PE" ? ExecutableTrust.Inspect(path) : TrustResult.Unavailable;
            var mismatch = type == "PE" && DocumentExtensions.Contains(extension);
            var doubleExtension = ActiveExtensions.Contains(extension) && DocumentExtensions.Contains(previous);
            var features = new FileFeatures(type, entropy, length, sections, imports.Length, executableWritable,
                doubleExtension ? 1 : 0, mismatch ? 1 : 0, scriptPatterns, trust);
            return new FileInspection(Convert.ToHexString(hash.GetHashAndReset()), features, imports);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private static string Identify(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return "Vacío";
        if (bytes.StartsWith("MZ"u8)) return "MZ";
        if (bytes.StartsWith<byte>([0x50, 0x4B, 0x03, 0x04]) || bytes.StartsWith<byte>([0x50, 0x4B, 0x05, 0x06])) return "ZIP";
        if (bytes.StartsWith("%PDF-"u8)) return "PDF";
        if (bytes.StartsWith<byte>([0x1F, 0x8B])) return "GZIP";
        if (bytes.StartsWith<byte>([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])) return "7z";
        if (bytes.StartsWith("Rar!"u8)) return "RAR";
        if (bytes.StartsWith<byte>([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) return "PNG";
        if (bytes.StartsWith<byte>([0xFF, 0xD8, 0xFF])) return "JPEG";
        if (bytes.StartsWith("GIF87a"u8) || bytes.StartsWith("GIF89a"u8)) return "GIF";
        if (bytes.StartsWith<byte>([0x7F, 0x45, 0x4C, 0x46])) return "ELF";
        if (bytes.StartsWith<byte>([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])) return "OLE";
        if (bytes.StartsWith("#!"u8)) return "Script";
        if (bytes.StartsWith<byte>([0xFF, 0xFE]) || bytes.StartsWith<byte>([0xFE, 0xFF])) return "Texto";
        foreach (var b in bytes[..Math.Min(bytes.Length, 4096)])
        {
            if (b < 0x20 && b is not (0x09 or 0x0A or 0x0D)) return "Binario";
        }
        return "Texto";
    }

    private static double Entropy(ReadOnlySpan<byte> bytes)
    {
        Span<int> counts = stackalloc int[256];
        counts.Clear();
        foreach (var b in bytes)
            counts[b]++;

        var entropy = 0d;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var fraction = (double)count / bytes.Length;
            entropy -= fraction * Math.Log2(fraction);
        }
        return entropy;
    }

    private static int CountScriptPatterns(ReadOnlySpan<byte> bytes)
    {
        var encoding = bytes.StartsWith<byte>([0xFF, 0xFE]) ? Encoding.Unicode :
            bytes.StartsWith<byte>([0xFE, 0xFF]) ? Encoding.BigEndianUnicode : Encoding.UTF8;
        var text = encoding.GetString(bytes);
        var patterns = new[] { "-EncodedCommand", "Invoke-Expression", "FromBase64String" };
        return patterns.Count(pattern => text.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    private static (int Sections, int WritableExecutable, string[] Imports) InspectPe(FileStream stream, CancellationToken ct)
    {
        stream.Position = 0;
        try
        {
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
            var header = reader.PEHeaders.PEHeader;
            if (header is null || reader.PEHeaders.SectionHeaders.Length > 96)
                return (0, 0, []);

            var sections = reader.PEHeaders.SectionHeaders;
            const SectionCharacteristics flags = SectionCharacteristics.MemExecute | SectionCharacteristics.MemWrite;
            var executableWritable = sections.Count(section => (section.SectionCharacteristics & flags) == flags);
            return (sections.Length, executableWritable, ReadImports(stream, reader.PEHeaders, header.ImportTableDirectory, ct));
        }
        catch (BadImageFormatException)
        {
            return (0, 0, []);
        }
        catch (ArgumentOutOfRangeException)
        {
            return (0, 0, []);
        }
    }

    private static string[] ReadImports(FileStream stream, PEHeaders headers, DirectoryEntry table, CancellationToken ct)
    {
        if (table.RelativeVirtualAddress <= 0 || table.Size < 20)
            return [];

        const int entrySize = 20;
        if (!TryLocateRva(stream.Length, headers, table.RelativeVirtualAddress, out var offset, out var available))
            return [];
        var count = Math.Min(Math.Min(available, table.Size) / entrySize, 256);
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Span<byte> entry = stackalloc byte[entrySize];
        Span<byte> name = stackalloc byte[256];
        for (var index = 0; index < count; index++)
        {
            ct.ThrowIfCancellationRequested();
            stream.Position = offset + index * entrySize;
            stream.ReadExactly(entry);
            var nameRva = BinaryPrimitives.ReadInt32LittleEndian(entry[12..]);
            if (nameRva <= 0) break;
            if (!TryLocateRva(stream.Length, headers, nameRva, out var nameOffset, out var nameAvailable)) continue;
            stream.Position = nameOffset;
            var candidate = name[..Math.Min(nameAvailable, name.Length)];
            stream.ReadExactly(candidate);
            var end = candidate.IndexOf((byte)0);
            if (end > 0) names.Add(Encoding.ASCII.GetString(name[..end]));
        }
        return [.. names];
    }

    private static bool TryLocateRva(long length, PEHeaders headers, int address, out long offset, out int bytes)
    {
        foreach (var section in headers.SectionHeaders)
        {
            var relative = (long)address - section.VirtualAddress;
            if (relative < 0 || relative >= section.SizeOfRawData || section.PointerToRawData < 0) continue;
            offset = section.PointerToRawData + relative;
            if (offset >= length) break;
            bytes = (int)Math.Min(length - offset, section.SizeOfRawData - relative);
            return bytes > 0;
        }
        offset = 0;
        bytes = 0;
        return false;
    }
}

using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using SentinelSecurity.Core;

namespace SentinelSecurity.Engine;

public static class OfficialSha256Catalog
{
    private static readonly string[] Archives = ["main.cvd", "daily.cvd", "bytecode.cvd"];
    private const long MaxArchiveBytes = 512L * 1024 * 1024;
    private const long MaxExpandedBytes = 1024L * 1024 * 1024;
    private const int MaxRecords = 2_000_000;

    public static async Task<IReadOnlyList<SignatureEntry>> ReadAsync(string sigTool, string databaseDirectory, CancellationToken ct)
    {
        var verifier = ToolProcess.ValidateExecutable(sigTool);
        var directory = ScanPath.Normalize(databaseDirectory);
        if ((ScanPath.CheckRegularPath(directory) & FileAttributes.Directory) == 0)
            throw new IOException("Seleccione un directorio de bases oficiales de ClamAV.");

        var catalog = new Catalog();
        foreach (var name in Archives)
        {
            var path = Path.Combine(directory, name);
            ScanPath.CheckRegularPath(path);
            await using var archive = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, useAsync: true);
            if (archive.Length is <= 512 or > MaxArchiveBytes)
                throw new IOException($"La base {name} excede los límites de importación de Sentinel.");

            var arguments = new List<string> { $"--info={path}" };
            var certificates = Path.Combine(Path.GetDirectoryName(verifier)!, "certs");
            if (Directory.Exists(certificates))
            {
                ScanPath.CheckRegularPath(certificates);
                arguments.Add($"--cvdcertsdir={certificates}");
            }
            var result = await ToolProcess.RunAsync(verifier, arguments, TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
            if (result.ExitCode != 0 || !result.StandardOutput.Split('\n').Any(line => line.Trim() == "Verification OK."))
                throw new IOException($"No se pudo verificar la firma de {name}. " + result.FirstError("Sigtool no confirmó la integridad."));

            await ReadArchiveAsync(archive, catalog, ct).ConfigureAwait(false);
        }

        return catalog.Build(ct);
    }

    private static async Task ReadArchiveAsync(FileStream archive, Catalog catalog, CancellationToken ct)
    {
        const int blockSize = 512;
        archive.Position = blockSize;
        await using var gzip = new GZipStream(archive, CompressionMode.Decompress, leaveOpen: true);
        var header = new byte[blockSize];
        var discard = new byte[64 * 1024];
        long expanded = 0;
        var count = 0;
        while (true)
        {
            var read = await gzip.ReadAtLeastAsync(header, header.Length, false, ct).ConfigureAwait(false);
            // ClamAV's CVD writer omits the standard tar footer. The native reader accepts EOF at
            // a header boundary and also accepts an all-zero header if one happens to be present.
            if (read == 0) return;
            if (read != blockSize) throw new IOException("La cabecera de una entrada CVD está incompleta.");
            if (!header.AsSpan().ContainsAnyExcept((byte)0)) return;
            if (++count > 1024) throw new IOException("El archivo CVD contiene demasiadas entradas.");

            var name = Encoding.ASCII.GetString(header, 0, 100).Split('\0', 2)[0];
            if (name.Length == 0 || name.Contains('/') || name.Contains('\\') || header[156] is not (0 or (byte)'0'))
                throw new IOException("El CVD contiene un nombre o tipo de entrada no admitido.");
            var size = ReadEntrySize(header);
            var padding = (blockSize - size % blockSize) % blockSize;
            expanded += blockSize + size + padding;
            if (expanded > MaxExpandedBytes) throw new IOException("El contenido expandido del CVD supera el límite de Sentinel.");

            var extension = Path.GetExtension(name).ToLowerInvariant();
            // ClamAV loads .hsu and .hdu only when PUA detection is enabled.
            if (extension is ".hsb" or ".hdb" or ".sfp" or ".fp" or ".ign" or ".ign2")
            {
                await using var data = new EntryDataStream(gzip, size);
                using var text = new StreamReader(data, Encoding.UTF8, bufferSize: 8192, leaveOpen: true);
                while (await text.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
                {
                    if (line.Length > 8192) throw new IOException("La base CVD contiene una línea de firma demasiado extensa.");
                    if (line.Length == 0 || line[0] == '#') continue;
                    catalog.Add(extension, line);
                }
            }
            else
            {
                await SkipExactlyAsync(gzip, discard, size, ct).ConfigureAwait(false);
            }
            await SkipExactlyAsync(gzip, discard, padding, ct).ConfigureAwait(false);
        }
    }

    private static long ReadEntrySize(byte[] header)
    {
        var field = Encoding.ASCII.GetString(header, 124, 12).Trim('\0', ' ');
        if (field.Length == 0 || field.Any(digit => digit is < '0' or > '7'))
            throw new IOException("El tamaño de una entrada CVD no es válido.");
        return Convert.ToInt64(field, 8);
    }

    private static async Task SkipExactlyAsync(Stream stream, byte[] scratch, long bytes, CancellationToken ct)
    {
        while (bytes > 0)
        {
            var chunk = (int)Math.Min(bytes, scratch.Length);
            await stream.ReadExactlyAsync(scratch.AsMemory(0, chunk), ct).ConfigureAwait(false);
            bytes -= chunk;
        }
    }

    private sealed class Catalog
    {
        private readonly List<Candidate> candidates = [];
        private readonly HashSet<string> allowedHashes = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<uint> legacyAllowSizes = [];
        private readonly HashSet<string> ignoredNames = new(StringComparer.Ordinal);
        private readonly HashSet<(string Name, Guid LineDigest)> ignoredRevisions = [];
        private int exclusionRecords;

        public void Add(string extension, string line)
        {
            var isDetectionSet = extension is ".hsb" or ".hdb";
            if (isDetectionSet && line.IndexOf(':') != 64) return;
            if (!isDetectionSet && ++exclusionRecords > MaxRecords)
                throw new IOException("El catálogo SHA-256 excede el límite de exclusiones.");
            var fields = line.Split(':');
            if (extension is ".ign" or ".ign2")
            {
                if (fields is [var ignoredName]) ignoredNames.Add(ignoredName);
                else if (fields is [var revisionName, var digest] && Guid.TryParseExact(digest, "N", out var parsed))
                    ignoredRevisions.Add((revisionName, parsed));
                else if (fields.Length == 3) ignoredNames.Add(fields[2]);
                return;
            }

            if (fields.Length is < 3 or > 5 || !TryGetSize(fields[1], out var size)) return;
            var hash = fields[0];
            if (!hash.All(Uri.IsHexDigit)) return;
            if (extension is ".sfp" or ".fp")
            {
                if (hash.Length == 64) allowedHashes.Add(hash);
                else if (hash.Length is 32 or 40) legacyAllowSizes.Add(size);
                return;
            }

            var name = fields[2];
            if (hash.Length != 64 || name.Length is 0 or > 256 || !name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')) return;
            if (IsAdvisory(name)) return;
            // Ordinary hashes are independent of ClamAV functionality levels. A wildcard with the
            // historical minimum 73 is also portable. Leave other version-gated signatures to libclamav.
            if ((size == 0 || fields.Length > 3) && (fields.Length != 4 || fields[3] != "73")) return;
            if (candidates.Count == MaxRecords) throw new IOException("El catálogo SHA-256 excede el límite de registros.");

            // MD5 mirrors ClamAV's ignore-list revision syntax. It does not authenticate the database.
            var revision = new Guid(MD5.HashData(Encoding.UTF8.GetBytes(line)), bigEndian: true);
            candidates.Add(new Candidate(hash.ToUpperInvariant(), name, size, revision));
        }

        public IReadOnlyList<SignatureEntry> Build(CancellationToken ct)
        {
            var included = new Dictionary<string, SignatureEntry>(StringComparer.Ordinal);
            foreach (var candidate in candidates)
            {
                ct.ThrowIfCancellationRequested();
                if (allowedHashes.Contains(candidate.Hash) || ignoredNames.Contains(candidate.Name) ||
                    ignoredRevisions.Contains((candidate.Name, candidate.Revision))) continue;
                // A legacy allow-list hash cannot be converted to SHA-256. Conservatively exclude any
                // rule whose declared size could overlap a legacy allow-list entry.
                if (legacyAllowSizes.Contains(0) || legacyAllowSizes.Contains(candidate.Size) ||
                    (candidate.Size == 0 && legacyAllowSizes.Count > 0)) continue;

                included.TryAdd(candidate.Hash, new SignatureEntry(candidate.Hash, candidate.Name));
            }
            if (included.Count == 0) throw new IOException("Las bases oficiales no contenían un catálogo SHA-256 compatible.");
            return [.. included.Values];
        }

        private static bool TryGetSize(string field, out uint size)
        {
            size = 0;
            return field == "*" || (uint.TryParse(field, NumberStyles.None, CultureInfo.InvariantCulture, out size) && size is > 0 and < uint.MaxValue);
        }

        private static bool IsAdvisory(string name)
        {
            if (name.Contains("EICAR", StringComparison.OrdinalIgnoreCase)) return true;
            var span = name.AsSpan();
            foreach (var range in span.Split('.'))
            {
                var part = span[range];
                if (part.Equals("PUA", StringComparison.OrdinalIgnoreCase) || part.Equals("Heuristics", StringComparison.OrdinalIgnoreCase) ||
                    part.Equals("Test", StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    private readonly record struct Candidate(string Hash, string Name, uint Size, Guid Revision);

    private sealed class EntryDataStream(Stream underlying, long remaining) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var count = (int)Math.Min(remaining, buffer.Length);
            return count == 0 ? 0 : CompleteRead(underlying.Read(buffer[..count]));
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var count = (int)Math.Min(remaining, buffer.Length);
            return count == 0 ? 0 : CompleteRead(await underlying.ReadAsync(buffer[..count], cancellationToken).ConfigureAwait(false));
        }

        private int CompleteRead(int read)
        {
            if (read == 0) throw new IOException("Los datos de una entrada CVD están incompletos.");
            remaining -= read;
            return read;
        }
    }
}

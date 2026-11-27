using System.Globalization;
using Microsoft.ML.Data;
using SentinelSecurity.Engine;

namespace SentinelSecurity.MachineLearning;

internal static class FeatureDataset
{
    public const int FeatureCount = 14;
    public const int SchemaVersion = 1;
    private const int MaxRows = 300_000;
    private const long MaxFileBytes = 128L * 1024 * 1024;
    private const string ManifestHeader = "split\tgroup\tlabel\tpath";
    private const string FeaturesHeader = "split\tgroup\tlabel\tsha256\tentropy\tlogBytes\tsections\timports\twritableExecutable\tdoubleExtension\ttypeMismatch\tscriptPatterns\ttrusted\tunverified\tisPe\tisText\tisArchive\tisMalformedMz";

    public static float[] ToVector(FileFeatures features) =>
    [
        (float)features.Entropy,
        (float)Math.Log2(features.Bytes + 1),
        features.Sections,
        features.ImportedLibraries,
        features.WritableExecutableSections,
        features.HasDoubleExtension,
        features.ExecutableTypeMismatch,
        features.SuspiciousScriptPatterns,
        features.Trust == TrustResult.Trusted ? 1 : 0,
        features.Trust == TrustResult.Unverified ? 1 : 0,
        features.Type == "PE" ? 1 : 0,
        features.Type is "Texto" or "Script" ? 1 : 0,
        features.Type is "ZIP" or "GZIP" or "7z" or "RAR" ? 1 : 0,
        features.Type == "MZ" ? 1 : 0
    ];

    public static async Task ExtractAsync(string manifest, string output, CancellationToken ct)
    {
        var manifestPath = Path.GetFullPath(manifest);
        var destination = Path.GetFullPath(output);
        var stage = destination + $".{Guid.NewGuid():N}.tmp";
        if (File.Exists(destination)) throw new IOException("El archivo de salida ya existe.");
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var groupSplits = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var source = File.OpenText(manifestPath);
        await VerifyHeaderAsync(source, ManifestHeader, ct);
        try
        {
            var file = new FileStream(stage, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, useAsync: true);
            await using (var writer = new StreamWriter(file))
            {
                await writer.WriteLineAsync(FeaturesHeader.AsMemory(), ct);
                await foreach (var (line, parts) in ReadRowsAsync(source, 4, ct))
                {
                    ValidateRow(parts, line, groupSplits);
                    var path = Path.GetFullPath(parts[3], Path.GetDirectoryName(manifestPath)!);
                    var (hash, features) = await ScanEngine.ExtractEvidenceAsync(path, MaxFileBytes, ct);
                    if (!seenHashes.Add(hash)) throw new InvalidDataException($"Fila {line}: el SHA-256 está duplicado.");
                    var values = ToVector(features).Select(value => value.ToString("R", CultureInfo.InvariantCulture));
                    var outputLine = string.Join('\t', new[] { parts[0], parts[1], parts[2], hash }.Concat(values));
                    await writer.WriteLineAsync(outputLine.AsMemory(), ct);
                }
            }
            ct.ThrowIfCancellationRequested();
            File.Move(stage, destination);
        }
        finally
        {
            File.Delete(stage);
        }
    }

    public static async Task<IReadOnlyDictionary<string, List<ModelInput>>> LoadAsync(string path, CancellationToken ct)
    {
        using var source = File.OpenText(path);
        await VerifyHeaderAsync(source, FeaturesHeader, ct);
        var result = new Dictionary<string, List<ModelInput>>(StringComparer.Ordinal)
        {
            ["train"] = [], ["validation"] = [], ["test"] = []
        };
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var groupSplits = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        await foreach (var (line, parts) in ReadRowsAsync(source, 4 + FeatureCount, ct))
        {
            ValidateRow(parts, line, groupSplits);
            if (parts[3].Length != 64 || !parts[3].All(Uri.IsHexDigit) || !hashes.Add(parts[3]))
                throw new InvalidDataException($"Fila {line}: SHA-256 inválido o duplicado.");

            var features = new float[FeatureCount];
            for (var index = 0; index < features.Length; index++)
            {
                if (!float.TryParse(parts[index + 4], NumberStyles.Float, CultureInfo.InvariantCulture, out var feature) ||
                    !float.IsFinite(feature) || feature < 0 || feature > 256)
                    throw new InvalidDataException($"Fila {line}: característica numérica fuera del dominio permitido.");
                features[index] = feature;
            }
            result[parts[0]].Add(new ModelInput { Label = parts[2] == "1", Features = features });
        }

        foreach (var (split, rows) in result)
        {
            if (!rows.Any(row => row.Label) || !rows.Any(row => !row.Label))
                throw new InvalidDataException($"La partición {split} debe contener ambas clases.");
        }
        return result;
    }

    private static async Task VerifyHeaderAsync(StreamReader source, string expected, CancellationToken ct)
    {
        if (await source.ReadLineAsync(ct) != expected)
            throw new InvalidDataException("El encabezado TSV no coincide con el esquema esperado.");
    }

    private static async IAsyncEnumerable<(int Line, string[] Parts)> ReadRowsAsync(StreamReader source, int width,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var number = 1;
        while (await source.ReadLineAsync(ct) is { } line)
        {
            number++;
            if (number > MaxRows + 1 || line.Length > 32768)
                throw new InvalidDataException("Se excedió el límite de tamaño del conjunto de datos.");
            var cells = line.Split('\t');
            if (cells.Length != width) throw new InvalidDataException($"Fila {number}: número de campos TSV inesperado.");
            yield return (number, cells);
        }
    }

    private static void ValidateRow(string[] parts, int line, IDictionary<string, string> groupSplits)
    {
        if (parts[0] is not ("train" or "validation" or "test") || parts[2] is not ("0" or "1") ||
            string.IsNullOrWhiteSpace(parts[1]) || parts[1].Length > 256 || parts[1] != parts[1].Trim())
            throw new InvalidDataException($"Fila {line}: partición, grupo o etiqueta inválidos.");

        if (groupSplits.TryGetValue(parts[1], out var part) && part != parts[0])
            throw new InvalidDataException($"Fila {line}: el grupo se repite en particiones diferentes.");
        groupSplits[parts[1]] = parts[0];
    }
}

internal sealed class ModelInput
{
    public bool Label { get; init; }

    [VectorType(FeatureDataset.FeatureCount)]
    public float[] Features { get; init; } = [];
}

internal sealed class ModelOutput
{
    public bool Label { get; set; }
    public bool PredictedLabel { get; set; }
    public float Score { get; set; }
}

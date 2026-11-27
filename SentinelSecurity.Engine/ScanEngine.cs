using System.Diagnostics;
using System.Security.Cryptography;
using SentinelSecurity.Core;

namespace SentinelSecurity.Engine;

public sealed class ScanEngine(ISignatureLookup signatures)
{
    private readonly SemaphoreSlim fileSlots = new(8, 8);
    private readonly ExternalDetectors external = new();
    private EngineConfiguration configuration = new();

    public void Configure(EngineConfiguration value) => Volatile.Write(ref configuration, value);

    public async Task<IReadOnlyList<EngineStatus>> GetStatusAsync(CancellationToken ct)
    {
        var current = Volatile.Read(ref configuration);
        var externalTask = external.GetStatusAsync(current, ct);
        var signatureTask = CheckSignaturesAsync(ct);
        await Task.WhenAll(externalTask, signatureTask);
        var externalStatuses = await externalTask;
        var signatureStatus = await signatureTask;
        return [signatureStatus, new EngineStatus("Heurística", true, "Inspección estática local disponible."), .. externalStatuses];
    }

    public Task<EngineStatus> CheckClamAsync(EngineConfiguration candidate, CancellationToken ct) =>
        external.GetClamStatusAsync(candidate, ct);

    public Task<EngineStatus> CheckYaraAsync(EngineConfiguration candidate, CancellationToken ct) =>
        external.GetYaraStatusAsync(candidate, ct);

    public async Task<EngineStatus> CheckSignaturesAsync(CancellationToken ct)
    {
        if (!signatures.HasSignatures)
            return new EngineStatus("SHA-256", false, "Sin firmas locales importadas.");
        try
        {
            var digest = Convert.ToHexString(SHA256.HashData("abc"u8));
            var available = digest == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD" &&
                await signatures.VerifyAsync(ct);
            return new EngineStatus("SHA-256", available, available ?
                "Cálculo SHA-256 y búsqueda en el catálogo verificados." : "No se pudo verificar el catálogo local.");
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            return new EngineStatus("SHA-256", false, "El catálogo local no respondió a la comprobación.");
        }
    }

    public async Task<FileResult> ScanFileAsync(string path, ScanOptions options, CancellationToken ct)
    {
        try
        {
            return await ScanFileCoreAsync(ScanPath.Normalize(path), options, ScanPath.GetExclusions(options.Exclusions),
                Volatile.Read(ref configuration), ct);
        }
        catch (Exception error) when (ScanPath.Expected(error))
        {
            return Omitted(path, error.Message);
        }
    }

    public async Task<ScanSummary> ScanAsync(ScanKind kind, IReadOnlyList<string> roots, ScanOptions options, ScanControl control,
        IProgress<ScanProgress>? progress, Func<FileResult, CancellationToken, ValueTask> onFile, CancellationToken ct)
    {
        var id = control.Id;
        var started = DateTimeOffset.UtcNow;
        var timer = Stopwatch.StartNew();
        var exclusions = ScanPath.GetExclusions(options.Exclusions);
        var current = Volatile.Read(ref configuration);
        var examined = 0;
        var threats = 0;
        var skipped = 0;
        var canceled = false;
        var lastProgress = long.MinValue;
        var total = roots.All(File.Exists) ? roots.Select(Path.GetFullPath).Distinct(ScanPath.Comparer).Count() : (int?)null;

        try
        {
            await Parallel.ForEachAsync(Enumerate(roots, exclusions, Math.Clamp(options.MaxDepth, 1, 256), ct),
                new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(options.Concurrency, 1, 8), CancellationToken = ct },
                async (candidate, token) =>
                {
                    await control.WaitAsync(token);
                    ReportProgress(candidate.Path);
                    var result = candidate.Error is null
                        ? await ScanFileCoreAsync(candidate.Path, options, exclusions, current, token)
                        : Omitted(candidate.Path, candidate.Error);
                    if (result.Verdict == Verdict.Unscanned)
                        Interlocked.Increment(ref skipped);
                    else
                        Interlocked.Increment(ref examined);
                    if (result.Verdict is Verdict.Suspicious or Verdict.HighRisk or Verdict.Malware)
                        Interlocked.Increment(ref threats);
                    await onFile(result, token);
                    ReportProgress(candidate.Path);
                });
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            canceled = true;
        }

        progress?.Report(new ScanProgress(examined, threats, skipped, total, string.Empty, timer.Elapsed));
        return new ScanSummary(id, kind, started, timer.Elapsed, examined, threats, skipped, canceled);

        void ReportProgress(string file)
        {
            if (progress is null) return;
            var now = timer.ElapsedMilliseconds;
            var previous = Interlocked.Read(ref lastProgress);
            if ((previous == long.MinValue || now - previous >= 100 || examined + skipped == total) &&
                Interlocked.CompareExchange(ref lastProgress, now, previous) == previous)
                progress.Report(new ScanProgress(examined, threats, skipped, total, file, timer.Elapsed));
        }
    }

    public static async Task<FileFeatures> ExtractFeaturesAsync(string path, long maxFileBytes, CancellationToken ct)
        => (await ExtractEvidenceAsync(path, maxFileBytes, ct)).Features;

    public static async Task<(string Sha256, FileFeatures Features)> ExtractEvidenceAsync(string path, long maxFileBytes,
        CancellationToken ct)
    {
        var normalized = ScanPath.Normalize(path);
        if ((ScanPath.CheckRegularPath(normalized) & FileAttributes.Directory) != 0)
            throw new IOException("La ruta no es un archivo.");
        await using var stream = OpenFile(normalized);
        if (stream.Length > maxFileBytes)
            throw new IOException("El archivo excede el límite de tamaño configurado.");
        var result = await FileInspector.InspectAsync(stream, normalized, maxFileBytes, ct);
        return (result.Sha256, result.Features);
    }

    private async Task<FileResult> ScanFileCoreAsync(string path, ScanOptions options, string[] exclusions,
        EngineConfiguration current, CancellationToken ct)
    {
        await fileSlots.WaitAsync(ct);
        try
        {
            if (ScanPath.IsExcluded(path, exclusions))
                return Omitted(path, "Ruta excluida en la configuración.");
            if ((ScanPath.CheckRegularPath(path) & FileAttributes.Directory) != 0)
                return Omitted(path, "La ruta no es un archivo.");

            await using var stream = OpenFile(path);
            var limit = Math.Clamp(options.MaxFileBytes, 1, 2L * 1024 * 1024 * 1024);
            var length = stream.Length;
            if (length > limit)
                return Omitted(path, "El archivo excede el límite de tamaño configurado.", length);

            var lastWrite = File.GetLastWriteTimeUtc(path);
            var inspection = await FileInspector.InspectAsync(stream, path, limit, ct);
            var detections = HeuristicDetections(inspection);
            var signature = await signatures.FindAsync(inspection.Sha256, ct);
            if (signature is not null)
                detections.Add(new Detection("SHA-256", signature, Verdict.Malware));

            ScanPath.CheckRegularPath(path);
            var (matches, errors) = await external.ScanAsync(path, current, ct);
            detections.AddRange(matches);
            if (length != inspection.Features.Bytes || stream.Length != length || File.GetLastWriteTimeUtc(path) != lastWrite)
                return Omitted(path, "El archivo cambió durante el análisis.", length);

            var verdict = detections.Count == 0 ? (errors.Count == 0 ? Verdict.Clean : Verdict.Unscanned)
                : detections.Max(item => item.Verdict);
            return new FileResult(path, inspection.Sha256, inspection.Features.Bytes, inspection.Features.Type,
                verdict, detections, errors.Count == 0 ? null : string.Join(" | ", errors));
        }
        catch (Exception error) when (ScanPath.Expected(error))
        {
            return Omitted(path, error.Message);
        }
        finally
        {
            fileSlots.Release();
        }
    }

    private static FileStream OpenFile(string path) => new(path, FileMode.Open, FileAccess.Read, FileShare.Read,
        64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static List<Detection> HeuristicDetections(FileInspection inspection)
    {
        var features = inspection.Features;
        var reasons = new List<(string Description, int Score)>();
        if (features.HasDoubleExtension > 0) reasons.Add(("Extensión activa después de una extensión de documento", 35));
        if (features.ExecutableTypeMismatch > 0) reasons.Add(("Ejecutable PE con extensión de documento", 45));
        if (features.WritableExecutableSections > 0) reasons.Add(("Secciones PE ejecutables y escribibles", 30));
        if (features.Type == "PE" && features.Bytes >= 8192 && features.Entropy >= 7.3)
            reasons.Add(("Entropía alta en los primeros 64 KiB del PE", 15));
        if (features.Trust == TrustResult.Unverified) reasons.Add(("Firma Authenticode no validada localmente", 10));
        if (features.SuspiciousScriptPatterns >= 2) reasons.Add(("Combinación de patrones de ofuscación en script", 35));
        if (features.WritableExecutableSections > 0 && inspection.Imports.Any(name => name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase)))
            reasons.Add(("Importación nativa combinada con una sección PE escribible y ejecutable", 10));

        var score = Math.Min(100, reasons.Sum(reason => reason.Score));
        if (score < 30)
            return [];
        return [new Detection("Heurística", string.Join(" · ", reasons.Select(reason => reason.Description)),
            score >= 65 ? Verdict.HighRisk : Verdict.Suspicious, score)];
    }

    private static FileResult Omitted(string path, string message, long size = 0) =>
        new(path, null, size, "Desconocido", Verdict.Unscanned, [], message);

    private static IEnumerable<Candidate> Enumerate(IReadOnlyList<string> roots, string[] exclusions, int maxDepth, CancellationToken ct)
    {
        var unique = new HashSet<string>(ScanPath.Comparer);
        foreach (var item in roots)
        {
            ct.ThrowIfCancellationRequested();
            var path = item;
            FileAttributes attrs = default;
            string? error = null;
            try
            {
                path = ScanPath.Normalize(item);
                if (!unique.Add(path)) continue;
                attrs = ScanPath.CheckRegularPath(path);
            }
            catch (Exception ex) when (ScanPath.Expected(ex))
            {
                error = ex.Message;
            }

            if (error is not null || (attrs & FileAttributes.Directory) == 0)
                yield return new Candidate(path, error);
            else
                foreach (var candidate in WalkDirectory(path, exclusions, maxDepth, ct))
                    yield return candidate;
        }
    }

    private static IEnumerable<Candidate> WalkDirectory(string path, string[] exclusions, int remainingDepth, CancellationToken ct)
    {
        if (ScanPath.IsExcluded(path, exclusions) || remainingDepth < 0)
        {
            yield return new Candidate(path, remainingDepth < 0 ? "Se superó la profundidad de recorrido." : "Carpeta excluida en la configuración.");
            yield break;
        }

        using var entries = TryEnumerate(path, out var enumerationError);
        if (entries is null)
        {
            yield return new Candidate(path, enumerationError);
            yield break;
        }

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var entry = path;
            var available = false;
            var directory = false;
            string? error = null;
            try
            {
                available = entries.MoveNext();
                if (!available) break;
                entry = entries.Current;
                var attrs = File.GetAttributes(entry);
                ScanPath.CheckAttributes(attrs);
                directory = (attrs & FileAttributes.Directory) != 0;
            }
            catch (Exception ex) when (ScanPath.Expected(ex))
            {
                error = ex.Message;
            }

            if (directory)
            {
                foreach (var candidate in WalkDirectory(entry, exclusions, remainingDepth - 1, ct))
                    yield return candidate;
            }
            else
                yield return new Candidate(entry, error);

            if (!available) yield break;
        }
    }

    private static IEnumerator<string>? TryEnumerate(string path, out string? error)
    {
        try
        {
            ScanPath.CheckRegularPath(path);
            error = null;
            return Directory.EnumerateFileSystemEntries(path).GetEnumerator();
        }
        catch (Exception ex) when (ScanPath.Expected(ex))
        {
            error = ex.Message;
            return null;
        }
    }

    private sealed record Candidate(string Path, string? Error);
}

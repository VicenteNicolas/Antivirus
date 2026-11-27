using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;
using SentinelSecurity.Core;
using SentinelSecurity.Engine;

namespace SentinelSecurity.Monitoring;

public sealed class FileMonitor : IAsyncDisposable
{
    private static readonly TimeSpan ReconcileInterval = TimeSpan.FromMinutes(10);
    private readonly ScanEngine engine;
    private readonly ScanOptions options;
    private readonly string[] roots;
    private readonly Func<FileResult, CancellationToken, ValueTask> onFile;
    private readonly Action<string> onStatus;
    private readonly List<FileSystemWatcher> watchers = [];
    private readonly Channel<(string Path, long QueuedAt)> queue = Channel.CreateBounded<(string, long)>(new BoundedChannelOptions(1024)
    {
        SingleReader = true,
        FullMode = BoundedChannelFullMode.Wait
    });
    private readonly Channel<bool> reconcile = Channel.CreateBounded<bool>(1);
    private readonly ConcurrentDictionary<string, byte> pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (long Length, DateTime Write, DateTime Created)> seen =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource stop = new();
    private readonly Task worker;
    private readonly Task sweeper;
    private readonly Task timer;
    private int degraded;

    public FileMonitor(ScanEngine engine, ScanOptions options, IEnumerable<string> roots,
        Func<FileResult, CancellationToken, ValueTask> onFile, Action<string> onStatus)
    {
        this.engine = engine;
        this.options = options;
        this.onFile = onFile;
        this.onStatus = onStatus;
        this.roots = roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        try
        {
            foreach (var root in this.roots)
            {
                if (!PathSafety.IsLocalWithoutLinks(root, directory: true))
                    throw new IOException($"La carpeta vigilada no está disponible: {root}");

                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite
                        | NotifyFilters.Size | NotifyFilters.CreationTime
                };
                watchers.Add(watcher);
                watcher.Created += OnChanged;
                watcher.Changed += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.Deleted += (sender, args) => seen.TryRemove(args.FullPath, out _);
                watcher.Error += (_, _) =>
                {
                    if (Interlocked.Exchange(ref degraded, 1) == 0)
                        onStatus("Se perdieron eventos. Se reconciliarán las carpetas. Reactiva el monitor para verificar la vigilancia.");
                    reconcile.Writer.TryWrite(true);
                };
                watcher.EnableRaisingEvents = true;
            }
        }
        catch
        {
            foreach (var watcher in watchers)
                watcher.Dispose();
            stop.Dispose();
            throw;
        }
        worker = Task.Run(() => ConsumeAsync(stop.Token));
        sweeper = Task.Run(() => ReconcileAsync(stop.Token));
        timer = Task.Run(() => TickAsync(stop.Token));
        reconcile.Writer.TryWrite(true);
    }

    public bool IsDegraded => Volatile.Read(ref degraded) != 0;
    public bool IsActive => watchers.Count > 0 && !worker.IsCompleted && !stop.IsCancellationRequested && !IsDegraded;

    private void OnChanged(object sender, FileSystemEventArgs args)
    {
        seen.TryRemove(args.FullPath, out _);
        if (Directory.Exists(args.FullPath))
        {
            reconcile.Writer.TryWrite(true);
            return;
        }
        if (pending.TryAdd(args.FullPath, 0) && !queue.Writer.TryWrite((args.FullPath, Stopwatch.GetTimestamp())))
        {
            pending.TryRemove(args.FullPath, out _);
            RequestReconciliation("Cola de vigilancia llena; se volverán a revisar las carpetas.");
        }
    }

    private void OnRenamed(object sender, RenamedEventArgs args)
    {
        seen.TryRemove(args.OldFullPath, out _);
        OnChanged(sender, args);
    }

    private void RequestReconciliation(string message)
    {
        if (reconcile.Writer.TryWrite(true))
            onStatus(message);
    }

    private async Task TickAsync(CancellationToken ct)
    {
        using var periodic = new PeriodicTimer(ReconcileInterval);
        while (await periodic.WaitForNextTickAsync(ct))
            reconcile.Writer.TryWrite(true);
    }

    private async Task ReconcileAsync(CancellationToken ct)
    {
        await foreach (var _ in reconcile.Reader.ReadAllAsync(ct))
        {
            foreach (var root in roots)
            {
                if (!PathSafety.IsLocalWithoutLinks(root, directory: true))
                {
                    Interlocked.Exchange(ref degraded, 1);
                    onStatus($"No se puede reconciliar la carpeta: {root}");
                    continue;
                }
                try
                {
                    var enumeration = new EnumerationOptions
                    {
                        RecurseSubdirectories = true, IgnoreInaccessible = true, MaxRecursionDepth = options.MaxDepth,
                        AttributesToSkip = FileAttributes.ReparsePoint
                    };
                    foreach (var path in Directory.EnumerateFiles(root, "*", enumeration))
                    {
                        ct.ThrowIfCancellationRequested();
                        if (TryStamp(path) is { } stamp && seen.TryGetValue(path, out var previous) && stamp == previous)
                            continue;
                        if (pending.TryAdd(path, 0))
                            await queue.Writer.WriteAsync((path, 0), ct);
                    }
                }
                catch (Exception error) when (error is IOException or UnauthorizedAccessException)
                {
                    onStatus($"Reconciliación incompleta: {error.Message}");
                }
            }
        }
    }

    private async Task ConsumeAsync(CancellationToken ct)
    {
        await foreach (var (path, queuedAt) in queue.Reader.ReadAllAsync(ct))
        {
            pending.TryRemove(path, out _);
            if (!PathSafety.IsLocalWithoutLinks(path, directory: false))
                continue;
            var excluded = options.Exclusions?.Any(root => PathSafety.IsWithin(path, root)) ?? false;
            if (excluded)
                continue;

            var initial = TryStamp(path);
            if (initial is null)
                continue;
            if (queuedAt != 0)
            {
                var remaining = TimeSpan.FromMilliseconds(120) - Stopwatch.GetElapsedTime(queuedAt);
                if (remaining > TimeSpan.Zero)
                    await Task.Delay(remaining, ct);
            }
            FileResult? result = null;
            try
            {
                for (var attempt = 0; attempt < 3; attempt++)
                {
                    result = await engine.ScanFileAsync(path, options, ct);
                    if (result.Verdict != Verdict.Unscanned || !File.Exists(path))
                        break;
                    if (attempt < 2)
                        await Task.Delay(250 * (attempt + 1), ct);
                }
                if (result is null)
                    continue;
                if (TryStamp(path) == initial && result.Verdict != Verdict.Unscanned)
                {
                    if (seen.Count >= 100_000)
                        seen.Clear();
                    seen[path] = initial.Value;
                }
                if (result.Verdict != Verdict.Clean || result.Error is not null)
                    await onFile(result, ct);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                onStatus($"Error de vigilancia: {error.Message}");
            }
        }
    }

    private static (long Length, DateTime Write, DateTime Created)? TryStamp(string path)
    {
        try
        {
            var file = new FileInfo(path);
            return file.Exists ? (file.Length, file.LastWriteTimeUtc, file.CreationTimeUtc) : null;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var watcher in watchers)
            watcher.Dispose();
        await stop.CancelAsync();
        try { await Task.WhenAll(worker, sweeper, timer); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        stop.Dispose();
    }
}

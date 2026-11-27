using System.Security.Cryptography;
using SentinelSecurity.Core;
using SentinelSecurity.Engine;
using SentinelSecurity.Infrastructure;
using SentinelSecurity.Monitoring;
using Xunit;

namespace SentinelSecurity.Tests;

public sealed class SecurityTests
{
    private const string StandardEicarSha256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F";
    private static string? EicarPath => Environment.GetEnvironmentVariable("SENTINEL_EICAR_PATH");
    public static bool HasLocalEicarFixture => EicarPath is { } path && File.Exists(path);

    [Fact]
    public async Task HashCatalogFindsTheExactContentAndSurvivesReopen()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var original = await directory.WriteAsync("sample.txt", "Sentinel integration fixture", ct);
        var different = await directory.WriteAsync("different.txt", "Different benign file", ct);
        var hash = await HashAsync(original, ct);
        var store = await directory.StoreAsync(ct);
        Assert.False(store.HasSignatures);
        await store.ImportSignaturesAsync([new SignatureEntry(hash, "Synthetic.Test")], "test-v1", ct);
        var reopened = await directory.StoreAsync(ct);
        var engine = new ScanEngine(reopened);

        Assert.True(reopened.HasSignatures);
        var matched = await engine.ScanFileAsync(original, new(), ct);
        Assert.Equal(Verdict.Malware, matched.Verdict);
        Assert.Equal(hash, matched.Sha256);
        Assert.Contains(matched.Detections, item => item.Name == "Synthetic.Test");
        Assert.Equal(Verdict.Clean, (await engine.ScanFileAsync(different, new(), ct)).Verdict);
        Assert.Contains(await reopened.GetUpdatesAsync(ct), record => record.Version == "test-v1");
    }

    [Fact]
    public async Task ManualScanRecordsReportedFindingsAndHonorsExclusions()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var first = await directory.WriteAsync("benign.txt", "one", ct);
        var candidate = await directory.WriteAsync("sub/flagged.txt", "two", ct);
        var excluded = await directory.WriteAsync("exclude/ignore.txt", "two", ct);
        var store = await directory.StoreAsync(ct);
        await store.ImportSignaturesAsync([new SignatureEntry(await HashAsync(candidate, ct), "Synthetic.Test")], "test-v2", ct);
        var control = new ScanControl();
        var engine = new ScanEngine(store);
        var summary = await engine.ScanAsync(ScanKind.Custom, [directory.Files],
            new ScanOptions(Exclusions: [Path.GetDirectoryName(excluded)!]), control, null,
            async (file, token) =>
            {
                if (file.Verdict != Verdict.Clean)
                    await store.RecordFindingAsync(control.Id, file, token);
            }, ct);
        await store.RecordScanAsync(summary, ct);

        Assert.True(File.Exists(first));
        Assert.Equal(control.Id, summary.Id);
        Assert.Equal(2, summary.Examined);
        Assert.Equal(1, summary.Threats);
        Assert.Equal(candidate, Assert.Single(await store.GetFindingsAsync(ct),
            finding => finding.Verdict == Verdict.Malware).Path);
        Assert.Equal(summary.Id, Assert.Single(await store.GetScansAsync(ct)).Id);
    }

    [Fact]
    public async Task PauseCanBeResumedAndWaitsCanBeCancelled()
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var control = new ScanControl();
        control.Pause();
        var paused = control.WaitAsync(stop.Token);
        Assert.False(paused.IsCompleted);
        control.Resume();
        await paused;
        Assert.False(control.IsPaused);
        control.Pause();
        var wait = control.WaitAsync(stop.Token);
        await stop.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
    }

    [Fact]
    public async Task AboveTheResourceLimitIsUnscanned()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var file = await directory.WriteAsync("large.txt", new string('x', 4096), ct);
        var engine = new ScanEngine(await directory.StoreAsync(ct));
        var result = await engine.ScanFileAsync(file, new ScanOptions(MaxFileBytes: 16), ct);
        Assert.Equal(Verdict.Unscanned, result.Verdict);
        Assert.Null(result.Sha256);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public async Task SettingChangesPersistOutsideTheSourceFolder()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var store = await directory.StoreAsync(ct);
        Assert.False((await store.LoadSettingsAsync(ct)).StartWithWindows);
        await store.SaveSettingsAsync(new SentinelSettings
        {
            GamingMode = true, Exclusions = [directory.Files], Concurrency = 3
        }, ct);
        var saved = await (await directory.StoreAsync(ct)).LoadSettingsAsync(ct);
        Assert.True(saved.GamingMode);
        Assert.Equal(directory.Files, Assert.Single(saved.Exclusions));
        Assert.Equal(3, saved.Concurrency);
        Assert.Empty(Directory.EnumerateFiles(directory.Files));
    }

    [Fact]
    public async Task QuarantineIsVerifiedAndNeverOverwritesAnExistingDestination()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        const string text = "Benign quarantine round trip";
        var file = await directory.WriteAsync("isolate.txt", text, ct);
        var hash = await HashAsync(file, ct);
        var store = await directory.StoreAsync(ct);
        var quarantine = new QuarantineService(store, directory.Data);
        var simulated = new FileResult(file, hash, new FileInfo(file).Length, "text", Verdict.Malware,
            [new Detection("Test", "Quarantine test", Verdict.Malware)]);

        var item = await quarantine.IsolateAsync(simulated, ct);
        Assert.False(File.Exists(file));
        Assert.True(await quarantine.VerifyAsync(item.Id, ct));
        await File.WriteAllTextAsync(file, "New unrelated file", ct);
        await Assert.ThrowsAnyAsync<IOException>(() => quarantine.RestoreAsync(item.Id, ct));
        Assert.Equal("New unrelated file", await File.ReadAllTextAsync(file, ct));
        File.Delete(file);
        await quarantine.RestoreAsync(item.Id, ct);
        Assert.Equal(text, await File.ReadAllTextAsync(file, ct));
        Assert.Empty(await store.GetQuarantineAsync(ct));
    }

    [Fact]
    public async Task MonitorScansANewFileInASelectedFolder()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var store = await directory.StoreAsync(ct);
        const string text = "Benign watcher fixture";
        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text)));
        await store.ImportSignaturesAsync([new SignatureEntry(hash, "Monitor.Test")], "test-monitor", ct);
        var result = new TaskCompletionSource<FileResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var monitor = new FileMonitor(new ScanEngine(store), new(), [directory.Files],
            (file, _) =>
            {
                if (file.Verdict == Verdict.Malware)
                    result.TrySetResult(file);
                return ValueTask.CompletedTask;
            }, _ => { });
        var file = await directory.WriteAsync("watch.txt", text, ct);
        Assert.True(monitor.IsActive);
        Assert.Equal(file, (await result.Task.WaitAsync(TimeSpan.FromSeconds(15), ct)).Path);
    }

    [Fact(SkipUnless = nameof(HasLocalEicarFixture), Skip = "EICAR externo opcional; no se crea ni descarga en CI.")]
    public async Task OfficialEicarFixtureIsDetectedByItsExactHash()
    {
        using var directory = new FixtureDirectory();
        var ct = TestContext.Current.CancellationToken;
        var store = await directory.StoreAsync(ct);
        await store.ImportSignaturesAsync([new SignatureEntry(StandardEicarSha256, "EICAR-Test-File")], "eicar-local", ct);
        var result = await new ScanEngine(store).ScanFileAsync(Path.GetFullPath(EicarPath!), new(), ct);
        Assert.Equal(StandardEicarSha256, result.Sha256);
        Assert.Equal(Verdict.Malware, result.Verdict);
    }

    private static async Task<string> HashAsync(string path, CancellationToken ct)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
    }

    private sealed class FixtureDirectory : IDisposable
    {
        private readonly string path = Path.Combine(Path.GetTempPath(), "SentinelTests-" + Guid.NewGuid().ToString("N"));
        public string Data => Path.Combine(path, "data");
        public string Files => Directory.CreateDirectory(Path.Combine(path, "files")).FullName;

        public async Task<string> WriteAsync(string relative, string content, CancellationToken ct)
        {
            var file = Path.Combine(Files, relative.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            await File.WriteAllTextAsync(file, content, ct);
            return file;
        }

        public async Task<SqliteStore> StoreAsync(CancellationToken ct)
        {
            var store = new SqliteStore(Data);
            await store.InitializeAsync(ct);
            return store;
        }

        public void Dispose()
        {
            if (Directory.Exists(path))
                Directory.Delete(path, recursive: true);
        }
    }
}

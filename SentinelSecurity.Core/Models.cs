namespace SentinelSecurity.Core;

public enum Verdict { Clean, Suspicious, HighRisk, Malware, Unscanned }
public enum ScanKind { Quick, Full, Custom, Monitor, Process }

public sealed record Detection(string Engine, string Name, Verdict Verdict, int Score = 0);
public sealed record FileResult(string Path, string? Sha256, long Size, string FileType,
    Verdict Verdict, IReadOnlyList<Detection> Detections, string? Error = null);
public sealed record ScanOptions(int Concurrency = 2, long MaxFileBytes = 134217728,
    IReadOnlyList<string>? Exclusions = null, int MaxDepth = 128);
public sealed record ScanProgress(int Examined, int Threats, int Skipped, int? Total,
    string CurrentFile, TimeSpan Elapsed);
public sealed record ScanSummary(Guid Id, ScanKind Kind, DateTimeOffset Started, TimeSpan Elapsed,
    int Examined, int Threats, int Skipped, bool Canceled);
public sealed record QuarantineItem(Guid Id, string OriginalPath, string Sha256, string Reason,
    DateTimeOffset IsolatedAt);
public sealed record SignatureEntry(string Sha256, string Name);
public sealed record UpdateRecord(string Source, string Version, DateTimeOffset UpdatedAt);
public sealed record EngineConfiguration(string? ClamScan = null, string? ClamDatabase = null,
    string? Yara = null, string? YaraRules = null);
public sealed record EngineStatus(string Name, bool Available, string Detail);

public interface ISignatureLookup
{
    bool HasSignatures { get; }
    ValueTask<string?> FindAsync(string sha256, CancellationToken ct);
}

public sealed record SentinelSettings
{
    public bool MonitorEnabled { get; init; }
    public bool Notifications { get; init; } = true;
    public bool StartWithWindows { get; init; }
    public bool AutoUpdate { get; init; }
    public bool GamingMode { get; init; }
    public bool LightTheme { get; init; }
    public string[] WatchFolders { get; init; } = [];
    public string[] Exclusions { get; init; } = [];
    public int Concurrency { get; init; } = 2;
    public int MaxFileMegabytes { get; init; } = 128;
    public int ScheduledScanHours { get; init; }
    public string? ClamScan { get; init; }
    public string? ClamDatabase { get; init; }
    public string? FreshClam { get; init; }
    public string? Yara { get; init; }
    public string? YaraRules { get; init; }
}

using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using SentinelSecurity.Core;
using SentinelSecurity.Engine;
using SentinelSecurity.Monitoring;

namespace SentinelSecurity.UI;

public sealed partial class ShellViewModel
{
    private bool monitorEnabled;
    private bool notifications = true;
    private bool startWithWindows;
    private bool autoUpdate;
    private bool gamingMode;
    private bool lightTheme;
    private string watchFoldersText = "";
    private string exclusionsText = "";
    private int concurrency = 2;
    private int maxFileMegabytes = 128;
    private int scheduledScanHours;
    private string clamScanPath = "";
    private string clamDatabasePath = "";
    private string freshClamPath = "";
    private string yaraPath = "";
    private DateTimeOffset lastSchedule = DateTimeOffset.UtcNow;
    private DateTimeOffset scheduledRetryAfter;
    private DateTimeOffset automaticUpdateAfter = DateTimeOffset.MinValue;

    public bool MonitorEnabled { get => monitorEnabled; set => Set(ref monitorEnabled, value); }
    public bool Notifications { get => notifications; set => Set(ref notifications, value); }
    public bool StartWithWindows { get => startWithWindows; set => Set(ref startWithWindows, value); }
    public bool AutoUpdate { get => autoUpdate; set => Set(ref autoUpdate, value); }
    public bool GamingMode { get => gamingMode; set => Set(ref gamingMode, value); }
    public bool LightTheme { get => lightTheme; set => Set(ref lightTheme, value); }
    public string WatchFoldersText { get => watchFoldersText; set => Set(ref watchFoldersText, value); }
    public string ExclusionsText { get => exclusionsText; set => Set(ref exclusionsText, value); }
    public int Concurrency { get => concurrency; set => Set(ref concurrency, value); }
    public int MaxFileMegabytes { get => maxFileMegabytes; set => Set(ref maxFileMegabytes, value); }
    public int ScheduledScanHours { get => scheduledScanHours; set => Set(ref scheduledScanHours, value); }
    public string ClamScanPath { get => clamScanPath; set => Set(ref clamScanPath, value); }
    public string ClamDatabasePath { get => clamDatabasePath; set => Set(ref clamDatabasePath, value); }
    public string FreshClamPath { get => freshClamPath; set => Set(ref freshClamPath, value); }
    public string YaraPath { get => yaraPath; set => Set(ref yaraPath, value); }

    private void ApplySettingsToEditor()
    {
        MonitorEnabled = settings.MonitorEnabled;
        Notifications = settings.Notifications;
        StartWithWindows = settings.StartWithWindows;
        AutoUpdate = settings.AutoUpdate;
        GamingMode = settings.GamingMode;
        LightTheme = settings.LightTheme;
        WatchFoldersText = string.Join(Environment.NewLine, settings.WatchFolders);
        ExclusionsText = string.Join(Environment.NewLine, settings.Exclusions);
        Concurrency = settings.Concurrency;
        MaxFileMegabytes = settings.MaxFileMegabytes;
        ScheduledScanHours = settings.ScheduledScanHours;
        ClamScanPath = settings.ClamScan ?? "";
        ClamDatabasePath = settings.ClamDatabase ?? "";
        FreshClamPath = settings.FreshClam ?? "";
        YaraPath = settings.Yara ?? "";
    }

    private async Task SaveSettingsAsync(CancellationToken ct)
    {
        if (Concurrency is < 1 or > 4 || MaxFileMegabytes is < 1 or > 512 || ScheduledScanHours is < 0 or > 720)
            throw new ArgumentException("Configura entre 1 y 4 hilos, entre 1 y 512 MB por archivo y entre 0 y 720 horas.");
        var updated = settings with
        {
            MonitorEnabled = MonitorEnabled, Notifications = Notifications, StartWithWindows = StartWithWindows,
            AutoUpdate = AutoUpdate, GamingMode = GamingMode, LightTheme = LightTheme,
            WatchFolders = ParsePaths(WatchFoldersText), Exclusions = ParsePaths(ExclusionsText),
            Concurrency = Concurrency, MaxFileMegabytes = MaxFileMegabytes, ScheduledScanHours = ScheduledScanHours,
            ClamScan = ValidateTool(ClamScanPath), ClamDatabase = ValidatePath(ClamDatabasePath, directory: true),
            FreshClam = ValidateTool(FreshClamPath), Yara = ValidateTool(YaraPath)
        };
        if (updated.WatchFolders.Any(path => !PathSafety.IsLocalWithoutLinks(path, directory: true)))
            throw new ArgumentException("Las carpetas vigiladas deben existir en una unidad local y no usar enlaces.");
        await SaveAndApplyAsync(updated, ct);
        await RefreshEngineDataAsync(ct);
        StatusText = "Configuración guardada.";
    }

    private static string[] ParsePaths(string text) => text
        .Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
        .Select(path =>
        {
            var expanded = Environment.ExpandEnvironmentVariables(path);
            if (!Path.IsPathFullyQualified(expanded) || expanded.StartsWith(@"\\", StringComparison.Ordinal))
                throw new ArgumentException($"Usa una ruta local absoluta: {path}");
            var full = Path.GetFullPath(expanded);
            if (full.AsSpan(2).Contains(':'))
                throw new ArgumentException($"Ruta no válida: {path}");
            return Path.TrimEndingDirectorySeparator(full);
        })
        .Distinct(StringComparer.OrdinalIgnoreCase).Take(65)
        .ToArray() is { Length: <= 64 } paths ? paths : throw new ArgumentException("Se permiten hasta 64 rutas por lista.");

    private static string? ValidatePath(string? raw, bool directory)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var path = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (!PathSafety.IsLocalWithoutLinks(path, directory))
            throw new ArgumentException($"La ruta indicada no existe o no es una ruta local normal: {path}");
        return Path.GetFullPath(path);
    }

    private static string? ValidateTool(string? raw)
    {
        var path = ValidatePath(raw, directory: false);
        if (path is not null && !string.Equals(Path.GetExtension(path), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Selecciona el ejecutable instalado: {path}");
        return path;
    }

    private static void SetWindowsStartup(bool enabled)
    {
        const string key = @"Software\Microsoft\Windows\CurrentVersion\Run";
        if (enabled)
        {
            var executable = Environment.ProcessPath ?? throw new IOException("No se encontró el ejecutable de Sentinel Security.");
            if (!string.Equals(Path.GetFileNameWithoutExtension(executable), "SentinelSecurity.UI",
                StringComparison.OrdinalIgnoreCase))
                throw new IOException("Abre el ejecutable publicado para registrar el inicio automático.");
            using var run = Registry.CurrentUser.CreateSubKey(key);
            run.SetValue("SentinelSecurity", $"\"{executable}\"", RegistryValueKind.String);
        }
        else
        {
            using var run = Registry.CurrentUser.OpenSubKey(key, writable: true);
            run?.DeleteValue("SentinelSecurity", throwOnMissingValue: false);
        }
    }

    private void ConfigureEngine() => engine.Configure(new EngineConfiguration(settings.ClamScan,
        settings.ClamDatabase, settings.Yara, settings.YaraRules));

    private FileMonitor? CreateMonitor(SentinelSettings candidate)
    {
        if (!candidate.MonitorEnabled || disposed)
            return null;
        var roots = candidate.WatchFolders;
        if (roots.Length == 0)
        {
            var downloads = ReadDownloadsFolder() ??
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!PathSafety.IsLocalWithoutLinks(downloads, directory: true))
                throw new IOException("Configura una carpeta para activar el monitor.");
            roots = [downloads];
        }
        if (roots.Any(path => PathSafety.IsWithin(path, dataDirectory)))
            throw new IOException("La carpeta privada de Sentinel no puede vigilarse.");
        return new FileMonitor(engine, Options(candidate), roots, OnMonitoredFileAsync, message =>
            dispatcher.BeginInvoke(() =>
            {
                if (disposed)
                    return;
                StatusText = message;
                OnChanged(nameof(MonitorActive));
                OnChanged(nameof(ProtectionBadge));
            }));
    }

    private Task ConfigureMonitorAsync() => ReplaceMonitorAsync(CreateMonitor(settings));

    private async Task ReplaceMonitorAsync(FileMonitor? replacement)
    {
        var previous = monitor;
        monitor = replacement;
        OnChanged(nameof(MonitorActive));
        OnChanged(nameof(ProtectionBadge));
        if (previous is not null)
            await previous.DisposeAsync();
    }

    private async Task SaveAndApplyAsync(SentinelSettings updated, CancellationToken ct)
    {
        var replacement = CreateMonitor(updated);
        var startupChanged = updated.StartWithWindows != settings.StartWithWindows;
        var previousStartup = settings.StartWithWindows;
        try
        {
            if (startupChanged)
                SetWindowsStartup(updated.StartWithWindows);
            try { await store.SaveSettingsAsync(updated, ct); }
            catch
            {
                if (startupChanged)
                    SetWindowsStartup(previousStartup);
                throw;
            }
        }
        catch
        {
            if (replacement is not null)
                await replacement.DisposeAsync();
            throw;
        }
        settings = updated;
        ConfigureEngine();
        await ReplaceMonitorAsync(replacement);
    }

    private async ValueTask OnMonitoredFileAsync(FileResult file, CancellationToken ct)
    {
        await store.RecordFindingAsync(null, file, ct);
        await dispatcher.InvokeAsync(async () =>
        {
            if (disposed)
                return;
            if (DateTimeOffset.UtcNow >= refreshFindingsAfter)
            {
                refreshFindingsAfter = DateTimeOffset.UtcNow.AddSeconds(2);
                await RefreshFindingsAsync(lifetime.Token);
            }
            if (settings.Notifications && (file.Verdict == Verdict.Malware ||
                (!settings.GamingMode && file.Verdict == Verdict.HighRisk)))
            {
                StatusText = $"Monitor · {Path.GetFileName(file.Path)} requiere revisión.";
                if (!settings.GamingMode)
                    System.Media.SystemSounds.Exclamation.Play();
            }
        }, System.Windows.Threading.DispatcherPriority.Background, ct).Task.Unwrap();
    }

    private async Task ToggleMonitorAsync(CancellationToken ct)
    {
        var updated = settings with { MonitorEnabled = !MonitorActive };
        await SaveAndApplyAsync(updated, ct);
        MonitorEnabled = updated.MonitorEnabled;
        StatusText = MonitorActive ? "Monitor activo en las carpetas configuradas." : "Monitor detenido.";
    }

    private async Task MaintainAsync(CancellationToken ct)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
            while (await timer.WaitForNextTickAsync(ct))
            {
                if (working || settings.GamingMode)
                    continue;
                var now = DateTimeOffset.UtcNow;
                if (settings.ScheduledScanHours > 0 && now >= scheduledRetryAfter &&
                    now - lastSchedule >= TimeSpan.FromHours(settings.ScheduledScanHours))
                {
                    scheduledRetryAfter = now.AddMinutes(15);
                    StartOperation(token => ScanAsync(ScanKind.Quick, QuickRoots(), token, navigate: false));
                }
                else if (settings.AutoUpdate && settings.FreshClam is not null && settings.ClamScan is not null &&
                    now >= automaticUpdateAfter &&
                    now - (Updates.FirstOrDefault(item => item.Source == "ClamAV")?.UpdatedAt ?? DateTimeOffset.MinValue)
                        >= TimeSpan.FromDays(1))
                {
                    automaticUpdateAfter = now.AddHours(1);
                    StartOperation(UpdateClamAsync);
                }
                if (now >= refreshFindingsAfter && MonitorActive && !working)
                {
                    try { await RefreshFindingsAsync(ct); }
                    catch (Exception error) when (error is not OperationCanceledException) { StatusText = error.Message; }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    private async Task UpdateClamAsync(CancellationToken ct)
    {
        if (settings.FreshClam is not { } freshClam || settings.ClamScan is not { } clamScan)
            throw new InvalidOperationException("Guarda las rutas de FreshClam y ClamScan en Configuración.");
        StatusText = "Descargando y verificando las firmas de ClamAV…";
        var result = await EngineUpdates.UpdateClamAsync(freshClam, clamScan, Path.Combine(dataDirectory, "ClamAV"), ct);
        var updated = settings with { ClamDatabase = result.Path };
        await store.SaveSettingsAndRecordUpdateAsync(updated, new UpdateRecord("ClamAV", result.Version, result.Updated), ct);
        settings = updated;
        ClamDatabasePath = result.Path;
        await ReloadDetectionAsync(ct);
        StatusText = "Base ClamAV verificada y activada.";
    }

    private async Task ImportYaraAsync(CancellationToken ct)
    {
        if (settings.Yara is not { } yara)
            throw new InvalidOperationException("Guarda la ruta del ejecutable de YARA en Configuración.");
        var source = new OpenFileDialog { Title = "Selecciona reglas YARA de una fuente confiable",
            Filter = "Reglas YARA|*.yar;*.yara" };
        if (source.ShowDialog(Application.Current.MainWindow) != true)
            return;
        var checksum = new OpenFileDialog { Title = "Selecciona el SHA-256 publicado por la fuente",
            Filter = "Suma SHA-256|*.sha256;*.txt|Todos los archivos|*.*" };
        if (checksum.ShowDialog(Application.Current.MainWindow) != true)
            return;
        if (new FileInfo(checksum.FileName).Length > 4096)
            throw new InvalidDataException("El archivo de suma SHA-256 es demasiado grande.");
        var expected = (await File.ReadAllTextAsync(checksum.FileName, ct))
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (expected is null || expected.Length != 64 || !expected.All(Uri.IsHexDigit))
            throw new InvalidDataException("El archivo de suma debe comenzar con 64 caracteres hexadecimales.");
        var result = await EngineUpdates.ImportYaraAsync(yara, source.FileName, expected, Path.Combine(dataDirectory, "YARA"), ct);
        var updated = settings with { YaraRules = result.Path };
        await store.SaveSettingsAndRecordUpdateAsync(updated, new UpdateRecord("YARA", result.Version, result.Updated), ct);
        settings = updated;
        await ReloadDetectionAsync(ct);
        StatusText = "Reglas YARA verificadas y activadas.";
    }

    private async Task ImportSignaturesAsync(CancellationToken ct)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Selecciona un catálogo SHA-256 de una fuente confiable",
            Filter = "Catálogo tabulado|*.tsv;*.txt"
        };
        if (dialog.ShowDialog(Application.Current.MainWindow) != true ||
            !Confirm("Importar catálogo de firmas", "Cada hash del catálogo se tratará como evidencia de malware. Confirma que has verificado su procedencia."))
            return;
        using var stream = File.OpenRead(dialog.FileName);
        if (stream.Length > 32 * 1024 * 1024)
            throw new InvalidDataException("El catálogo supera el máximo de 32 MB.");
        var version = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct));
        stream.Position = 0;
        using var reader = new StreamReader(stream);
        var signatures = new List<SignatureEntry>();
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#')) continue;
            var columns = line.Split('\t', 2, StringSplitOptions.TrimEntries);
            if (columns.Length != 2 || columns[0].Length != 64 || !columns[0].All(Uri.IsHexDigit) ||
                columns[1].Length is < 1 or > 256)
                throw new InvalidDataException($"Entrada SHA-256 no válida después de {signatures.Count:N0} firmas.");
            signatures.Add(new SignatureEntry(columns[0].ToUpperInvariant(), columns[1]));
        }
        if (signatures.Count == 0)
            throw new InvalidDataException("El catálogo no contiene firmas.");
        await store.ImportSignaturesAsync(signatures, version, ct);
        await ReloadDetectionAsync(ct);
        StatusText = $"{signatures.Count:N0} firmas SHA-256 importadas.";
    }

    private async Task ReloadDetectionAsync(CancellationToken ct)
    {
        ConfigureEngine();
        await ConfigureMonitorAsync();
        await RefreshEngineDataAsync(ct);
    }
}

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using SentinelSecurity.Core;
using SentinelSecurity.Engine;
using SentinelSecurity.Infrastructure;
using SentinelSecurity.Monitoring;

namespace SentinelSecurity.UI;

public sealed partial class ShellViewModel : INotifyPropertyChanged, IAsyncDisposable
{
    private readonly SqliteStore store;
    private readonly ScanEngine engine;
    private readonly QuarantineService quarantine;
    private readonly string dataDirectory;
    private readonly Dispatcher dispatcher;
    private readonly CancellationTokenSource lifetime = new();
    private SentinelSettings settings = new();
    private FileMonitor? monitor;
    private Task? runningOperation;
    private Task? maintenance;
    private CancellationTokenSource? scanCancellation;
    private ScanControl? scanControl;
    private DateTimeOffset refreshFindingsAfter;
    private bool disposed;
    private int pageIndex;
    private bool working;
    private string statusText = "Inicializando…";
    private string progressText = "Listo para analizar.";
    private string currentFile = "";
    private double progressPercent;
    private bool progressIndeterminate;
    private string processFilter = "";
    private FileResult? selectedFinding;
    private QuarantineItem? selectedQuarantine;
    private ProcessItem? selectedProcess;

    internal ShellViewModel(SqliteStore store, ScanEngine engine, QuarantineService quarantine,
        string dataDirectory, Dispatcher dispatcher)
    {
        this.store = store;
        this.engine = engine;
        this.quarantine = quarantine;
        this.dataDirectory = dataDirectory;
        this.dispatcher = dispatcher;
        ProcessesView = CollectionViewSource.GetDefaultView(Processes);
        ProcessesView.Filter = entry => entry is ProcessItem item &&
            (item.Name.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase) ||
             item.Id.ToString().Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase) ||
             (item.Path?.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase) ?? false) ||
             item.Publisher.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase) ||
             item.Signature.Contains(ProcessFilter, StringComparison.OrdinalIgnoreCase));

        NavigateCommand = new UiCommand(value =>
        {
            if (int.TryParse(value?.ToString(), out var page) && page is >= 0 and <= 9)
                PageIndex = page;
        });
        QuickCommand = Operation(ct => ScanAsync(ScanKind.Quick, QuickRoots(), ct));
        FullCommand = Operation(ct => PickScanAsync(ScanKind.Full, directory: true, ct));
        CustomFileCommand = Operation(ct => PickScanAsync(ScanKind.Custom, directory: false, ct));
        CustomFolderCommand = Operation(ct => PickScanAsync(ScanKind.Custom, directory: true, ct));
        PauseCommand = new UiCommand(_ => TogglePause(), () => ScanBusy);
        CancelCommand = new UiCommand(_ => scanCancellation?.Cancel(), () => ScanBusy);
        ToggleMonitorCommand = Operation(ToggleMonitorAsync);
        RefreshProcessesCommand = Operation(RefreshProcessesAsync);
        ScanProcessCommand = Operation(ScanProcessAsync, () => SelectedProcess?.Path is not null);
        AuditCommand = Operation(RefreshAuditAsync);
        IsolateCommand = Operation(IsolateAsync, () => SelectedFinding is { Sha256: not null,
            Verdict: Verdict.Suspicious or Verdict.HighRisk or Verdict.Malware } file && File.Exists(file.Path));
        RestoreCommand = Operation(RestoreAsync, () => SelectedQuarantine is not null);
        DeleteCommand = Operation(DeleteAsync, () => SelectedQuarantine is not null);
        VerifyCommand = Operation(VerifyAsync, () => SelectedQuarantine is not null);
        RefreshEnginesCommand = Operation(RefreshEnginesAsync);
        UpdateClamCommand = Operation(UpdateClamAsync);
        ImportYaraCommand = Operation(ImportYaraAsync);
        ImportSignaturesCommand = Operation(ImportSignaturesAsync);
        ConfigureEnginesCommand = Operation(RunEngineSetupAsync);
        CancelSetupCommand = new UiCommand(_ => setupCancellation?.Cancel(), () => SetupRunning);
        SaveSettingsCommand = Operation(SaveSettingsAsync);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public int PageIndex { get => pageIndex; set => Set(ref pageIndex, value); }
    public string StatusText { get => statusText; private set => Set(ref statusText, value); }
    public string ProgressText { get => progressText; private set => Set(ref progressText, value); }
    public string CurrentFile { get => currentFile; private set => Set(ref currentFile, value); }
    public double ProgressPercent { get => progressPercent; private set => Set(ref progressPercent, value); }
    public bool ProgressIndeterminate { get => progressIndeterminate; private set => Set(ref progressIndeterminate, value); }
    public bool ScanBusy => scanControl is not null;
    public string PauseText => scanControl?.IsPaused == true ? "Continuar" : "Pausar";
    public bool MonitorActive => monitor?.IsActive == true;
    public bool HasActiveThreats => Findings.Any(file => file.Verdict == Verdict.Malware && File.Exists(file.Path));
    public string ProtectionBadge => MonitorActive ? "Monitor activo" :
        monitor?.IsDegraded == true ? "Monitor degradado" : "Monitor inactivo";
    public string SecurityTitle => HasActiveThreats ? "Amenazas identificadas" : "Estado de seguridad";
    public string MachineLearningText => "ML.NET pendiente de un modelo entrenado y validado.";
    public string LastScanText => Scans.FirstOrDefault(scan => scan.Kind != ScanKind.Process) switch
    {
        null => "Sin análisis finalizados.",
        { Canceled: true } scan => $"Último análisis cancelado · {scan.Examined:N0} examinados",
        { Threats: > 0 } scan => $"Último análisis · {scan.Threats:N0} hallazgos · {scan.Skipped:N0} omitidos",
        { Skipped: > 0 } scan => $"Sin hallazgos en archivos examinados · {scan.Skipped:N0} omitidos",
        var scan => $"Sin hallazgos en el último análisis · {scan.Examined:N0} examinados"
    };
    public string EngineText => EngineStatuses.Count == 0 ? "Verificando motores…" :
        string.Join("   ·   ", EngineStatuses.Select(status => $"{status.Name} {(status.Available ? "disponible" : "no disponible")}"));
    public string LastUpdateText => Updates.FirstOrDefault() is { } update
        ? $"Última actualización · {update.Source} · {update.UpdatedAt.ToLocalTime():g}"
        : "Sin actualizaciones registradas.";

    public ObservableCollection<ScanSummary> Scans { get; } = [];
    public ObservableCollection<FileResult> Findings { get; } = [];
    public ObservableCollection<QuarantineItem> QuarantineItems { get; } = [];
    public ObservableCollection<ProcessItem> Processes { get; } = [];
    public ICollectionView ProcessesView { get; }
    public ObservableCollection<AuditItem> AuditItems { get; } = [];
    public ObservableCollection<UpdateRecord> Updates { get; } = [];
    public ObservableCollection<EngineStatus> EngineStatuses { get; } = [];
    public FileResult? SelectedFinding { get => selectedFinding; set => Select(ref selectedFinding, value); }
    public QuarantineItem? SelectedQuarantine { get => selectedQuarantine; set => Select(ref selectedQuarantine, value); }
    public ProcessItem? SelectedProcess { get => selectedProcess; set => Select(ref selectedProcess, value); }
    public string ProcessFilter
    {
        get => processFilter;
        set { if (Set(ref processFilter, value ?? "")) ProcessesView.Refresh(); }
    }

    public ICommand NavigateCommand { get; }
    public ICommand QuickCommand { get; }
    public ICommand FullCommand { get; }
    public ICommand CustomFileCommand { get; }
    public ICommand CustomFolderCommand { get; }
    public ICommand PauseCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ToggleMonitorCommand { get; }
    public ICommand RefreshProcessesCommand { get; }
    public ICommand ScanProcessCommand { get; }
    public ICommand AuditCommand { get; }
    public ICommand IsolateCommand { get; }
    public ICommand RestoreCommand { get; }
    public ICommand DeleteCommand { get; }
    public ICommand VerifyCommand { get; }
    public ICommand RefreshEnginesCommand { get; }
    public ICommand UpdateClamCommand { get; }
    public ICommand ImportYaraCommand { get; }
    public ICommand ImportSignaturesCommand { get; }
    public ICommand SaveSettingsCommand { get; }
    public ICommand ConfigureEnginesCommand { get; }
    public ICommand CancelSetupCommand { get; }

    internal async Task InitializeAsync()
    {
        working = true;
        try
        {
            var ct = lifetime.Token;
            settings = await store.LoadSettingsAsync(ct);
            ApplySettingsToEditor();
            ConfigureEngine();
            await RefreshHistoryAsync(ct);
            if (Scans.FirstOrDefault(scan => scan.Kind == ScanKind.Quick && !scan.Canceled) is { } lastQuick)
                lastSchedule = lastQuick.Started + lastQuick.Elapsed;
            await RefreshFindingsAsync(ct);
            if (settings.MonitorEnabled)
            {
                try { await ConfigureMonitorAsync(); }
                catch (IOException error) { StatusText = error.Message; }
            }
            await RefreshEngineDataAsync(ct);
            if (StatusText == "Inicializando…")
                StatusText = "Listo.";
            maintenance = MaintainAsync(ct);
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        finally
        {
            working = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private ICommand Operation(Func<CancellationToken, Task> action, Func<bool>? enabled = null) =>
        new UiCommand(_ => StartOperation(action), () => !working && !disposed && (enabled?.Invoke() ?? true));

    private void StartOperation(Func<CancellationToken, Task> action)
    {
        if (working || disposed)
            return;
        working = true;
        CommandManager.InvalidateRequerySuggested();
        runningOperation = RunOperationAsync(action);
    }

    private async Task RunOperationAsync(Func<CancellationToken, Task> action)
    {
        try { await action(lifetime.Token); }
        catch (OperationCanceledException) { StatusText = "Operación cancelada."; }
        catch (Exception error)
        {
            StatusText = error.Message;
            try { await store.LogAsync("Operación", error.GetType().Name + " · " + error.Message, lifetime.Token); }
            catch (Exception logError) { System.Diagnostics.Trace.TraceError(logError.ToString()); }
        }
        finally
        {
            working = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private async Task RefreshHistoryAsync(CancellationToken ct)
    {
        Replace(Scans, await store.GetScansAsync(ct));
        OnChanged(nameof(LastScanText));
    }

    private async Task RefreshFindingsAsync(CancellationToken ct)
    {
        var records = await store.GetFindingsAsync(ct);
        var isolated = await store.GetQuarantineAsync(ct);
        var paths = isolated.Select(item => (item.OriginalPath.ToUpperInvariant(), item.Sha256.ToUpperInvariant())).ToHashSet();
        Replace(QuarantineItems, isolated);
        Replace(Findings, records.Where(item => item.Sha256 is null ||
            !paths.Contains((item.Path.ToUpperInvariant(), item.Sha256.ToUpperInvariant()))));
        OnChanged(nameof(HasActiveThreats));
        OnChanged(nameof(SecurityTitle));
    }

    private async Task RefreshEngineDataAsync(CancellationToken ct)
    {
        Replace(EngineStatuses, await Task.Run(() => engine.GetStatusAsync(ct), ct));
        Replace(Updates, await store.GetUpdatesAsync(ct));
        OnChanged(nameof(EngineText));
        OnChanged(nameof(LastUpdateText));
        OnChanged(nameof(ShowEngineSetup));
    }

    private async Task RefreshEnginesAsync(CancellationToken ct)
    {
        await RefreshEngineDataAsync(ct);
        StatusText = "Disponibilidad de motores actualizada.";
    }

    private async Task RefreshProcessesAsync(CancellationToken ct)
    {
        StatusText = "Consultando procesos activos…";
        Replace(Processes, await Task.Run(() => ProcessInventory.LoadAsync(ct), ct));
        StatusText = $"{Processes.Count:N0} procesos observados.";
    }

    private async Task RefreshAuditAsync(CancellationToken ct)
    {
        StatusText = "Consultando la configuración de Windows…";
        Replace(AuditItems, await WindowsAudit.ReadAsync(ct));
        StatusText = $"{AuditItems.Count:N0} resultados de auditoría.";
    }

    private void TogglePause()
    {
        if (scanControl is not { } control)
            return;
        if (control.IsPaused)
            control.Resume();
        else
            control.Pause();
        OnChanged(nameof(PauseText));
    }

    private static void Replace<T>(ObservableCollection<T> collection, IEnumerable<T> items)
    {
        collection.Clear();
        foreach (var item in items)
            collection.Add(item);
    }

    private void Select<T>(ref T storage, T value, [CallerMemberName] string? name = null)
    {
        if (Set(ref storage, value, name))
            CommandManager.InvalidateRequerySuggested();
    }

    private bool Set<T>(ref T storage, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(storage, value))
            return false;
        storage = value;
        OnChanged(name);
        return true;
    }

    private void OnChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;
        await lifetime.CancelAsync();
        if (runningOperation is not null)
            await runningOperation;
        if (maintenance is not null)
            await maintenance;
        if (monitor is not null)
            await monitor.DisposeAsync();
        lifetime.Dispose();
    }
}

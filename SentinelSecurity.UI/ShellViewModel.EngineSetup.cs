using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Input;
using SentinelSecurity.Core;
using SentinelSecurity.Engine;

namespace SentinelSecurity.UI;

public sealed record EngineSetupStep(string Name, string Status, string Detail);

public sealed partial class ShellViewModel
{
    private static readonly string[] SetupNames = ["ClamAV", "Firmas de ClamAV", "Firmas SHA-256", "YARA"];
    private readonly OfficialToolInstaller toolInstaller = new();
    private readonly TrustedYaraRules trustedYaraRules = new();
    private CancellationTokenSource? setupCancellation;
    private int setupPhase = -1;
    private double setupPercent;
    private bool setupIndeterminate;
    private string setupStatus = "Configura los motores desde sus fuentes verificadas.";

    public ObservableCollection<EngineSetupStep> SetupSteps { get; } = new(SetupNames.Select(
        name => new EngineSetupStep(name, "Pendiente", "")));
    public bool ShowEngineSetup => EngineStatuses.Any(status => !status.Available);
    public bool SetupRunning => setupCancellation is not null;
    public double SetupPercent { get => setupPercent; private set => Set(ref setupPercent, value); }
    public bool SetupIndeterminate { get => setupIndeterminate; private set => Set(ref setupIndeterminate, value); }
    public string SetupStatus { get => setupStatus; private set => Set(ref setupStatus, value); }
    private string ToolsDirectory => Path.Combine(dataDirectory, "tools");

    private async Task RunEngineSetupAsync(CancellationToken ct)
    {
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = cancel.Token;
        setupCancellation = cancel;
        PageIndex = 8;
        SetupPercent = 0;
        for (var index = 0; index < SetupSteps.Count; index++)
            SetupSteps[index] = new EngineSetupStep(SetupNames[index], "Pendiente", "");
        OnChanged(nameof(SetupRunning));
        CommandManager.InvalidateRequerySuggested();

        ClamToolInstallation? clam = null;
        EngineUpdateResult? clamDatabase = null;
        try
        {
            var toolsReady = await SetupStageAsync(0, async () =>
            {
                clam = await ProvisionClamToolsAsync(token);
                return $"ClamAV {clam.Version} verificado en el equipo.";
            }, token);
            if (toolsReady && clam is not null)
            {
                var installed = clam;
                var databaseReady = await SetupStageAsync(1, async () =>
                {
                    SetupStatus = "FreshClam está comprobando y descargando las bases oficiales. Puede tardar varios minutos.";
                    clamDatabase = await RefreshClamDatabaseAsync(installed.ClamScan, installed.FreshClam, token);
                    return $"Base oficial comprobada mediante un análisis real · {clamDatabase.Version}.";
                }, token);

                if (!databaseReady && settings.ClamDatabase is { } previousDatabase &&
                    Updates.FirstOrDefault(item => item.Source == "ClamAV") is { } previousUpdate)
                    clamDatabase = new EngineUpdateResult(previousDatabase, previousUpdate.Version, previousUpdate.UpdatedAt);

                if (clamDatabase is not null)
                {
                    var database = clamDatabase;
                    await SetupStageAsync(2, () => ImportClamSha256Async(installed.SigTool, database, token), token);
                }
                else
                {
                    SetupSteps[2] = new EngineSetupStep(SetupNames[2], "Pendiente", "Requiere bases oficiales verificadas de ClamAV.");
                }
            }
            else
            {
                SetupSteps[1] = new EngineSetupStep(SetupNames[1], "Pendiente", "Requiere el ejecutable verificado de FreshClam.");
                SetupSteps[2] = new EngineSetupStep(SetupNames[2], "Pendiente", "Requiere bases oficiales verificadas de ClamAV.");
            }

            await SetupStageAsync(3, ConfigureYaraAsync, token);
            SetupStatus = SetupSteps.All(step => step.Status == "Verificado")
                ? "Los tres motores se configuraron y comprobaron."
                : "Configuración parcial. Revisa el detalle de los pasos pendientes y vuelve a intentarlo.";
            StatusText = SetupStatus;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            if (setupPhase is >= 0 and < 4)
                SetupSteps[setupPhase] = new EngineSetupStep(SetupNames[setupPhase], "Cancelado", "Se conservaron los motores ya verificados.");
            SetupStatus = "Configuración cancelada. Puedes retomarla desde Actualizaciones.";
            StatusText = SetupStatus;
        }
        finally
        {
            setupPhase = -1;
            SetupIndeterminate = false;
            try
            {
                if (!ct.IsCancellationRequested)
                    await RefreshEngineDataAsync(ct);
            }
            finally
            {
                setupCancellation = null;
                OnChanged(nameof(SetupRunning));
                CommandManager.InvalidateRequerySuggested();
            }
        }

        async Task<string> ConfigureYaraAsync()
        {
            SetupStatus = "Buscando una instalación utilizable de YARA…";
            var yara = await toolInstaller.FindYaraAsync(settings.Yara, ToolsDirectory, token);
            yara ??= await toolInstaller.InstallYaraAsync(ToolsDirectory, ToolProgress(3, 0, 50), token);
            var configured = settings with { Yara = yara.YaraPath };
            if (configured.YaraRules is not null &&
                (await engine.CheckYaraAsync(DetectorConfiguration(configured), token)).Available)
            {
                if (configured.Yara != settings.Yara)
                    await store.SaveSettingsAsync(configured, token);
                settings = configured;
                YaraPath = yara.YaraPath;
                ConfigureEngine();
                return $"YARA {yara.Version} comprobó las reglas existentes.";
            }

            SetupStatus = "Descargando las reglas verificadas de ReversingLabs…";
            SetupIndeterminate = false;
            var rulesProgress = new Progress<(int Completed, int Total)>(progress =>
            {
                if (setupPhase == 3 && !token.IsCancellationRequested)
                {
                    SetupIndeterminate = false;
                    SetupPercent = (3 + 0.5 + 0.4 * progress.Completed / progress.Total) * 25;
                }
            });
            var rules = await trustedYaraRules.ImportAsync(yara.YaraPath, Path.Combine(dataDirectory, "YARA"), rulesProgress, token);
            configured = configured with { YaraRules = rules.Path };
            var valid = await engine.CheckYaraAsync(DetectorConfiguration(configured), token);
            if (!valid.Available)
                throw new IOException(valid.Detail);
            await store.SaveSettingsAndRecordUpdateAsync(configured, new UpdateRecord("YARA", rules.Version, rules.Updated), token);
            settings = configured;
            YaraPath = yara.YaraPath;
            ConfigureEngine();
            monitor?.RecheckWithUpdatedDetectors();
            return $"YARA {yara.Version} analizó un archivo de prueba con las reglas de ReversingLabs.";
        }
    }

    private async Task<bool> SetupStageAsync(int phase, Func<Task<string>> operation, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        setupPhase = phase;
        SetupPercent = 25 * phase;
        SetupIndeterminate = true;
        SetupStatus = $"Configurando {SetupNames[phase]}…";
        SetupSteps[phase] = new EngineSetupStep(SetupNames[phase], "En curso", "");
        try
        {
            var detail = await operation();
            SetupSteps[phase] = new EngineSetupStep(SetupNames[phase], "Verificado", detail);
            return true;
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            SetupSteps[phase] = new EngineSetupStep(SetupNames[phase], "Error", error.Message);
            try { await store.LogAsync("Asistente de motores", $"{SetupNames[phase]} · {error.Message}", ct); }
            catch (Exception logError) when (logError is not OperationCanceledException)
            {
                System.Diagnostics.Trace.TraceError(logError.ToString());
            }
            return false;
        }
        finally
        {
            if (!ct.IsCancellationRequested)
                SetupPercent = 25 * (phase + 1);
            SetupIndeterminate = false;
        }
    }

    private IProgress<ToolInstallProgress> ToolProgress(int phase, int from, int to) =>
        new Progress<ToolInstallProgress>(value =>
        {
            if (setupPhase != phase || setupCancellation?.IsCancellationRequested != false)
                return;
            SetupStatus = value.Message;
            SetupIndeterminate = value.TotalBytes is not > 0 || value.BytesDownloaded is null;
            if (!SetupIndeterminate)
                SetupPercent = 25 * (phase + (from + (to - from) *
                    Math.Clamp(value.BytesDownloaded!.Value / (double)value.TotalBytes!.Value, 0, 1)) / 100);
        });

    private async Task<ClamToolInstallation> ProvisionClamToolsAsync(CancellationToken ct)
    {
        if (settings.PortableClam is { } cached && await toolInstaller.VerifyClamAvAsync(
            new InstalledClamAv(cached.ClamScan, cached.FreshClam, cached.SigTool, cached.Version), ToolsDirectory, ct))
            return cached;
        var fetched = await toolInstaller.InstallClamAvAsync(ToolsDirectory, ToolProgress(0, 0, 100), ct);
        var installed = new ClamToolInstallation(fetched.ClamScanPath, fetched.FreshClamPath, fetched.SigToolPath, fetched.Version);
        var saved = settings with { PortableClam = installed };
        await store.SaveSettingsAsync(saved, ct);
        settings = saved;
        return installed;
    }

    private async Task<EngineUpdateResult> RefreshClamDatabaseAsync(string clam, string freshClam, CancellationToken ct)
    {
        var result = await EngineUpdates.UpdateClamAsync(freshClam, clam, Path.Combine(dataDirectory, "ClamAV"),
            settings.ClamDatabase, ct);
        var databaseChanged = !string.Equals(settings.ClamDatabase, result.Path, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(settings.ClamScan, clam, StringComparison.OrdinalIgnoreCase);
        var updated = settings with { ClamDatabase = result.Path, ClamScan = clam, FreshClam = freshClam };
        await store.SaveSettingsAndRecordUpdateAsync(updated, new UpdateRecord("ClamAV", result.Version, result.Updated), ct);
        settings = updated;
        ClamScanPath = clam;
        FreshClamPath = freshClam;
        ClamDatabasePath = result.Path;
        ConfigureEngine();
        if (databaseChanged)
            monitor?.RecheckWithUpdatedDetectors();
        return result;
    }

    private async Task<string> ImportClamSha256Async(string sigTool, EngineUpdateResult database, CancellationToken ct)
    {
        var signatures = await OfficialSha256Catalog.ReadAsync(sigTool, database.Path, ct);
        await store.ImportOfficialSignaturesAsync(signatures, $"Cisco Talos ClamAV · {database.Version}", ct);
        var status = await engine.CheckSignaturesAsync(ct);
        if (!status.Available)
            throw new IOException(status.Detail);
        monitor?.RecheckWithUpdatedDetectors();
        return $"{signatures.Count:N0} firmas oficiales importadas y consultables en SQLite.";
    }
}

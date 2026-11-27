using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SentinelSecurity.Core;
using SentinelSecurity.Monitoring;

namespace SentinelSecurity.UI;

public sealed partial class ShellViewModel
{
    private async Task PickScanAsync(ScanKind kind, bool directory, CancellationToken ct)
    {
        string[] roots;
        if (directory)
        {
            var dialog = new OpenFolderDialog
            {
                Title = kind == ScanKind.Full ? "Selecciona las unidades del análisis completo" : "Selecciona carpetas",
                Multiselect = true
            };
            if (dialog.ShowDialog(Application.Current.MainWindow) != true)
                return;
            roots = dialog.FolderNames;
            if (kind == ScanKind.Full && roots.Any(root => !string.Equals(
                Path.TrimEndingDirectorySeparator(root), Path.TrimEndingDirectorySeparator(Path.GetPathRoot(root) ?? ""),
                StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Selecciona la raíz de cada unidad (por ejemplo, C:\\). Usa el análisis personalizado para carpetas.");
        }
        else
        {
            var dialog = new OpenFileDialog { Title = "Selecciona archivos para analizar", Multiselect = true };
            if (dialog.ShowDialog(Application.Current.MainWindow) != true)
                return;
            roots = dialog.FileNames;
        }
        await ScanAsync(kind, roots, ct);
    }

    private string[] QuickRoots()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads = ReadDownloadsFolder() ?? Path.Combine(profile, "Downloads");
        return new[]
        {
            downloads, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        }.Where(path => PathSafety.IsLocalWithoutLinks(path, directory: true))
         .Distinct(StringComparer.OrdinalIgnoreCase)
         .ToArray();
    }

    private static string? ReadDownloadsFolder()
    {
        using var folders = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders");
        return folders?.GetValue("{374DE290-123F-4565-9164-39C4925E467B}") as string;
    }

    private ScanOptions Options(SentinelSettings candidate)
    {
        var workers = candidate.GamingMode ? 1 : candidate.Concurrency;
        return new ScanOptions(workers, candidate.MaxFileMegabytes * 1048576L, [.. candidate.Exclusions, dataDirectory]);
    }

    private async Task<FileResult?> ScanAsync(ScanKind kind, string[] roots, CancellationToken ct, bool navigate = true)
    {
        if (roots.Length == 0)
            throw new IOException("No hay ubicaciones disponibles para analizar.");
        if (navigate)
            PageIndex = 1;
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var control = new ScanControl();
        scanControl = control;
        scanCancellation = cancel;
        OnChanged(nameof(ScanBusy));
        OnChanged(nameof(PauseText));
        CommandManager.InvalidateRequerySuggested();
        ProgressIndeterminate = true;
        ProgressPercent = 0;
        CurrentFile = "";
        ProgressText = "Preparando el análisis…";
        StatusText = "Análisis en curso.";
        FileResult? singleResult = null;
        try
        {
            var progress = new Progress<ScanProgress>(report =>
            {
                if (scanControl != control)
                    return;
                ProgressIndeterminate = report.Total is null;
                if (report.Total is > 0)
                    ProgressPercent = Math.Clamp((report.Examined + report.Skipped) * 100d / report.Total.Value, 0, 100);
                CurrentFile = report.CurrentFile;
                var rate = report.Examined / Math.Max(1d, report.Elapsed.TotalSeconds);
                ProgressText = $"{report.Examined:N0} examinados · {report.Threats:N0} hallazgos · {report.Skipped:N0} omitidos · {report.Elapsed:hh\\:mm\\:ss} · {rate:N1} archivos/s";
            });
            var scanOptions = Options(settings);
            var summary = await Task.Run(() => engine.ScanAsync(kind, roots, scanOptions, control, progress,
                async (file, token) =>
                {
                    if (kind == ScanKind.Process)
                        singleResult = file;
                    if (file.Verdict != Verdict.Clean || file.Error is not null)
                        await store.RecordFindingAsync(control.Id, file, token);
                }, cancel.Token));
            await store.RecordScanAsync(summary, ct);
            if (summary.Kind == ScanKind.Quick && !summary.Canceled)
                lastSchedule = summary.Started + summary.Elapsed;
            ProgressIndeterminate = false;
            if (!summary.Canceled) ProgressPercent = 100;
            CurrentFile = "";
            ProgressText = $"{summary.Examined:N0} examinados · {summary.Threats:N0} hallazgos · {summary.Skipped:N0} omitidos · {summary.Elapsed:hh\\:mm\\:ss}";
            StatusText = summary.Canceled ? "Análisis cancelado." : "Análisis finalizado.";
            await RefreshHistoryAsync(ct);
            await RefreshFindingsAsync(ct);
            return singleResult;
        }
        finally
        {
            scanCancellation = null;
            scanControl = null;
            ProgressIndeterminate = false;
            OnChanged(nameof(ScanBusy));
            OnChanged(nameof(PauseText));
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private async Task ScanProcessAsync(CancellationToken ct)
    {
        if (SelectedProcess is not { Path: not null } process)
            return;
        var result = await ScanAsync(ScanKind.Process, [process.Path], ct);
        PageIndex = 5;
        var index = Processes.IndexOf(process);
        if (result is null || index < 0)
            return;
        var label = result.Verdict switch
        {
            Verdict.Clean => "Sin hallazgos",
            Verdict.Suspicious => "Sospechoso",
            Verdict.HighRisk => "Riesgo alto",
            Verdict.Malware => "Malware identificado",
            _ => "No analizado"
        };
        var updated = process with { Sha256 = result.Sha256, Result = label };
        Processes[index] = updated;
        SelectedProcess = updated;
    }

    private async Task IsolateAsync(CancellationToken ct)
    {
        if (SelectedFinding is not { } finding || !Confirm("Aislar archivo",
            $"Se retirará el archivo de su ubicación original y se cifrará en la cuarentena.\n\n{finding.Path}"))
            return;
        await quarantine.IsolateAsync(finding, ct);
        await RefreshFindingsAsync(ct);
        StatusText = "Archivo aislado. Puede revisar su integridad desde Cuarentena.";
    }

    private async Task RestoreAsync(CancellationToken ct)
    {
        if (SelectedQuarantine is not { } item || !Confirm("Restaurar archivo",
            $"El archivo volverá a su ubicación original y recuperará su acceso habitual.\n\n{item.OriginalPath}"))
            return;
        await quarantine.RestoreAsync(item.Id, ct);
        await RefreshFindingsAsync(ct);
        StatusText = "Archivo restaurado.";
    }

    private async Task DeleteAsync(CancellationToken ct)
    {
        if (SelectedQuarantine is not { } item || !Confirm("Eliminar permanentemente",
            $"Se eliminará la copia en cuarentena. Esta acción es irreversible.\n\n{item.OriginalPath}"))
            return;
        await quarantine.DeleteAsync(item.Id, ct);
        await RefreshFindingsAsync(ct);
        StatusText = "Copia en cuarentena eliminada.";
    }

    private async Task VerifyAsync(CancellationToken ct)
    {
        if (SelectedQuarantine is not { } item)
            return;
        StatusText = await quarantine.VerifyAsync(item.Id, ct)
            ? "Integridad verificada mediante SHA-256." : "No se pudo verificar la integridad de la copia.";
    }

    private static bool Confirm(string title, string message) =>
        MessageBox.Show(Application.Current.MainWindow, message, title, MessageBoxButton.YesNo,
            MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
}

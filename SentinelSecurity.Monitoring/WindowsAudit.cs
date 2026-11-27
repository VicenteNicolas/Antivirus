using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SentinelSecurity.Monitoring;

public sealed record AuditItem(string Category, string Name, string Status, string Detail);

public static class WindowsAudit
{
    public static async Task<IReadOnlyList<AuditItem>> ReadAsync(CancellationToken ct)
    {
        var executable = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!OperatingSystem.IsWindows() || !File.Exists(executable))
            throw new PlatformNotSupportedException("La auditoría requiere Windows PowerShell.");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(Query)) })
            start.ArgumentList.Add(argument);

        using var process = Process.Start(start) ?? throw new IOException("No se pudo iniciar la consulta de Windows.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(75));
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var error = process.StandardError.ReadToEndAsync(timeout.Token);
            await Task.WhenAll(process.WaitForExitAsync(timeout.Token), output, error);
            if (process.ExitCode != 0)
                throw new IOException("Windows no pudo completar la consulta de auditoría.");
            return JsonSerializer.Deserialize<AuditItem[]>(await output) ?? [];
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("La auditoría agotó su tiempo de espera.");
        }
        finally
        {
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
        }
    }

    private const string Query = """
        $ErrorActionPreference = 'Stop'
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $results = [Collections.Generic.List[object]]::new()
        $checkedSignatures = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        function Row($category,$name,$status,$detail) {
            $results.Add([pscustomobject]@{Category=[string]$category;Name=[string]$name;Status=[string]$status;Detail=[string]$detail})
        }
        function Check($category,$name,[scriptblock]$query) {
            try { & $query } catch { Row $category $name 'No disponible' $_.Exception.Message }
        }
        function Signature($label,$command) {
            $expanded = [Environment]::ExpandEnvironmentVariables([string]$command)
            if ($expanded -match '^\s*"([^"]+\.exe)"' -or $expanded -match '^\s*([A-Za-z]:\\[^"]*?\.exe)(?:\s|$)') {
                $target = $Matches[1]
                if ($target -notmatch '^[A-Za-z]:\\' -or $target.Substring(2).Contains(':')) { return }
                if ($checkedSignatures.Count -ge 80 -or !$checkedSignatures.Add($target)) { return }
                $drive = [IO.DriveInfo]::new($target.Substring(0,3))
                if ($drive.DriveType -notin 'Fixed','Removable') { return }
                $parent = $target
                while ($parent) {
                    $item = Get-Item -LiteralPath $parent -ErrorAction SilentlyContinue
                    if (!$item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return }
                    $parent = [IO.Path]::GetDirectoryName($parent)
                }
                $signature = Get-AuthenticodeSignature -LiteralPath $target -ErrorAction SilentlyContinue
                if (!$signature -or $signature.Status -ne 'Valid') {
                    Row Firma $label 'Revisar' "$target · $($signature.Status)"
                } elseif ($signature.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)') {
                    Row Firma $label 'Microsoft' $target
                } else {
                    Row Firma $label 'Tercero firmado' "$target · $($signature.SignerCertificate.Subject)"
                }
            }
        }
        Check Protección 'Microsoft Defender' {
            $d = Get-MpComputerStatus
            Row Protección 'Microsoft Defender' $(if ($d.RealTimeProtectionEnabled) {'Activo'} else {'Revisar'}) "Modo $($d.AMRunningMode) · Firmas $($d.AntivirusSignatureVersion)"
        }
        Check Protección Firewall {
            Get-NetFirewallProfile | ForEach-Object {
                Row Protección "Firewall $($_.Name)" $(if ($_.Enabled) {'Activo'} else {'Revisar'}) 'Perfil de Windows'
            }
        }
        Check Arranque 'Secure Boot' {
            $enabled = Confirm-SecureBootUEFI
            Row Arranque 'Secure Boot' $(if ($enabled) {'Activo'} else {'Revisar'}) 'Configuración UEFI'
        }
        Check Protección UAC {
            $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
            Row Protección UAC $(if ($uac -eq 1) {'Activo'} elseif ($uac -eq 0) {'Revisar'} else {'No disponible'}) 'Configuración EnableLUA'
        }
        Check Actualizaciones 'Windows Update' {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $count = [Math]::Min(10, $searcher.GetTotalHistoryCount())
            if ($count -eq 0) { Row Actualizaciones 'Windows Update' 'Sin historial' 'Historial local' }
            else {
                $searcher.QueryHistory(0,$count) | ForEach-Object {
                    Row Actualizaciones $_.Title $(if ($_.ResultCode -eq 2) {'Instalada'} else {"Resultado $($_.ResultCode)"}) $_.Date.ToString('s')
                }
            }
        }
        Check Inicio 'Programas de inicio' {
            Get-CimInstance Win32_StartupCommand | Select-Object -First 100 | ForEach-Object {
                Row Inicio $_.Name 'Configurado' "$($_.Location) · $($_.Command)"
                Signature $_.Name $_.Command
            }
        }
        $keys = @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')
        foreach ($key in $keys) {
            Check Registro $key {
                if (!(Test-Path -LiteralPath $key)) { return }
                $entry = Get-Item -LiteralPath $key
                foreach ($name in ($entry.GetValueNames() | Select-Object -First 40)) {
                    $command = $entry.GetValue($name)
                    Row Registro $name 'Configurado' "$key · $command"
                    Signature $name $command
                }
            }
        }
        Check Tareas 'Programador de tareas' {
            Get-ScheduledTask | Select-Object -First 300 | ForEach-Object {
                $origin = if ($_.TaskPath.StartsWith('\Microsoft\Windows\')) {'Ruta de Windows'} else {'Otra ruta'}
                Row Tareas $_.TaskName $_.State "$origin · $($_.TaskPath)"
                foreach ($action in $_.Actions) { if ($action.Execute) { Signature $_.TaskName ('"' + $action.Execute + '"') } }
            }
        }
        Check Servicios 'Servicios de Windows' {
            Get-CimInstance Win32_Service | Select-Object -First 500 | ForEach-Object {
                Row Servicios $_.DisplayName $_.State "$($_.StartMode) · $($_.PathName)"
                Signature $_.DisplayName $_.PathName
            }
        }
        Check Red 'Conexiones TCP' {
            Get-NetTCPConnection -State Established | Select-Object -First 300 | ForEach-Object {
                Row Red "TCP PID $($_.OwningProcess)" 'Establecida' "$($_.LocalAddress):$($_.LocalPort) → $($_.RemoteAddress):$($_.RemotePort)"
            }
        }
        Check Red 'Puertos UDP' {
            Get-NetUDPEndpoint | Select-Object -First 100 | ForEach-Object {
                Row Red "UDP PID $($_.OwningProcess)" 'Local' "$($_.LocalAddress):$($_.LocalPort)"
            }
        }
        ConvertTo-Json -InputObject @($results.ToArray()) -Depth 3 -Compress
        """;
}

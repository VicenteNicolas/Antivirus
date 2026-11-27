using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SentinelSecurity.Engine;

public sealed record InstalledClamAv(string ClamScanPath, string FreshClamPath, string SigToolPath, string Version);

public sealed record InstalledYara(string YaraPath, string Version);

public sealed record ToolInstallProgress(string Message, long? BytesDownloaded = null, long? TotalBytes = null);

public sealed class OfficialToolInstaller
{
    // Digests from the release asset pages of Cisco-Talos/clamav and VirusTotal/yara.
    private static readonly Package ClamAvPackage = new("ClamAV", "1.5.5",
        new("https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.5/clamav-1.5.5.win.x64.zip"),
        "90169F5E551010BFBD0208B50D9B2FA8988EF396CCCBD46B0CC8CAE03E22A4A4", 256, 1024);
    private static readonly Package YaraPackage = new("YARA", "4.6.0",
        new("https://github.com/VirusTotal/yara/releases/download/v4.6.0/yara-4.6.0-2443-win64.zip"),
        "5E7124F173ED442458429AC0F79A4DB2C024CC183C595737D477A7575D81E6DC", 12, 32);
    private const string KnownYaraExecutableSha256 = "6B4897B945F408080645EC06E2D2540F067A57A68D5E5830781CDC1D88FC41E2";
    private static readonly string[] YaraFileNames = ["yara64.exe", "yara.exe"];
    private static readonly TimeSpan ToolProbeTimeout = TimeSpan.FromSeconds(15);
    private static readonly HttpClient DefaultHttp = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(20),
        AutomaticDecompression = DecompressionMethods.None
    })
    {
        Timeout = Timeout.InfiniteTimeSpan
    };
    private readonly HttpClient http;

    public OfficialToolInstaller() : this(DefaultHttp) { }

    public OfficialToolInstaller(HttpClient http)
    {
        this.http = http ?? throw new ArgumentNullException(nameof(http));
    }

    public async Task<InstalledClamAv> InstallClamAvAsync(string toolsDirectory,
        IProgress<ToolInstallProgress>? progress, CancellationToken ct)
    {
        var paths = await InstallAsync(ClamAvPackage, toolsDirectory,
            ["clamscan.exe", "freshclam.exe", "sigtool.exe"], progress, ct).ConfigureAwait(false);
        return new InstalledClamAv(paths[0], paths[1], paths[2], ClamAvPackage.Version);
    }

    public async Task<bool> VerifyClamAvAsync(InstalledClamAv installed, string toolsDirectory, CancellationToken ct)
    {
        if (!string.Equals(installed.Version, ClamAvPackage.Version, StringComparison.Ordinal))
            return false;
        try
        {
            var root = Path.TrimEndingDirectorySeparator(ScanPath.Normalize(toolsDirectory)) + Path.DirectorySeparatorChar;
            foreach (var (path, name) in new[]
            {
                (installed.ClamScanPath, "clamscan.exe"), (installed.FreshClamPath, "freshclam.exe"),
                (installed.SigToolPath, "sigtool.exe")
            })
            {
                var full = ToolProcess.ValidateExecutable(path);
                if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(Path.GetFileName(full), name, StringComparison.OrdinalIgnoreCase))
                    return false;
                var result = await ProbeToolAsync(full, ct).ConfigureAwait(false);
                if (result.ExitCode != 0 || !MatchesPackageVersion(ClamAvPackage, FirstOutputLine(result)))
                    return false;
            }
            return true;
        }
        catch (Exception error) when (ScanPath.Expected(error) || error is Win32Exception or TimeoutException)
        {
            return false;
        }
    }

    public async Task<InstalledYara> InstallYaraAsync(string toolsDirectory,
        IProgress<ToolInstallProgress>? progress, CancellationToken ct)
    {
        var paths = await InstallAsync(YaraPackage, toolsDirectory, ["yara64.exe"], progress, ct)
            .ConfigureAwait(false);
        return new InstalledYara(paths[0], YaraPackage.Version);
    }

    public Task<InstalledYara?> FindYaraAsync(string? configuredPath, CancellationToken ct) =>
        FindYaraAsync(configuredPath, Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData), "SentinelSecurity", "tools"), ct);

    public async Task<InstalledYara?> FindYaraAsync(string? configuredPath, string toolsDirectory, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        // This path is an existing explicit user choice. Automatic discovery verifies
        // published bytes and isolates the binary before starting any process.
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            var version = await TryGetYaraVersionAsync(configuredPath, ct).ConfigureAwait(false);
            if (version is not null)
                return new InstalledYara(Path.GetFullPath(configuredPath), version);
        }

        foreach (var path in YaraSearchDirectories()
                     .Where(Path.IsPathFullyQualified)
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .Take(128)
                     .SelectMany(directory => YaraFileNames.Select(name => Path.Combine(directory, name))))
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(path))
                continue;

            FileStream? source = null;
            try
            {
                var executable = ToolProcess.ValidateExecutable(path);
                source = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read, 65536,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                if (source.Length > YaraPackage.MaxDownloadBytes)
                    continue;
                var digest = await SHA256.HashDataAsync(source, ct).ConfigureAwait(false);
                if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(KnownYaraExecutableSha256)))
                    continue;

                var root = PrepareDirectory(toolsDirectory);
                var staging = CreateStagingDirectory(root);
                try
                {
                    var copy = Path.Combine(staging, "yara64.exe");
                    source.Position = 0;
                    await using (var output = new FileStream(copy, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                        65536, FileOptions.Asynchronous | FileOptions.SequentialScan))
                        await source.CopyToAsync(output, ct).ConfigureAwait(false);
                    var version = await TryGetYaraVersionAsync(copy, ct).ConfigureAwait(false);
                    if (!string.Equals(version, YaraPackage.Version, StringComparison.Ordinal))
                        continue;
                    ct.ThrowIfCancellationRequested();
                    var destination = NewGenerationPath(root, YaraPackage);
                    Directory.Move(staging, destination);
                    return new InstalledYara(Path.Combine(destination, "yara64.exe"), version!);
                }
                finally
                {
                    RemoveStagingDirectory(root, staging);
                }
            }
            catch (Exception error) when (ScanPath.Expected(error))
            {
                // An unreadable candidate should never stop the search or fallback to the official ZIP.
            }
            finally
            {
                if (source is not null)
                    await source.DisposeAsync().ConfigureAwait(false);
            }
        }

        return null;
    }

    private async Task<string[]> InstallAsync(Package package, string toolsDirectory, string[] executableNames,
        IProgress<ToolInstallProgress>? progress, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.OSArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("Estos paquetes portátiles están destinados a Windows x64.");

        var root = PrepareDirectory(toolsDirectory);
        var staging = CreateStagingDirectory(root);
        var archive = Path.Combine(staging, "package.zip");
        var extracted = Path.Combine(staging, "files");
        try
        {
            progress?.Report(new($"Descargando {package.Name} {package.Version}…", 0));
            await DownloadAsync(package, archive, progress, ct).ConfigureAwait(false);
            progress?.Report(new($"Extrayendo el paquete verificado de {package.Name}…"));
            Directory.CreateDirectory(extracted);
            await SafeToolArchive.ExtractAsync(archive, extracted, package.MaxExpandedBytes, ct)
                .ConfigureAwait(false);

            progress?.Report(new($"Comprobando los ejecutables de {package.Name}…"));
            var paths = new string[executableNames.Length];
            for (var i = 0; i < executableNames.Length; i++)
            {
                ct.ThrowIfCancellationRequested();
                var name = executableNames[i];
                var matches = Directory.EnumerateFiles(extracted, name, SearchOption.AllDirectories).Take(2).ToArray();
                if (matches.Length != 1)
                    throw new IOException($"El paquete oficial de {package.Name} no contiene un único {name}.");
                var executable = ToolProcess.ValidateExecutable(matches[0]);
                var result = await ProbeToolAsync(executable, ct)
                    .ConfigureAwait(false);
                var versionText = FirstOutputLine(result);
                if (result.ExitCode != 0 || !MatchesPackageVersion(package, versionText))
                    throw new IOException($"{name} no pudo confirmar la versión esperada {package.Version}. " +
                        result.FirstError("Comprueba los permisos y las dependencias de Windows."));
                paths[i] = Path.GetRelativePath(extracted, executable);
            }

            ct.ThrowIfCancellationRequested();
            var destination = NewGenerationPath(root, package);
            Directory.Move(extracted, destination);
            return paths.Select(path => Path.Combine(destination, path)).ToArray();
        }
        finally
        {
            RemoveStagingDirectory(root, staging);
        }
    }

    private static async Task<ToolResult> ProbeToolAsync(string executable, CancellationToken ct)
    {
        if (!Path.GetFileName(executable).Equals("freshclam.exe", StringComparison.OrdinalIgnoreCase))
            return await ToolProcess.RunAsync(executable, ["--version"], ToolProbeTimeout, ct).ConfigureAwait(false);

        var config = Path.Combine(Path.GetDirectoryName(executable)!, $"probe-{Guid.NewGuid():N}.conf");
        try
        {
            await File.WriteAllTextAsync(config, "DatabaseMirror database.clamav.net\n", ct).ConfigureAwait(false);
            return await ToolProcess.RunAsync(executable, [$"--config-file={config}", "--version"], ToolProbeTimeout, ct)
                .ConfigureAwait(false);
        }
        finally
        {
            ExternalDetectors.DeleteTemporaryFile(config);
        }
    }

    private async Task DownloadAsync(Package package, string archive,
        IProgress<ToolInstallProgress>? progress, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromMinutes(8));
        try
        {
            var token = timeout.Token;
            using var response = await OpenOfficialDownloadAsync(package.DownloadUrl, token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                throw new IOException($"El servidor de {package.Name} respondió HTTP {(int)response.StatusCode}.");
            var total = response.Content.Headers.ContentLength;
            if (total is <= 0 || total > package.MaxDownloadBytes)
                throw new IOException($"El tamaño del paquete descargado de {package.Name} es inválido.");

            await using var input = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            await using var output = new FileStream(archive, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[131072];
            long bytes = 0;
            long lastReported = 0;
            progress?.Report(new($"Descargando {package.Name} {package.Version}…", 0, total));
            int read;
            while ((read = await input.ReadAsync(buffer, token).ConfigureAwait(false)) > 0)
            {
                bytes += read;
                if (bytes > package.MaxDownloadBytes || bytes > total)
                    throw new IOException($"El paquete de {package.Name} excede el tamaño permitido.");
                hash.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read), token).ConfigureAwait(false);
                if (bytes - lastReported >= 256 * 1024)
                {
                    lastReported = bytes;
                    progress?.Report(new($"Descargando {package.Name} {package.Version}…", bytes, total));
                }
            }

            progress?.Report(new($"Verificando SHA-256 de {package.Name}…", bytes, total));
            if (bytes == 0 || (total.HasValue && total.Value != bytes) ||
                !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(package.Sha256)))
                throw new IOException($"El paquete de {package.Name} no coincide con el SHA-256 oficial.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"La descarga de {package.Name} superó el tiempo de espera.");
        }
        catch (HttpRequestException error)
        {
            throw new IOException($"No se pudo conectar al servidor oficial de {package.Name}.", error);
        }
    }

    private async Task<HttpResponseMessage> OpenOfficialDownloadAsync(Uri uri, CancellationToken ct)
    {
        for (var redirects = 0; redirects <= 4; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.UserAgent.ParseAdd("SentinelSecurity/0.2");
            var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (response.RequestMessage?.RequestUri is { } effectiveUrl && !IsAllowedDownloadUri(effectiveUrl))
            {
                response.Dispose();
                throw new IOException("El servidor de descarga cambió a un origen no permitido.");
            }
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308))
                return response;
            using (response)
            {
                if (response.Headers.Location is not { } location ||
                    !Uri.TryCreate(uri, location, out var next) || !IsAllowedDownloadUri(next))
                    throw new IOException("El servidor de descarga indicó un origen no permitido.");
                uri = next;
            }
        }
        throw new IOException("El servidor de descarga generó demasiadas redirecciones.");
    }

    private static bool IsAllowedDownloadUri(Uri uri) =>
        uri.IsAbsoluteUri && uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
        uri.IdnHost is "github.com" or "release-assets.githubusercontent.com" or "objects.githubusercontent.com";

    private static string PrepareDirectory(string path)
    {
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("La ubicación de motores debe ser una ruta local absoluta.", nameof(path));
        var root = Path.TrimEndingDirectorySeparator(ScanPath.Normalize(path));
        var existing = root;
        while (!Directory.Exists(existing))
            existing = Path.GetDirectoryName(existing) ?? throw new IOException("La carpeta de motores no es válida.");
        ScanPath.CheckRegularPath(existing);
        Directory.CreateDirectory(root);
        ScanPath.CheckRegularPath(root);
        return root;
    }

    private static string CreateStagingDirectory(string root) =>
        Directory.CreateDirectory(Path.Combine(root, $"staging-{Guid.NewGuid():N}")).FullName;

    private static string NewGenerationPath(string root, Package package) =>
        Path.Combine(root, $"{package.Name.ToLowerInvariant()}-{package.Version}-{Guid.NewGuid():N}");

    private static void RemoveStagingDirectory(string root, string staging)
    {
        try
        {
            if (string.Equals(Path.GetDirectoryName(Path.GetFullPath(staging)), root, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(staging).StartsWith("staging-", StringComparison.Ordinal) && Directory.Exists(staging) &&
                (File.GetAttributes(staging) & FileAttributes.ReparsePoint) == 0)
                Directory.Delete(staging, recursive: true);
        }
        catch (Exception error) when (ScanPath.Expected(error)) { }
    }

    private static async Task<string?> TryGetYaraVersionAsync(string path, CancellationToken ct)
    {
        try
        {
            var result = await ToolProcess.RunAsync(path, ["--version"], ToolProbeTimeout, ct).ConfigureAwait(false);
            var text = FirstOutputLine(result);
            return result.ExitCode == 0 && Version.TryParse(text, out _) ? text : null;
        }
        catch (Exception error) when (ScanPath.Expected(error) || error is Win32Exception or TimeoutException)
        {
            return null;
        }
    }

    private static string? FirstOutputLine(ToolResult result) => result.StandardOutput
        .Split(['\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

    private static bool MatchesPackageVersion(Package package, string? text) => package == YaraPackage
        ? string.Equals(text, package.Version, StringComparison.Ordinal)
        : string.Equals(text, $"ClamAV {package.Version}", StringComparison.Ordinal) ||
          (text?.StartsWith($"ClamAV {package.Version}/", StringComparison.Ordinal) ?? false);

    private static IEnumerable<string> YaraSearchDirectories()
    {
        foreach (var path in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator,
                     StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            yield return path.Trim('"');

        foreach (var parent in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs")
        }.Where(Path.IsPathFullyQualified).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            yield return Path.Combine(parent, "YARA");
            yield return Path.Combine(parent, "YARA", "bin");
            yield return Path.Combine(parent, "VirusTotal", "YARA");
        }

        var winget = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "WinGet", "Packages");
        string[] folders;
        try
        {
            folders = Directory.Exists(winget)
                ? Directory.EnumerateDirectories(winget, "VirusTotal.YARA_*").Take(16).ToArray()
                : [];
        }
        catch (Exception error) when (ScanPath.Expected(error))
        {
            folders = [];
        }
        foreach (var folder in folders)
            yield return folder;
    }

    private sealed record Package(string Name, string Version, Uri DownloadUrl, string Sha256,
        int MaxDownloadMiB, int MaxExpandedMiB)
    {
        public long MaxDownloadBytes => MaxDownloadMiB * 1048576L;
        public long MaxExpandedBytes => MaxExpandedMiB * 1048576L;
    }
}

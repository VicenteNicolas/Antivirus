using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace SentinelSecurity.Engine;

public sealed class TrustedYaraRules
{
    private const string Revision = "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84";
    private const string Upstream = "https://raw.githubusercontent.com/reversinglabs/reversinglabs-yara-rules/";
    private const int FileLimit = 64 * 1024;
    private static readonly HttpClient Network = new(new SocketsHttpHandler { AllowAutoRedirect = false });
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly (string Path, string Sha256)[] Files =
    [
        ("LICENSE", "8AC378A5A6716E1AEF984C2EA50CBEB28D9A2F0A871846875245F71A02D023FC"),
        ("yara/ransomware/Win32.Ransomware.BlackCat.yara", "06E7C925272803D4623A95D227B1C2BFAEA2EAD94CA2BF4E0FC514F00576D9F0"),
        ("yara/ransomware/Win32.Ransomware.Conti.yara", "0E15843153384F4DAC9FC53101BCFA79FDC5D4CCE1DA3BFFD738F2503AA9FB23"),
        ("yara/ransomware/Win32.Ransomware.LockBit.yara", "FA3BB2A9CB674AACF2755152FEE239BCE0086094C7614756AC97B7F8586B4195"),
        ("yara/ransomware/Win32.Ransomware.NotPetya.yara", "D1E415F2310E4DA4642731230304290B22ED12A617E09FCE49580FBFF4972772"),
        ("yara/ransomware/Win32.Ransomware.WannaCry.yara", "620A3A157121C9DB704DD9716CBFD98D7A7A2E9A7FDAA90433E7507976765EC0"),
        ("yara/trojan/Win32.Trojan.Emotet.yara", "990A5F92FCD4FF544C3FE1DC281F52238120216E49138CCF98DA849217102347")
    ];

    private readonly HttpClient network;

    public TrustedYaraRules() : this(Network) { }

    public TrustedYaraRules(HttpClient network)
    {
        this.network = network ?? throw new ArgumentNullException(nameof(network));
    }

    public async Task<EngineUpdateResult> ImportAsync(string yara, string rulesRoot, IProgress<(int Completed, int Total)>? progress,
        CancellationToken ct)
    {
        var source = new StringBuilder("// Reglas de ReversingLabs, revisión ").Append(Revision).Append('\n');
        for (var index = 0; index < Files.Length; index++)
        {
            var (path, digest) = Files[index];
            var text = await DownloadAsync(path, digest, ct);
            if (index == 0)
            {
                using var license = new StringReader(text);
                while (license.ReadLine() is { } line)
                    source.Append("// ").Append(line).Append('\n');
            }
            else
            {
                source.Append("\n// ").Append(path).Append('\n').Append(text).Append('\n');
            }
            progress?.Report((index + 1, Files.Length));
        }

        var bytes = Utf8.GetBytes(source.ToString());
        var root = EngineUpdates.PrepareRoot(rulesRoot);
        var stagedSource = Path.Combine(root, $"source-{Guid.NewGuid():N}.yar");
        try
        {
            await File.WriteAllBytesAsync(stagedSource, bytes, ct);
            var bundle = await EngineUpdates.ImportYaraAsync(yara, stagedSource,
                Convert.ToHexString(SHA256.HashData(bytes)), root, ct);
            return bundle with { Version = $"ReversingLabs {Revision} · {bundle.Version}" };
        }
        finally
        {
            ExternalDetectors.DeleteTemporaryFile(stagedSource);
        }
    }

    private async Task<string> DownloadAsync(string path, string expected, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        var token = timeout.Token;
        try
        {
            using var response = await network.GetAsync(Upstream + Revision + "/" + path, HttpCompletionOption.ResponseHeadersRead, token);
            if (!response.IsSuccessStatusCode)
                throw new IOException($"ReversingLabs respondió HTTP {(int)response.StatusCode} al descargar {Path.GetFileName(path)}.");
            if (response.Content.Headers.ContentLength is > FileLimit)
                throw new IOException("El archivo de reglas excede el tamaño esperado.");
            await using var input = await response.Content.ReadAsStreamAsync(token);
            using var content = new MemoryStream();
            var buffer = ArrayPool<byte>.Shared.Rent(8192);
            try
            {
                int read;
                while ((read = await input.ReadAsync(buffer.AsMemory(0, 8192), token)) > 0)
                {
                    if (content.Length + read > FileLimit)
                        throw new IOException("El archivo de reglas excede el tamaño esperado.");
                    content.Write(buffer, 0, read);
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buffer); }
            var bytes = content.ToArray();
            if (!string.Equals(Convert.ToHexString(SHA256.HashData(bytes)), expected, StringComparison.Ordinal))
                throw new IOException($"El SHA-256 de {Path.GetFileName(path)} no coincide con la revisión verificada de ReversingLabs.");
            return Utf8.GetString(bytes).TrimStart('\uFEFF');
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"ReversingLabs no respondió a tiempo al descargar {Path.GetFileName(path)}.");
        }
        catch (HttpRequestException error)
        {
            throw new IOException("No se pudo conectar con el repositorio oficial de reglas de ReversingLabs.", error);
        }
    }
}

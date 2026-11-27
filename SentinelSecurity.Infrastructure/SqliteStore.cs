using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelSecurity.Core;

namespace SentinelSecurity.Infrastructure;

public sealed class SqliteStore : ISignatureLookup
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly string _directory;
    private readonly string _connectionString;
    private bool _hasSignatures;

    public SqliteStore(string dataDirectory)
    {
        _directory = Path.GetFullPath(dataDirectory);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(_directory, "sentinel.db"),
            Mode = SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 5,
            Pooling = false
        }.ToString();
    }

    public bool HasSignatures => Volatile.Read(ref _hasSignatures);

    public Task InitializeAsync(CancellationToken ct = default) => RunAsync(connection =>
    {
        using var version = Command(connection, "PRAGMA user_version");
        if (Convert.ToInt64(version.ExecuteScalar()) > 2)
            throw new InvalidOperationException("La base de datos requiere una versión posterior de Sentinel Security.");

        Execute(connection, "PRAGMA journal_mode = WAL");
        using var transaction = connection.BeginTransaction();
        using var schema = Command(connection, """
            CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id = 1), payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS exclusions (path TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS signatures (sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS official_signatures (sha256 TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, started INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, scan_id TEXT, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS quarantine (id TEXT PRIMARY KEY, isolated INTEGER NOT NULL, confirmed INTEGER NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS updates (id INTEGER PRIMARY KEY, source TEXT NOT NULL, version TEXT NOT NULL, updated INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, occurred INTEGER NOT NULL, category TEXT NOT NULL, message TEXT NOT NULL);
            PRAGMA user_version = 2;
            """);
        schema.Transaction = transaction;
        schema.ExecuteNonQuery();
        transaction.Commit();

        using var count = Command(connection,
            "SELECT EXISTS (SELECT 1 FROM signatures) OR EXISTS (SELECT 1 FROM official_signatures)");
        Volatile.Write(ref _hasSignatures, Convert.ToInt64(count.ExecuteScalar()) != 0);
    }, ct);

    public Task<SentinelSettings> LoadSettingsAsync(CancellationToken ct = default) => RunAsync(connection =>
    {
        using var transaction = connection.BeginTransaction(deferred: true);
        using var command = Command(connection, "SELECT payload FROM settings WHERE id = 1");
        command.Transaction = transaction;
        var settings = command.ExecuteScalar() is string payload ? Deserialize<SentinelSettings>(payload) : new SentinelSettings();
        using var exclusions = Command(connection, "SELECT path FROM exclusions ORDER BY rowid");
        exclusions.Transaction = transaction;
        using var reader = exclusions.ExecuteReader();
        var paths = new List<string>();
        while (reader.Read()) paths.Add(reader.GetString(0));
        return settings with { Exclusions = paths.ToArray() };
    }, ct);

    public Task SaveSettingsAsync(SentinelSettings settings, CancellationToken ct = default) =>
        SaveSettingsAsync(settings, null, ct);

    public Task SaveSettingsAndRecordUpdateAsync(SentinelSettings settings, UpdateRecord record, CancellationToken ct) =>
        SaveSettingsAsync(settings, record, ct);

    private Task SaveSettingsAsync(SentinelSettings settings, UpdateRecord? record, CancellationToken ct) => RunAsync(connection =>
    {
        ArgumentNullException.ThrowIfNull(settings);
        using var transaction = connection.BeginTransaction();
        using var update = Command(connection,
            "INSERT INTO settings VALUES(1, $payload) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            ("$payload", Serialize(settings with { Exclusions = [] })));
        update.Transaction = transaction;
        update.ExecuteNonQuery();

        using var clear = Command(connection, "DELETE FROM exclusions");
        clear.Transaction = transaction;
        clear.ExecuteNonQuery();
        using var insert = Command(connection, "INSERT INTO exclusions VALUES($path)");
        insert.Transaction = transaction;
        var pathParameter = insert.Parameters.Add("$path", SqliteType.Text);
        foreach (var path in settings.Exclusions.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            pathParameter.Value = path;
            insert.ExecuteNonQuery();
        }
        if (record is not null)
            InsertUpdate(connection, record, transaction);
        ct.ThrowIfCancellationRequested();
        transaction.Commit();
    }, ct);

    public ValueTask<string?> FindAsync(string sha256, CancellationToken ct = default)
    {
        if (!HasSignatures) return ValueTask.FromResult<string?>(null);
        return new ValueTask<string?>(RunAsync(connection => FindSignature(connection, sha256), ct));
    }

    private static string? FindSignature(SqliteConnection connection, string sha256)
    {
        using var command = Command(connection, """
            SELECT name FROM signatures WHERE sha256 = $sha
            UNION ALL
            SELECT name FROM official_signatures WHERE sha256 = $sha LIMIT 1
            """, ("$sha", sha256.ToUpperInvariant()));
        return command.ExecuteScalar() as string;
    }

    public Task<bool> VerifyAsync(CancellationToken ct) => RunAsync(connection =>
    {
        using var command = Command(connection, """
            SELECT sha256, name FROM signatures
            UNION ALL SELECT sha256, name FROM official_signatures LIMIT 1
            """);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return false;
        var hash = reader.GetString(0);
        var name = reader.GetString(1);
        reader.Close();
        return IsSha256(hash) && !string.IsNullOrWhiteSpace(name) &&
            string.Equals(name, FindSignature(connection, hash), StringComparison.Ordinal);
    }, ct);

    public Task ImportSignaturesAsync(IReadOnlyList<SignatureEntry> signatures, string version, CancellationToken ct = default) =>
        ImportSignaturesAsync(signatures, version, official: false, ct);

    public Task ImportOfficialSignaturesAsync(IReadOnlyList<SignatureEntry> signatures, string version, CancellationToken ct) =>
        ImportSignaturesAsync(signatures, version, official: true, ct);

    private Task ImportSignaturesAsync(IReadOnlyList<SignatureEntry> signatures, string version, bool official,
        CancellationToken ct) => RunAsync(connection =>
    {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        if (signatures.Count is 0 or > 2_000_000 || version.Length > 256)
            throw new ArgumentException("Se requiere entre 1 y 2 000 000 firmas y una versión de hasta 256 caracteres.");

        using var transaction = connection.BeginTransaction();
        using var clear = Command(connection, official ? "DELETE FROM official_signatures" : "DELETE FROM signatures");
        clear.Transaction = transaction;
        clear.ExecuteNonQuery();

        using var insert = Command(connection, official ?
            "INSERT INTO official_signatures VALUES($sha, $name)" : "INSERT INTO signatures VALUES($sha, $name)");
        insert.Transaction = transaction;
        var hash = insert.Parameters.Add("$sha", SqliteType.Text);
        var name = insert.Parameters.Add("$name", SqliteType.Text);
        foreach (var signature in signatures)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsSha256(signature.Sha256) || string.IsNullOrWhiteSpace(signature.Name) || signature.Name.Length > 512)
                throw new ArgumentException("Firma SHA-256 o nombre de detección no válido.");
            hash.Value = signature.Sha256.ToUpperInvariant();
            name.Value = signature.Name.Trim();
            insert.ExecuteNonQuery();
        }

        using var check = Command(connection, official
            ? "SELECT name FROM official_signatures WHERE sha256 = $sha"
            : "SELECT name FROM signatures WHERE sha256 = $sha", ("$sha", signatures[0].Sha256.ToUpperInvariant()));
        check.Transaction = transaction;
        if (!string.Equals(check.ExecuteScalar() as string, signatures[0].Name.Trim(), StringComparison.Ordinal))
            throw new IOException("No se pudo comprobar el catálogo de firmas después de importarlo.");
        InsertUpdate(connection, new UpdateRecord(official ? "SHA-256 oficial" : "SHA-256", version.Trim(),
            DateTimeOffset.UtcNow), transaction);
        ct.ThrowIfCancellationRequested();
        transaction.Commit();
        Volatile.Write(ref _hasSignatures, true);
    }, ct);

    public Task RecordScanAsync(ScanSummary summary, CancellationToken ct = default) => RunAsync(connection =>
        Execute(connection, "INSERT INTO scans VALUES($id, $started, $payload) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            ("$id", summary.Id.ToString("N")), ("$started", summary.Started.UtcTicks), ("$payload", Serialize(summary))), ct);

    public Task RecordFindingAsync(Guid? scanId, FileResult result, CancellationToken ct = default) => RunAsync(connection =>
        Execute(connection, "INSERT INTO findings(scan_id, payload) VALUES($scan, $payload)",
            ("$scan", scanId?.ToString("N")), ("$payload", Serialize(result))), ct);

    public Task<IReadOnlyList<ScanSummary>> GetScansAsync(CancellationToken ct = default) =>
        ReadPayloadsAsync<ScanSummary>("SELECT payload FROM scans ORDER BY started DESC LIMIT 500", ct);

    public Task<IReadOnlyList<FileResult>> GetFindingsAsync(CancellationToken ct = default) =>
        ReadPayloadsAsync<FileResult>("SELECT payload FROM findings ORDER BY id DESC LIMIT 2000", ct);

    public Task<IReadOnlyList<QuarantineItem>> GetQuarantineAsync(CancellationToken ct = default) => RunAsync<IReadOnlyList<QuarantineItem>>(connection =>
    {
        using var command = Command(connection, "SELECT confirmed, payload FROM quarantine ORDER BY isolated DESC");
        using var reader = command.ExecuteReader();
        var items = new List<QuarantineItem>();
        while (reader.Read())
        {
            ct.ThrowIfCancellationRequested();
            var item = Deserialize<QuarantineItem>(reader.GetString(1));
            items.Add(reader.GetBoolean(0) ? item : item with { Reason = $"Aislamiento sin confirmar. {item.Reason}" });
        }
        return items;
    }, ct);

    internal Task<QuarantineItem?> FindQuarantineAsync(Guid id, CancellationToken ct) => RunAsync(connection =>
    {
        using var command = Command(connection, "SELECT payload FROM quarantine WHERE id = $id", ("$id", id.ToString("N")));
        return command.ExecuteScalar() is string payload ? Deserialize<QuarantineItem>(payload) : null;
    }, ct);

    internal Task RememberQuarantineAsync(QuarantineItem item, CancellationToken ct) => RunAsync(connection =>
        Execute(connection, "INSERT INTO quarantine VALUES($id, $date, 0, $payload)",
            ("$id", item.Id.ToString("N")), ("$date", item.IsolatedAt.UtcTicks), ("$payload", Serialize(item))), ct);

    internal Task ConfirmQuarantineAsync(Guid id, CancellationToken ct) => RunAsync(connection =>
        Execute(connection, "UPDATE quarantine SET confirmed = 1 WHERE id = $id", ("$id", id.ToString("N"))), ct);

    internal Task ForgetQuarantineAsync(Guid id, CancellationToken ct) => RunAsync(connection =>
        Execute(connection, "DELETE FROM quarantine WHERE id = $id", ("$id", id.ToString("N"))), ct);

    public Task RecordUpdateAsync(UpdateRecord update, CancellationToken ct = default) =>
        RunAsync(connection => InsertUpdate(connection, update, null), ct);

    public Task<IReadOnlyList<UpdateRecord>> GetUpdatesAsync(CancellationToken ct = default) => RunAsync<IReadOnlyList<UpdateRecord>>(connection =>
    {
        using var command = Command(connection, "SELECT source, version, updated FROM updates ORDER BY updated DESC, id DESC LIMIT 500");
        using var reader = command.ExecuteReader();
        var updates = new List<UpdateRecord>();
        while (reader.Read())
        {
            ct.ThrowIfCancellationRequested();
            updates.Add(new UpdateRecord(reader.GetString(0), reader.GetString(1), new DateTimeOffset(reader.GetInt64(2), TimeSpan.Zero)));
        }
        return updates;
    }, ct);

    public Task LogAsync(string category, string message, CancellationToken ct = default) => RunAsync(connection =>
        Execute(connection, "INSERT INTO events(occurred, category, message) VALUES($when, $category, $message)",
            ("$when", DateTimeOffset.UtcNow.UtcTicks), ("$category", category), ("$message", message)), ct);

    internal static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);

    private Task<IReadOnlyList<T>> ReadPayloadsAsync<T>(string sql, CancellationToken ct) => RunAsync<IReadOnlyList<T>>(connection =>
    {
        using var command = Command(connection, sql);
        using var reader = command.ExecuteReader();
        var rows = new List<T>();
        while (reader.Read())
        {
            ct.ThrowIfCancellationRequested();
            rows.Add(Deserialize<T>(reader.GetString(0)));
        }
        return rows;
    }, ct);

    private Task RunAsync(Action<SqliteConnection> action, CancellationToken ct) => RunAsync(connection =>
    {
        action(connection);
        return true;
    }, ct);

    // Microsoft.Data.Sqlite runs file I/O synchronously, including its async APIs.
    private Task<T> RunAsync<T>(Func<SqliteConnection, T> action, CancellationToken ct) => Task.Run(() =>
    {
        ct.ThrowIfCancellationRequested();
        Directory.CreateDirectory(_directory);
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return action(connection);
    }, ct);

    private static void InsertUpdate(SqliteConnection connection, UpdateRecord update, SqliteTransaction? transaction)
    {
        using var command = Command(connection, "INSERT INTO updates(source, version, updated) VALUES($source, $version, $updated)",
            ("$source", update.Source), ("$version", update.Version), ("$updated", update.UpdatedAt.UtcTicks));
        command.Transaction = transaction;
        command.ExecuteNonQuery();
    }

    private static void Execute(SqliteConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = Command(connection, sql, parameters);
        command.ExecuteNonQuery();
    }

    private static SqliteCommand Command(SqliteConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Json);

    private static T Deserialize<T>(string payload) => JsonSerializer.Deserialize<T>(payload, Json)
        ?? throw new InvalidDataException("Registro local no válido.");
}

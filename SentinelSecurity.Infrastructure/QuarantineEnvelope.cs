using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text.Json;
using SentinelSecurity.Core;

namespace SentinelSecurity.Infrastructure;

[SupportedOSPlatform("windows")]
internal static class QuarantineEnvelope
{
    internal const long MaximumBytes = 512L * 1024 * 1024;
    private const int ChunkBytes = 1024 * 1024;
    private const int TagBytes = 16;
    private const int HeaderBytes = 18;
    private static ReadOnlySpan<byte> Magic => "SNTLQ001"u8;
    private static readonly byte[] KeyPurpose = "Sentinel Security quarantine v1"u8.ToArray();

    internal static async Task EncryptAsync(Stream source, Stream destination, QuarantineItem item, long size, CancellationToken ct)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var protectedKey = ProtectedData.Protect(key, KeyPurpose, DataProtectionScope.CurrentUser);
            var header = new byte[HeaderBytes];
            Magic.CopyTo(header);
            BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(8), size);
            BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(16), checked((ushort)protectedKey.Length));
            await destination.WriteAsync(header, ct).ConfigureAwait(false);
            await destination.WriteAsync(protectedKey, ct).ConfigureAwait(false);
            await ProcessAsync(source, destination, item, size, key, encrypting: true, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static async Task DecryptAsync(Stream source, Stream destination, QuarantineItem item, CancellationToken ct)
    {
        var header = new byte[HeaderBytes];
        await source.ReadExactlyAsync(header, ct).ConfigureAwait(false);
        if (!header.AsSpan(0, 8).SequenceEqual(Magic)) throw new InvalidDataException("Formato de cuarentena no válido.");
        var size = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(8));
        var protectedKeyLength = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(16));
        if (size is < 0 or > MaximumBytes || protectedKeyLength is < 1 or > 4096)
            throw new InvalidDataException("Encabezado de cuarentena no válido.");

        var protectedKey = new byte[protectedKeyLength];
        await source.ReadExactlyAsync(protectedKey, ct).ConfigureAwait(false);
        var key = ProtectedData.Unprotect(protectedKey, KeyPurpose, DataProtectionScope.CurrentUser);
        try
        {
            if (key.Length != 32) throw new InvalidDataException("Clave de cuarentena no válida.");
            await ProcessAsync(source, destination, item, size, key, encrypting: false, ct).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static async Task ProcessAsync(Stream source, Stream destination, QuarantineItem item, long size,
        byte[] key, bool encrypting, CancellationToken ct)
    {
        using var cipher = new AesGcm(key, TagBytes);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var associatedData = JsonSerializer.SerializeToUtf8Bytes(new { item.Id, item.OriginalPath, item.Sha256, Size = size });
        var plaintext = ArrayPool<byte>.Shared.Rent(ChunkBytes);
        var ciphertext = ArrayPool<byte>.Shared.Rent(ChunkBytes);
        var tag = new byte[TagBytes];
        // Each file has its own random AES key. The frame counter keeps nonce values distinct within the file.
        var nonce = new byte[12];
        var remaining = size;
        var sequence = 0u;
        try
        {
            do
            {
                var count = (int)Math.Min(ChunkBytes, remaining);
                BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(8), sequence++);
                if (encrypting)
                {
                    await source.ReadExactlyAsync(plaintext.AsMemory(0, count), ct).ConfigureAwait(false);
                    cipher.Encrypt(nonce, plaintext.AsSpan(0, count), ciphertext.AsSpan(0, count), tag, associatedData);
                    await destination.WriteAsync(ciphertext.AsMemory(0, count), ct).ConfigureAwait(false);
                    await destination.WriteAsync(tag, ct).ConfigureAwait(false);
                }
                else
                {
                    await source.ReadExactlyAsync(ciphertext.AsMemory(0, count), ct).ConfigureAwait(false);
                    await source.ReadExactlyAsync(tag, ct).ConfigureAwait(false);
                    cipher.Decrypt(nonce, ciphertext.AsSpan(0, count), tag, plaintext.AsSpan(0, count), associatedData);
                    await destination.WriteAsync(plaintext.AsMemory(0, count), ct).ConfigureAwait(false);
                }
                hash.AppendData(plaintext, 0, count);
                remaining -= count;
            }
            while (remaining > 0);

            ct.ThrowIfCancellationRequested();
            if (source.ReadByte() != -1 || !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(item.Sha256), hash.GetHashAndReset()))
                throw new InvalidDataException("El contenido ya no coincide con el hash SHA-256 del análisis.");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(plaintext, clearArray: true);
            ArrayPool<byte>.Shared.Return(ciphertext);
        }
    }
}

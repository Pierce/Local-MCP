using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LocalMcp.Roots;
using LocalMcp.Security;

namespace LocalMcp.Tools;

internal sealed record DirectoryCursorState(
    int TokenVersion,
    int OrderingVersion,
    int PageSize,
    string RootBinding,
    string DirectoryBinding,
    string ConfigurationBinding,
    string LastVisibleName);

/// <summary>
/// Process-local cursor authority. Cursor state is authenticated and encrypted so decoding the
/// transport representation cannot disclose the logical resume name or protected host facts.
/// </summary>
public sealed class DirectoryCursorProtector : IDisposable
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int MaximumTokenLength = 8192;
    private readonly byte[] _encryptionKey = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _bindingKey = RandomNumberGenerator.GetBytes(32);
    private bool _disposed;

    internal string Protect(DirectoryCursorState state)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(state);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(_encryptionKey, TagSize))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        }

        var token = new byte[1 + NonceSize + TagSize + ciphertext.Length];
        token[0] = 1;
        nonce.CopyTo(token.AsSpan(1));
        tag.CopyTo(token.AsSpan(1 + NonceSize));
        ciphertext.CopyTo(token.AsSpan(1 + NonceSize + TagSize));
        CryptographicOperations.ZeroMemory(plaintext);
        return Base64UrlEncode(token);
    }

    internal bool TryUnprotect(string? token, out DirectoryCursorState? state)
    {
        state = null;
        if (_disposed || string.IsNullOrWhiteSpace(token) || token.Length > MaximumTokenLength)
            return false;

        byte[] packed;
        try { packed = Base64UrlDecode(token); }
        catch (FormatException) { return false; }
        if (packed.Length <= 1 + NonceSize + TagSize || packed[0] != 1)
            return false;

        var nonce = packed.AsSpan(1, NonceSize);
        var tag = packed.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = packed.AsSpan(1 + NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(_encryptionKey, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            state = JsonSerializer.Deserialize<DirectoryCursorState>(plaintext);
            return state is not null;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or NotSupportedException)
        {
            state = null;
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    internal string BindRoot(string rootId) => Bind("root", Encoding.UTF8.GetBytes(rootId));

    internal string BindDirectory(AuthorizedFileSystemObject directory)
    {
        var value = Encoding.UTF8.GetBytes(
            $"{directory.RelativePath.ToUpperInvariant()}\0{directory.Facts.Identity.VolumeSerialNumber:X16}:{directory.Facts.Identity.FileIdHex}");
        return Bind("directory", value);
    }

    internal string BindConfiguration(ValidatedRootRegistry registry) =>
        Bind("configuration", registry.DeniedConfiguration.ContentSha256);

    private string Bind(string purpose, ReadOnlySpan<byte> value)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var hmac = new HMACSHA256(_bindingKey);
        var purposeBytes = Encoding.UTF8.GetBytes(purpose + "\0");
        hmac.TransformBlock(purposeBytes, 0, purposeBytes.Length, null, 0);
        hmac.TransformFinalBlock(value.ToArray(), 0, value.Length);
        return Base64UrlEncode(hmac.Hash!);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        normalized += (normalized.Length % 4) switch { 2 => "==", 3 => "=", 0 => "", _ => throw new FormatException() };
        return Convert.FromBase64String(normalized);
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_encryptionKey);
        CryptographicOperations.ZeroMemory(_bindingKey);
        _disposed = true;
    }
}

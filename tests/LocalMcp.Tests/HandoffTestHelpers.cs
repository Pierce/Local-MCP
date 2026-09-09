using System.Security.Cryptography;
using System.Text;
using LocalMcp.Configuration;
using LocalMcp.Handoff;

namespace LocalMcp.Tests;

public static class HandoffTestHelpers
{
    /// <summary>
    /// Creates a governed staged record for testing. This simulates the governed
    /// staging writer placing a record in the handoff store.
    /// </summary>
    public static string CreateStagedRecord(
        string storePath,
        string handoffId,
        string transportSchemaVersion,
        string intendedRecipientReference,
        string payloadContent,
        byte[] hmacKey,
        string stagingWriter = "test-staging-writer-v1",
        bool available = true)
    {
        var manifestsDir = Path.Combine(storePath, "manifests");
        var payloadsDir = Path.Combine(storePath, "payloads");

        Directory.CreateDirectory(manifestsDir);
        Directory.CreateDirectory(payloadsDir);

        // Write payload bytes (preserve exact content)
        var payloadBytes = Encoding.UTF8.GetBytes(payloadContent);
        var payloadIdentity = Convert.ToHexString(SHA256.HashData(payloadBytes)).ToUpperInvariant();
        File.WriteAllBytes(Path.Combine(payloadsDir, $"{handoffId}.payload.bin"), payloadBytes);

        var stagedAt = DateTime.UtcNow;

        // Compute HMAC (sole integrity authenticator for the record)
        var hmacValue = StagingIntegrity.ComputeHmac(
            hmacKey, handoffId, transportSchemaVersion, intendedRecipientReference,
            payloadIdentity, stagedAt.Ticks, stagingWriter, available);

        var record = new StagedHandoffRecord(
            handoffId, transportSchemaVersion, intendedRecipientReference,
            payloadIdentity, hmacValue, stagedAt, available, stagingWriter);

        // Write manifest
        var manifestJson = System.Text.Json.JsonSerializer.Serialize(record, new System.Text.Json.JsonSerializerOptions
        {
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower,
            WriteIndented = true
        });
        File.WriteAllText(Path.Combine(manifestsDir, $"{handoffId}.manifest.json"), manifestJson);

        return payloadIdentity;
    }

    /// <summary>
    /// Creates a self-consistent but UNAUTHORIZED record (inserted outside governed staging).
    /// This computes correct hashes but cannot produce a valid HMAC because it doesn't
    /// know the key. This tests R-02: an unauthorized insertion cannot become valid merely
    /// by recomputing hashes.
    /// </summary>
    public static string CreateUnauthorizedRecord(
        string storePath,
        string handoffId,
        string transportSchemaVersion,
        string intendedRecipientReference,
        string payloadContent,
        byte[] wrongKey)
    {
        // This simulates an attacker who knows the algorithm but not the real key.
        // Using a wrong/different key means the HMAC won't verify.
        return CreateStagedRecord(storePath, handoffId, transportSchemaVersion,
            intendedRecipientReference, payloadContent, wrongKey,
            stagingWriter: "unauthorized-inserter", available: true);
    }

    public static HandoffRetrievalConfig CreateTestConfig(string storePath, string recipientRef, byte[] hmacKey)
    {
        return new HandoffRetrievalConfig(true, storePath, recipientRef, hmacKey,
            HandoffRetrievalConfig.DefaultMaxPayloadBytes,
            HandoffRetrievalConfig.DefaultMaxManifestBytes);
    }

    public static byte[] GenerateTestKey() => RandomNumberGenerator.GetBytes(32);

    /// <summary>
    /// Byte-fidelity test payloads covering all required edge cases per R-03.
    /// </summary>
    public static readonly Dictionary<string, string> ByteFidelityCases = new()
    {
        ["lf-only"] = "Hello\nWorld\n",
        ["crlf"] = "Hello\r\nWorld\r\n",
        ["non-ascii-utf8"] = "Hello Wörld 🌍\n",
        ["combining-unicode"] = "é\u0301\u20DE\n",  // e + combining acute + combining enclosing circle
        ["precomposed-unicode"] = "\u00E9\u20DE\n", // single-character é + enclosing circle
        ["json-quotes"] = "{\"key\": \"value\"}\n",
        ["json-escapes"] = "line1\\nline2\\ttab\n",
        ["tabs"] = "col1\tcol2\tcol3\n",
        ["whitespace"] = "  leading and trailing  \n",
        ["trailing-newline"] = "ends with newline\n",
        ["no-trailing-newline"] = "no newline at end",
        ["bom-utf8"] = "\uFEFFHello with BOM\n",
        ["serializer-sensitive"] = "null byte: \0 and control: \u0001\u0002\n",
    };

    /// <summary>
    /// Gets the exact bytes for a test payload string.
    /// </summary>
    public static byte[] GetPayloadBytes(string content) => Encoding.UTF8.GetBytes(content);

    /// <summary>
    /// Computes SHA-256 as hex uppercase.
    /// </summary>
    public static string ComputeSha256Hex(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToUpperInvariant();

    /// <summary>
    /// Creates a HandoffStore from config.
    /// </summary>
    public static HandoffStore CreateStore(HandoffRetrievalConfig config) => new(config);
}
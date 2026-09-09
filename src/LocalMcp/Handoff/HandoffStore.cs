using System.Security.Cryptography;
using System.Text.Json;
using LocalMcp.Configuration;

namespace LocalMcp.Handoff;

/// <summary>
/// Governed handoff store that reads and validates staged handoff records
/// from a configured staging directory.
///
/// Every retrieval validates:
/// - manifest integrity via HMAC (R-02 staging provenance);
/// - payload identity via SHA-256 (R-03 exact byte fidelity);
/// - intended recipient match (mechanical boundary only);
/// - availability state (mechanical retrievability only, not lifecycle).
/// </summary>
public sealed class HandoffStore
{
    private readonly HandoffRetrievalConfig _config;
    private readonly string _manifestsPath;
    private readonly string _payloadsPath;

    public HandoffStore(HandoffRetrievalConfig config)
    {
        _config = config;
        _manifestsPath = Path.Combine(config.StorePath, "manifests");
        _payloadsPath = Path.Combine(config.StorePath, "payloads");
    }

    /// <summary>
    /// Attempts to retrieve a governed staged handoff record by exact handoff_id.
    /// Returns a RetrievalResult with either the verified record or a failure category.
    /// </summary>
    public RetrievalResult TryGetHandoff(string handoffId)
    {
        if (!IsValidHandoffId(handoffId))
            return RetrievalResult.Failure(RetrievalFailureCategory.MalformedHandoffId);

        var manifestResult = LoadManifest(handoffId);
        if (manifestResult.Category.HasValue)
            return manifestResult;

        var record = manifestResult.Record!;

        if (!string.Equals(record.IntendedRecipientReference, _config.IntendedRecipientReference, StringComparison.Ordinal))
            return RetrievalResult.Failure(RetrievalFailureCategory.CrossRecipient);

        if (!record.Available)
            return RetrievalResult.Failure(RetrievalFailureCategory.Unavailable);

        if (!StagingIntegrity.VerifyHmac(_config.HmacKey, record))
            return RetrievalResult.Failure(RetrievalFailureCategory.ManifestIntegrityFailed);

        var payloadResult = LoadPayload(handoffId);
        if (payloadResult.Category.HasValue)
            return payloadResult;

        if (!StagingIntegrity.VerifyPayloadIdentity(record.PayloadIdentity, payloadResult.PayloadBytes!))
            return RetrievalResult.Failure(RetrievalFailureCategory.PayloadIntegrityFailed);

        return RetrievalResult.Success(record, payloadResult.PayloadBytes!);
    }
private RetrievalResult LoadManifest(string handoffId)
    {
        var manifestPath = Path.Combine(_manifestsPath, $"{handoffId}.manifest.json");
        if (!File.Exists(manifestPath)) return RetrievalResult.Failure(RetrievalFailureCategory.UnknownId);

        byte[] manifestBytes;
        try
        {
            var fi = new FileInfo(manifestPath);
            if (fi.Length > _config.MaxManifestBytes)
                return RetrievalResult.Failure(RetrievalFailureCategory.InvalidManifestFormat);
            manifestBytes = File.ReadAllBytes(manifestPath);
        }
        catch { return RetrievalResult.Failure(RetrievalFailureCategory.InvalidManifestFormat); }

        StagedHandoffRecord? record;
        try { record = JsonSerializer.Deserialize<StagedHandoffRecord>(manifestBytes, _jsonOptions); }
        catch (JsonException) { return RetrievalResult.Failure(RetrievalFailureCategory.InvalidManifestFormat); }

        if (record is null ||
            string.IsNullOrWhiteSpace(record.HandoffId) ||
            string.IsNullOrWhiteSpace(record.TransportSchemaVersion) ||
            string.IsNullOrWhiteSpace(record.IntendedRecipientReference) ||
            string.IsNullOrWhiteSpace(record.PayloadIdentity) ||
            string.IsNullOrWhiteSpace(record.ManifestHmac) ||
            string.IsNullOrWhiteSpace(record.StagingWriter))
        {
            return RetrievalResult.Failure(RetrievalFailureCategory.InvalidManifestFormat);
        }

        if (!string.Equals(record.HandoffId, handoffId, StringComparison.Ordinal))
            return RetrievalResult.Failure(RetrievalFailureCategory.InvalidManifestFormat);

        return RetrievalResult.Manifest(record, manifestBytes);
    }

    private RetrievalResult LoadPayload(string handoffId)
    {
        var payloadPath = Path.Combine(_payloadsPath, $"{handoffId}.payload.bin");
        if (!File.Exists(payloadPath)) return RetrievalResult.Failure(RetrievalFailureCategory.PayloadNotFound);

        try
        {
            var fi = new FileInfo(payloadPath);
            if (fi.Length > _config.MaxPayloadBytes)
                return RetrievalResult.Failure(RetrievalFailureCategory.PayloadSizeExceeded);
            return RetrievalResult.Payload(File.ReadAllBytes(payloadPath));
        }
        catch { return RetrievalResult.Failure(RetrievalFailureCategory.PayloadReaderFailed); }
    }

    internal static bool IsValidHandoffId(string? handoffId)
    {
        if (string.IsNullOrEmpty(handoffId) || handoffId.Length > 256) return false;
        foreach (var c in handoffId)
        {
            if (!char.IsAscii(c) || char.IsControl(c) || char.IsWhiteSpace(c)) return false;
            if (c is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|') return false;
        }
        if (handoffId == "." || handoffId == ".." || handoffId.Contains("..", StringComparison.Ordinal) || handoffId.StartsWith('~'))
            return false;
        return true;
    }

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
    };
}

public sealed record RetrievalResult
{
    private RetrievalResult(StagedHandoffRecord? record, byte[]? payloadBytes, byte[]? manifestBytes, RetrievalFailureCategory? category)
    {
        Record = record; PayloadBytes = payloadBytes; ManifestBytes = manifestBytes; Category = category;
    }
    public StagedHandoffRecord? Record { get; }
    public byte[]? PayloadBytes { get; }
    public byte[]? ManifestBytes { get; }
    public RetrievalFailureCategory? Category { get; }
    public bool IsSuccess => Record is not null && PayloadBytes is not null && Category is null;
    public static RetrievalResult Success(StagedHandoffRecord record, byte[] payloadBytes) => new(record, payloadBytes, null, null);
    public static RetrievalResult Failure(RetrievalFailureCategory category) => new(null, null, null, category);
    public static RetrievalResult Manifest(StagedHandoffRecord record, byte[] manifestBytes) => new(record, null, manifestBytes, null);
    public static RetrievalResult Payload(byte[] payloadBytes) => new(null, payloadBytes, null, null);
}
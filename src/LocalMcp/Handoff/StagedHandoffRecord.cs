using System.Text.Json.Serialization;

namespace LocalMcp.Handoff;

/// <summary>
/// A governed staged handoff record with verified staging provenance.
/// This represents a successfully validated record that passed all
/// staging-integrity and association checks.
/// </summary>
public sealed record StagedHandoffRecord(
    [property: JsonPropertyName("handoff_id")] string HandoffId,
    [property: JsonPropertyName("transport_schema_version")] string TransportSchemaVersion,
    [property: JsonPropertyName("intended_recipient_reference")] string IntendedRecipientReference,
    [property: JsonPropertyName("payload_identity")] string PayloadIdentity,
    [property: JsonPropertyName("manifest_hmac")] string ManifestHmac,
    [property: JsonPropertyName("staged_at")] DateTime StagedAtUtc,
    [property: JsonPropertyName("available")] bool Available,
    [property: JsonPropertyName("staging_writer")] string StagingWriter);

/// <summary>
/// Internal categories for failed retrieval diagnosis.
/// These are never exposed to the MCP client.
/// </summary>
public enum RetrievalFailureCategory
{
    UnknownId,
    CrossRecipient,
    Unavailable,
    PayloadNotFound,
    PayloadSizeExceeded,
    ManifestIntegrityFailed,
    PayloadIntegrityFailed,
    PayloadReaderFailed,
    InvalidManifestFormat,
    MalformedHandoffId,
}
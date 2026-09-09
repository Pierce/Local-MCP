using System.ComponentModel;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using LocalMcp.Handoff;
using ModelContextProtocol.Server;

namespace LocalMcp.Tools;

/// <summary>
/// Separately governed Handoff Retrieval MCP tool.
/// 
/// CAPABILITY AUTHORITY: This tool belongs to the governed Handoff Retrieval
/// capability, not to Local Files. It is registered only when the handoff
/// retrieval configuration is enabled and validated. Enabling this tool does
/// not implicitly enable any Local Files tool, and enabling Local Files does
/// not implicitly enable this tool.
/// 
/// R-01: The calling process must have no Local Files root that contains,
/// aliases, or resolves into the governed handoff store. This is validated
/// at startup, not in this tool.
/// 
/// R-02: Staging provenance/integrity is enforced via HMAC-SHA256 before
/// any retrieval is returned.
/// 
/// R-03: Payload is returned as Base64 to guarantee exact byte fidelity.
/// The payload_identity (SHA-256) is verified against the original bytes.
/// 
/// R-04: Authorization-sensitive failures collapse to a single generic
/// MCP-visible error code: "HANOFF_NOT_RETRIEVABLE".
/// </summary>
[McpServerToolType]
public sealed class GetHandoffTool
{
    private readonly HandoffStore _store;

    public GetHandoffTool(HandoffStore store)
    {
        _store = store;
    }

    [McpServerTool(Name = "get_handoff", ReadOnly = true, Idempotent = true)]
    [Description("Retrieves one verified governed handoff by exact handoff_id. Returns the immutable staged handoff with Base64-encoded payload for exact byte reconstruction.")]
    public GetHandoffResponse GetHandoff(string handoff_id)
    {
        var result = _store.TryGetHandoff(handoff_id);
        if (!result.IsSuccess)
        {
            // R-04: Collapse to generic failure for syntactically valid IDs
            if (result.Category == RetrievalFailureCategory.MalformedHandoffId)
            {
                return GetHandoffResponse.Failure("HANDOFF_ID_SYNTAX_INVALID");
            }

            return GetHandoffResponse.Failure("HANOFF_NOT_RETRIEVABLE");
        }

        return GetHandoffResponse.Success(
            result.Record!.HandoffId,
            result.Record.PayloadIdentity,
            Convert.ToBase64String(result.PayloadBytes!),
            result.Record.TransportSchemaVersion);
    }
}

public sealed record GetHandoffResponse(
    [property: JsonPropertyName("handoff_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? HandoffId,
    [property: JsonPropertyName("payload_identity"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? PayloadIdentity,
    [property: JsonPropertyName("payload_base64"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? PayloadBase64,
    [property: JsonPropertyName("transport_schema_version"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? TransportSchemaVersion,
    [property: JsonPropertyName("error_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    string? ErrorCode)
{
    public static GetHandoffResponse Success(string handoffId, string payloadIdentity, string payloadBase64, string transportSchemaVersion) =>
        new(handoffId, payloadIdentity, payloadBase64, transportSchemaVersion, null);

    public static GetHandoffResponse Failure(string errorCode) =>
        new(null, null, null, null, errorCode);
}
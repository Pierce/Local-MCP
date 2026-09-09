using System.Security.Cryptography;
using System.Text;

namespace LocalMcp.Handoff;

/// <summary>
/// Bounded HMAC-SHA256 based staging provenance mechanism.
///
/// Design rationale (R-02):
/// An attacker who can write files can compute correct payload hashes for
/// any inserted content. Hash-only self-consistency is insufficient.
///
/// This mechanism uses HMAC-SHA256 with a pre-shared key known only to the
/// governed staging writer and the Handoff Retrieval configuration. Without
/// the key, an attacker cannot produce a valid manifest.
///
/// The HMAC covers all governing record fields, binding the exact association.
/// Substituting any field between otherwise valid staged records fails closed.
/// </summary>
internal static class StagingIntegrity
{
    private const string HmacFieldSeparator = "\u0000";

    /// <summary>
    /// Computes the HMAC-SHA256 over canonical field bytes for a staged record.
    /// This is the sole integrity authenticator for the record. It covers all
    /// governing fields so that no field can be substituted without detection.
    /// </summary>
    public static string ComputeHmac(byte[] key, string handoffId, string transportSchemaVersion,
        string intendedRecipientReference, string payloadIdentity, long stagedAtTicks,
        string stagingWriter, bool available)
    {
        var canonicalBytes = BuildCanonicalBytes(handoffId, transportSchemaVersion,
            intendedRecipientReference, payloadIdentity, stagedAtTicks, stagingWriter, available);

        using var hmac = new HMACSHA256(key);
        var hash = hmac.ComputeHash(canonicalBytes);
        return ConvertToHex(hash);
    }

    /// <summary>
    /// Verifies that the HMAC on a stored record matches the recomputed value.
    /// This proves the record originated through the configured governed
    /// staging boundary (the writer knew the HMAC key).
    /// </summary>
    public static bool VerifyHmac(byte[] key, StagedHandoffRecord record)
    {
        var expected = ComputeHmac(key, record.HandoffId, record.TransportSchemaVersion,
            record.IntendedRecipientReference, record.PayloadIdentity,
            record.StagedAtUtc.Ticks, record.StagingWriter, record.Available);

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expected),
            Encoding.ASCII.GetBytes(record.ManifestHmac));
    }

    /// <summary>
    /// Verifies payload identity matches SHA-256 of the provided payload bytes.
    /// </summary>
    public static bool VerifyPayloadIdentity(string expectedIdentity, byte[] payloadBytes)
    {
        var actualHash = SHA256.HashData(payloadBytes);
        var actualHex = ConvertToHex(actualHash);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedIdentity),
            Encoding.ASCII.GetBytes(actualHex));
    }

    private static byte[] BuildCanonicalBytes(string handoffId, string transportSchemaVersion,
        string intendedRecipientReference, string payloadIdentity, long stagedAtTicks,
        string stagingWriter, bool available)
    {
        var builder = new StringBuilder();
        builder.Append(handoffId ?? string.Empty);
        builder.Append(HmacFieldSeparator);
        builder.Append(transportSchemaVersion ?? string.Empty);
        builder.Append(HmacFieldSeparator);
        builder.Append(intendedRecipientReference ?? string.Empty);
        builder.Append(HmacFieldSeparator);
        builder.Append(payloadIdentity ?? string.Empty);
        builder.Append(HmacFieldSeparator);
        builder.Append(stagedAtTicks);
        builder.Append(HmacFieldSeparator);
        builder.Append(stagingWriter ?? string.Empty);
        builder.Append(HmacFieldSeparator);
        builder.Append(available ? '1' : '0');
        builder.Append(HmacFieldSeparator);
        builder.Append("GOVERNED_HANOFF_V1");

        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    private static string ConvertToHex(byte[] bytes) =>
        Convert.ToHexString(bytes).ToUpperInvariant();
}
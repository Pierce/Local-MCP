using System.Security.Cryptography;

namespace LocalMcp.Configuration;

/// <summary>
/// Configuration for the separately governed Handoff Retrieval capability.
/// This is never derived from Local Files configuration and must be explicitly
/// and independently enabled.
/// </summary>
public sealed record HandoffRetrievalConfig(
    bool Enabled,
    string StorePath,
    string IntendedRecipientReference,
    byte[] HmacKey,
    long MaxPayloadBytes,
    long MaxManifestBytes)
{
    public const long DefaultMaxPayloadBytes = 1_048_576; // 1 MiB
    public const long DefaultMaxManifestBytes = 65_536;   // 64 KiB

    public static HandoffRetrievalConfig Disabled() => new(
        false, string.Empty, string.Empty, Array.Empty<byte>(), 0, 0);

    public bool IsEnabled => Enabled
        && !string.IsNullOrWhiteSpace(StorePath)
        && !string.IsNullOrWhiteSpace(IntendedRecipientReference)
        && HmacKey.Length > 0
        && MaxPayloadBytes > 0
        && MaxManifestBytes > 0;
}
using System.Security.Cryptography;
using System.Text;
using LocalMcp.Handoff;
using LocalMcp.Roots;
using LocalMcp.Security;
using Tomlyn;
using Tomlyn.Model;

namespace LocalMcp.Configuration;

internal sealed class ConfigurationAuthorityLoader
{
    private const int MaximumConfigurationBytes = 1_048_576;
    private static readonly HashSet<string> TopLevelFields = new(StringComparer.Ordinal) { "schema_version", "roots", "handoff_retrieval" };
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "id", "path", "description", "enabled", "deny" };
    private readonly IWindowsFileSystemAuthority _authority;

    public ConfigurationAuthorityLoader(IWindowsFileSystemAuthority authority) => _authority = authority;

    public ConfigurationLoadResult Load(string explicitPath)
    {
        var configurationOpen = _authority.OpenConfiguration(explicitPath);
        if (!configurationOpen.IsSuccess) return ConfigurationLoadResult.Failure(configurationOpen.ErrorCode!);

        using var configurationHandle = configurationOpen.Handle!;
        var acl = _authority.EvaluateConfigurationAcl(configurationHandle);
        if (!acl.IsTrusted) return ConfigurationLoadResult.Failure(acl.ErrorCode!);

        byte[] content;
        try
        {
            using var stream = new FileStream(configurationHandle, FileAccess.Read, MaximumConfigurationBytes, isAsync: false);
            if (stream.Length is < 1 or > MaximumConfigurationBytes) return ConfigurationLoadResult.Failure("CONFIG_SIZE_INVALID");
            content = new byte[stream.Length];
            stream.ReadExactly(content);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return ConfigurationLoadResult.Failure("CONFIG_READ_FAILED");
        }

        string text;
        try { text = new UTF8Encoding(false, true).GetString(content); }
        catch (DecoderFallbackException) { return ConfigurationLoadResult.Failure("CONFIG_ENCODING_INVALID"); }

        TomlTable? table;
        try { table = TomlSerializer.Deserialize<TomlTable>(text); }
        catch (Exception exception) when (exception is TomlException or InvalidOperationException or ArgumentException)
        {
            return ConfigurationLoadResult.Failure("CONFIG_TOML_MALFORMED");
        }

        if (table is null) return ConfigurationLoadResult.Failure("CONFIG_TOML_MALFORMED");

        if (table.Keys.Any(key => !TopLevelFields.Contains(key)))
            return ConfigurationLoadResult.Failure("CONFIG_UNKNOWN_AUTHORITY_FIELD");

        table.TryGetValue("schema_version", out var rawSchemaVersion);
        var compatibility = SchemaCompatibilityPolicy.Classify(rawSchemaVersion);
        if (compatibility != SchemaCompatibility.Current)
            return ConfigurationLoadResult.Failure($"CONFIG_SCHEMA_{compatibility.ToString().ToUpperInvariant()}");

        if (!table.TryGetValue("roots", out var rawRoots) || rawRoots is not TomlTableArray rootTables)
            return ConfigurationLoadResult.Failure("CONFIG_ROOTS_AMBIGUOUS");

        var roots = new List<RootDefinition>(rootTables.Count);
        foreach (var rootTable in rootTables)
        {
            if (rootTable.Keys.Any(key => !RootFields.Contains(key)))
                return ConfigurationLoadResult.Failure("CONFIG_UNKNOWN_AUTHORITY_FIELD");

            if (!TryRequiredString(rootTable, "id", out var id) || !TryRequiredString(rootTable, "path", out var path) ||
                !rootTable.TryGetValue("enabled", out var rawEnabled) || rawEnabled is not bool enabled)
                return ConfigurationLoadResult.Failure("CONFIG_ROOT_FIELD_AMBIGUOUS");

            if (!IsSafeRootId(id!)) return ConfigurationLoadResult.Failure("CONFIG_ROOT_ID_INVALID");

            string? description = null;
            if (rootTable.TryGetValue("description", out var rawDescription))
            {
                if (rawDescription is not string candidate || !IsSafeDescription(candidate))
                    return ConfigurationLoadResult.Failure("CONFIG_DESCRIPTION_INVALID");
                description = candidate;
            }

            if (!TryDenyPaths(rootTable, out var denyPaths))
                return ConfigurationLoadResult.Failure("CONFIG_DENY_RULE_AMBIGUOUS");

            roots.Add(new RootDefinition(id!, path!, description, enabled, denyPaths!));
        }

        if (roots.GroupBy(root => root.Id, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
            return ConfigurationLoadResult.Failure("CONFIG_DUPLICATE_ROOT_ID");

        // Parse handoff_retrieval section (separately governed capability)
        var handoffConfig = ParseHandoffRetrievalConfig(table);
        if (handoffConfig is null)
            return ConfigurationLoadResult.Failure("HANOFF_RETRIEVAL_CONFIG_INVALID");

        var config = new McpConfig(SchemaCompatibilityPolicy.CurrentSchemaVersion, roots, handoffConfig);
        var activeConfiguration = new ConfigurationAuthorityIdentity(
            configurationOpen.CanonicalPath!, configurationOpen.ObjectIdentity!, SHA256.HashData(content));
        var validatedRoots = new List<ValidatedRoot>();
        var issues = new List<RootValidationIssue>();

        foreach (var root in roots.Where(root => root.Enabled))
        {
            var openedRoot = _authority.OpenRoot(root.Path);
            if (!openedRoot.IsSuccess)
            {
                issues.Add(new RootValidationIssue(root.Id, openedRoot.ErrorCode!));
                continue;
            }

            validatedRoots.Add(new ValidatedRoot(root.Id, root.Description, root.DenyPaths, openedRoot.CanonicalPath!,
                openedRoot.ObjectIdentity!, openedRoot.Handle!));
        }

        // R-01: Structural Local Files non-exposure validation (after roots are validated)
        if (handoffConfig.IsEnabled)
        {
            var exposureError = ValidateNoLocalFilesExposure(validatedRoots, handoffConfig);
            if (exposureError is not null)
                return ConfigurationLoadResult.Failure(exposureError);
        }

        return ConfigurationLoadResult.Success(config,
            new ValidatedRootRegistry(validatedRoots, activeConfiguration), activeConfiguration, issues);
    }
private static HandoffRetrievalConfig? ParseHandoffRetrievalConfig(TomlTable table)
    {
        if (!table.TryGetValue("handoff_retrieval", out var raw))
        {
            // No handoff_retrieval section means disabled
            return HandoffRetrievalConfig.Disabled();
        }

        if (raw is not TomlTable hrTable)
            return null;

        // enabled (required, default false)
        var enabled = false;
        if (hrTable.TryGetValue("enabled", out var rawEnabled) && rawEnabled is bool enabledVal)
            enabled = enabledVal;

        if (!enabled)
            return HandoffRetrievalConfig.Disabled();

        // store_path (required when enabled)
        string? storePath;
        if (!TryRequiredString(hrTable, "store_path", out storePath) || !Path.IsPathFullyQualified(storePath!))
            return null;

        // intended_recipient_reference (required when enabled)
        string? recipientRef;
        if (!TryRequiredString(hrTable, "intended_recipient_reference", out recipientRef))
            return null;

        // hmac_key_base64 (required when enabled)
        byte[] hmacKey;
        if (!hrTable.TryGetValue("hmac_key_base64", out var rawKey) || rawKey is not string keyBase64)
            return null;

        try { hmacKey = Convert.FromBase64String(keyBase64); }
        catch (FormatException) { return null; }

        if (hmacKey.Length == 0)
            return null;

        // max_payload_bytes (optional)
        long maxPayload = HandoffRetrievalConfig.DefaultMaxPayloadBytes;
        if (hrTable.TryGetValue("max_payload_bytes", out var rawMax))
        {
            if (rawMax is long maxVal && maxVal > 0 && maxVal <= 10_000_000)
                maxPayload = maxVal;
            else if (rawMax is not null)
                return null;
        }

        // max_manifest_bytes (optional)
        long maxManifest = HandoffRetrievalConfig.DefaultMaxManifestBytes;
        if (hrTable.TryGetValue("max_manifest_bytes", out var rawMaxManifest))
        {
            if (rawMaxManifest is long maxMVal && maxMVal > 0 && maxMVal <= 1_000_000)
                maxManifest = maxMVal;
            else if (rawMaxManifest is not null)
                return null;
        }

        // Verify store path exists
        if (!Directory.Exists(storePath!))
            return null;

        return new HandoffRetrievalConfig(true, storePath!, recipientRef!, hmacKey, maxPayload, maxManifest);
    }

    private string? ValidateNoLocalFilesExposure(
        IReadOnlyList<ValidatedRoot> validatedRoots, HandoffRetrievalConfig handoffConfig)
    {
        if (!handoffConfig.IsEnabled)
            return null;

        // Open the store through the same opened-object/native filesystem identity
        // machinery used for Local Files roots. This resolves reparse/junction
        // aliases so containment is decided on physical filesystem identity, not on
        // the configured lexical store_path spelling. A store junction whose target
        // physically lies within a Local Files root is therefore detected.
        var openedStore = _authority.OpenStore(handoffConfig.StorePath);
        if (!openedStore.IsSuccess)
            return openedStore.ErrorCode ?? "HANOFF_STORE_PATH_INVALID";

        using var storeHandle = openedStore.Handle!;
        if (!WindowsCanonicalPath.TryParse(openedStore.CanonicalPath!, out var storePath))
            return "HANOFF_STORE_PATH_INVALID";

        foreach (var root in validatedRoots)
        {
            // Root canonical path is the resolved native identity from OpenRoot().
            if (!WindowsCanonicalPath.TryParse(root.CanonicalPath, out var rootPath))
                continue;

            // Physical store must not be within physical root (R01-N1 / R01-N4).
            if (WindowsCanonicalPath.Contains(rootPath!, storePath!))
                return "HANOFF_STORE_EXPOSED_BY_ROOT";

            // Physical root must not be within physical store (R01-N2 / R01-N3).
            // Resolving both sides through native identity means a root junction or
            // a store junction cannot hide the physical containment relationship.
            if (WindowsCanonicalPath.Contains(storePath!, rootPath!))
                return "HANOFF_STORE_EXPOSED_BY_ROOT";
        }

        return null;
    }

    private static bool TryRequiredString(TomlTable table, string key, out string? value)
    {
        value = null;
        if (!table.TryGetValue(key, out var raw) || raw is not string candidate || string.IsNullOrWhiteSpace(candidate)) return false;
        value = candidate;
        return true;
    }

    private static bool IsSafeRootId(string id) => id.Length <= 64 && char.IsAsciiLetterOrDigit(id[0]) &&
        id.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');

    private static bool IsSafeDescription(string value) =>
        value.Length <= 256 &&
        value.All(character => !char.IsControl(character)) &&
        !value.Contains(":\\", StringComparison.Ordinal) &&
        !value.Contains("\\\\", StringComparison.Ordinal);

    private static bool TryDenyPaths(TomlTable table, out IReadOnlyList<string>? denyPaths)
    {
        denyPaths = Array.Empty<string>();
        if (!table.TryGetValue("deny", out var raw)) return true;
        if (raw is not TomlArray array) return false;

        var parsed = new List<string>(array.Count);
        foreach (var item in array)
        {
            if (item is not string candidate ||
                !WindowsRelativePath.TryParse(candidate, out var relativePath) ||
                parsed.Contains(relativePath!.Value, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }

            parsed.Add(relativePath.Value);
        }

        denyPaths = parsed;
        return true;
    }
}

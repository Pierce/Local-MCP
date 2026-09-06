using System.Security.Cryptography;
using System.Text;
using LocalMcp.Roots;
using LocalMcp.Security;
using Tomlyn;
using Tomlyn.Model;

namespace LocalMcp.Configuration;

internal sealed class ConfigurationAuthorityLoader
{
    private const int MaximumConfigurationBytes = 1_048_576;
    private static readonly HashSet<string> TopLevelFields = new(StringComparer.Ordinal) { "schema_version", "roots" };
    private static readonly HashSet<string> RootFields = new(StringComparer.Ordinal) { "id", "path", "description", "enabled" };
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

            roots.Add(new RootDefinition(id!, path!, description, enabled));
        }

        if (roots.GroupBy(root => root.Id, StringComparer.OrdinalIgnoreCase).Any(group => group.Count() > 1))
            return ConfigurationLoadResult.Failure("CONFIG_DUPLICATE_ROOT_ID");

        var config = new McpConfig(SchemaCompatibilityPolicy.CurrentSchemaVersion, roots);
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

            validatedRoots.Add(new ValidatedRoot(root.Id, root.Description, openedRoot.CanonicalPath!,
                openedRoot.ObjectIdentity!, openedRoot.Handle!));
        }

        return ConfigurationLoadResult.Success(config,
            new ValidatedRootRegistry(validatedRoots, activeConfiguration), activeConfiguration, issues);
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
}

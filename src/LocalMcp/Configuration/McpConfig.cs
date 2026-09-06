namespace LocalMcp.Configuration;

/// <summary>The only current, explicitly governed Local Files configuration schema.</summary>
public sealed record McpConfig(int SchemaVersion, IReadOnlyList<RootDefinition> Roots);

/// <summary>A root declaration as parsed from the one active authority file.</summary>
public sealed record RootDefinition(
    string Id,
    string Path,
    string? Description,
    bool Enabled);

public enum SchemaCompatibility
{
    Current,
    Unsupported,
    Future,
    Ambiguous,
}

public static class SchemaCompatibilityPolicy
{
    public const int CurrentSchemaVersion = 1;

    public static SchemaCompatibility Classify(object? value) => value switch
    {
        long version when version == CurrentSchemaVersion => SchemaCompatibility.Current,
        long version when version > CurrentSchemaVersion => SchemaCompatibility.Future,
        long => SchemaCompatibility.Unsupported,
        _ => SchemaCompatibility.Ambiguous,
    };
}

using LocalMcp.Roots;

namespace LocalMcp.Configuration;

public sealed record ConfigurationLoadResult(
    McpConfig? Configuration,
    ValidatedRootRegistry? Registry,
    ConfigurationAuthorityIdentity? ActiveConfiguration,
    IReadOnlyList<RootValidationIssue> RootIssues,
    string? FatalErrorCode)
{
    public bool IsSuccess => FatalErrorCode is null && Configuration is not null && Registry is not null && ActiveConfiguration is not null;

    public static ConfigurationLoadResult Failure(string code) =>
        new(null, null, null, Array.Empty<RootValidationIssue>(), code);

    public static ConfigurationLoadResult Success(
        McpConfig configuration,
        ValidatedRootRegistry registry,
        ConfigurationAuthorityIdentity activeConfiguration,
        IReadOnlyList<RootValidationIssue> rootIssues) =>
        new(configuration, registry, activeConfiguration, rootIssues, null);
}

public sealed record ConfigurationAuthorityIdentity(
    string CanonicalPath,
    FileObjectIdentity ObjectIdentity,
    byte[] ContentSha256);

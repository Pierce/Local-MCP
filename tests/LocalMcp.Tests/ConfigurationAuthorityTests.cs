using LocalMcp.Security;

namespace LocalMcp.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class ConfigurationAuthorityTests
{
    [Fact]
    public void ExplicitConfigurationPath_IsRequired_AndNoAlternateArgumentsAreAccepted()
    {
        Assert.False(LocalMcp.Configuration.StartupArguments.Parse([]).IsSuccess);
        Assert.False(LocalMcp.Configuration.StartupArguments.Parse(["authority.toml"]).IsSuccess);
        Assert.False(LocalMcp.Configuration.StartupArguments.Parse(["--config", "a", "--config", "b"]).IsSuccess);
        Assert.True(LocalMcp.Configuration.StartupArguments.Parse(["--config", @"C:\authority.toml"]).IsSuccess);
    }

    [Fact]
    public void MissingConfiguration_FailsClosed_WithoutFallbackDiscovery()
    {
        using var workspace = new AuthorityTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.BasePath, "local-mcp.toml"),
            AuthorityTestWorkspace.CurrentConfiguration(("fallback", workspace.ValidRootPath, null, true)));
        var result = workspace.Load(Path.Combine(workspace.BasePath, "explicit-missing.toml"));
        Assert.False(result.IsSuccess);
        Assert.Equal("CONFIG_NOT_FOUND", result.FatalErrorCode);
    }

    [Fact]
    public void MalformedToml_IsFatal()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration("schema_version = [");
        var result = workspace.Load();
        Assert.False(result.IsSuccess);
        Assert.Equal("CONFIG_TOML_MALFORMED", result.FatalErrorCode);
    }

    [Theory]
    [InlineData("schema_version = 0\nroots = []", "CONFIG_SCHEMA_UNSUPPORTED")]
    [InlineData("schema_version = 2\nroots = []", "CONFIG_SCHEMA_FUTURE")]
    [InlineData("roots = []", "CONFIG_SCHEMA_AMBIGUOUS")]
    [InlineData("schema_version = 1.0\nroots = []", "CONFIG_SCHEMA_AMBIGUOUS")]
    public void UnsupportedFutureAndAmbiguousSchemas_AreFatal(string toml, string expected)
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration(toml);
        var result = workspace.Load();
        Assert.False(result.IsSuccess);
        Assert.Equal(expected, result.FatalErrorCode);
    }

    [Fact]
    public void DuplicateRootIds_AreFatal_CaseInsensitively()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("Project", workspace.ValidRootPath, null, true),
            ("project", workspace.ValidRootPath, null, true)));
        var result = workspace.Load();
        Assert.False(result.IsSuccess);
        Assert.Equal("CONFIG_DUPLICATE_ROOT_ID", result.FatalErrorCode);
    }

    [Theory]
    [InlineData("unexpected = true", "CONFIG_UNKNOWN_AUTHORITY_FIELD")]
    [InlineData("", "CONFIG_ROOT_FIELD_AMBIGUOUS")]
    public void UnknownAuthorityFields_AndAuthorityEnlargingDefaults_AreFatal(string rootTail, string expected)
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid = 'root'\npath = '{workspace.ValidRootPath}'\n{rootTail}\n");
        var result = workspace.Load();
        Assert.False(result.IsSuccess);
        Assert.Equal(expected, result.FatalErrorCode);
    }

    [Fact]
    public void TopLevelUnknownAuthorityField_IsFatal()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\nauthority_profile = 'other'\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\n");
        Assert.Equal("CONFIG_UNKNOWN_AUTHORITY_FIELD", workspace.Load().FatalErrorCode);
    }

    [Fact]
    public void HostPathInClientVisibleDescription_IsRejected()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("root", workspace.ValidRootPath, workspace.ValidRootPath, true)));
        Assert.Equal("CONFIG_DESCRIPTION_INVALID", workspace.Load().FatalErrorCode);
    }

    [Fact]
    public void ActiveConfiguration_IsNotRewritten_AndIsRegisteredAsDenied()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        var before = workspace.HashConfiguration();
        var result = workspace.Load();
        using var registry = result.Registry;
        var after = workspace.HashConfiguration();

        Assert.True(result.IsSuccess, result.FatalErrorCode);
        Assert.Equal(before, after);
        Assert.Equal(result.ActiveConfiguration, registry!.DeniedConfiguration);
        Assert.Equal(before, registry.DeniedConfiguration.ContentSha256);
    }

    [Fact]
    public void RootLocalFailures_DoNotDisableOtherRoots_AndDoNotTriggerDiscovery()
    {
        using var workspace = new AuthorityTestWorkspace();
        var missing = Path.Combine(workspace.BasePath, "missing");
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("valid", workspace.ValidRootPath, "Visible", true),
            ("missing", missing, "Must be filtered", true),
            ("disabled", Path.Combine(workspace.BasePath, "also-missing"), null, false)));
        var result = workspace.Load();
        using var registry = result.Registry;

        Assert.True(result.IsSuccess, result.FatalErrorCode);
        Assert.Single(registry!.Roots);
        Assert.Equal("valid", registry.Roots.Single().Id);
        Assert.Single(result.RootIssues);
        Assert.Equal("missing", result.RootIssues.Single().RootId);
        Assert.Equal("ROOT_NOT_FOUND", result.RootIssues.Single().ErrorCode);
    }

    [Fact]
    public void InaccessibleRoot_IsAStableRootLocalFailure()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        var result = workspace.Load(authority: new RootFailureAuthority(new WindowsFileSystemAuthority(), "ROOT_INACCESSIBLE"));
        using var registry = result.Registry;
        Assert.True(result.IsSuccess);
        Assert.Empty(registry!.Roots);
        Assert.Equal("ROOT_INACCESSIBLE", result.RootIssues.Single().ErrorCode);
    }

    [Fact]
    public void NonDirectoryRoot_IsFilteredAsUnsupported()
    {
        using var workspace = new AuthorityTestWorkspace();
        var file = Path.Combine(workspace.BasePath, "not-a-root.txt");
        File.WriteAllText(file, "data");
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(("file", file, null, true)));
        var result = workspace.Load();
        using var registry = result.Registry;
        Assert.True(result.IsSuccess);
        Assert.Empty(registry!.Roots);
        Assert.Equal("ROOT_TARGET_UNSUPPORTED", result.RootIssues.Single().ErrorCode);
    }

    [Fact]
    public void AdditiveRootDenyPaths_AreAcceptedAndPreserved()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\ndeny=['private-area', 'nested\\restricted']\n");
        var result = workspace.Load();
        using var registry = result.Registry;

        Assert.True(result.IsSuccess, result.FatalErrorCode);
        Assert.Equal(new[] { "private-area", @"nested\restricted" }, registry!.Roots.Single().DenyPaths);
    }

    [Theory]
    [InlineData("deny = 'private-area'")]
    [InlineData("deny = ['..\\outside']")]
    [InlineData("deny = ['C:\\outside']")]
    [InlineData("deny = ['private*']")]
    [InlineData("deny = ['private', 'PRIVATE']")]
    public void AmbiguousOrNonLiteralDenyConfiguration_FailsClosed(string deny)
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\n{deny}\n");

        Assert.Equal("CONFIG_DENY_RULE_AMBIGUOUS", workspace.Load().FatalErrorCode);
    }

    [Theory]
    [InlineData("allow_sensitive = true")]
    [InlineData("disable_builtin_denies = true")]
    [InlineData("allow = ['.ssh']")]
    public void AttemptsToWeakenBuiltInPolicy_AreUnknownAuthorityFieldsAndFatal(string overrideField)
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\n{overrideField}\n");

        Assert.Equal("CONFIG_UNKNOWN_AUTHORITY_FIELD", workspace.Load().FatalErrorCode);
    }

    private sealed class RootFailureAuthority(IWindowsFileSystemAuthority inner, string errorCode) : IWindowsFileSystemAuthority
    {
        public AuthorityOpenResult OpenConfiguration(string explicitPath) => inner.OpenConfiguration(explicitPath);
        public AuthorityOpenResult OpenRoot(string configuredPath) => AuthorityOpenResult.Failure(errorCode);
        public AuthorityOpenResult OpenStore(string configuredPath) => AuthorityOpenResult.Failure(errorCode);
        public AclEvaluationResult EvaluateConfigurationAcl(Microsoft.Win32.SafeHandles.SafeFileHandle handle) => inner.EvaluateConfigurationAcl(handle);
    }
}

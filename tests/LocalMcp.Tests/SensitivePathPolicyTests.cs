using LocalMcp.Security;

namespace LocalMcp.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class SensitivePathPolicyTests
{
    [Theory]
    [InlineData(".ssh")]
    [InlineData("folder", ".SSH", "config")]
    [InlineData(".git", "objects", "01")]
    [InlineData(".env")]
    [InlineData(".ENV.production")]
    [InlineData("server.pem")]
    [InlineData("private.KEY")]
    [InlineData("id_rsa")]
    [InlineData("id_ed25519")]
    [InlineData("credentials.json")]
    [InlineData("production-secrets.json")]
    [InlineData("nested", "secrets")]
    [InlineData("tokens.db")]
    [InlineData("user data", "Default")]
    [InlineData("Login Data")]
    [InlineData("cookies.sqlite")]
    public void GovernedBuiltInClasses_AreDenied(params string[] components)
    {
        Assert.True(SensitivePathPolicy.MatchesBuiltIn(components));
    }

    [Theory]
    [InlineData(".gitignore")]
    [InlineData("environment.txt")]
    [InlineData("tokenizer.cs")]
    [InlineData("secretary.txt")]
    [InlineData("public-key.pub")]
    [InlineData("src", "allowed.txt")]
    public void AllowedPositiveControls_AreNotOvermatched(params string[] components)
    {
        Assert.False(SensitivePathPolicy.MatchesBuiltIn(components));
    }

    [Fact]
    public void ConfiguredDeny_IsCaseInsensitiveLiteralPrefixAndOnlyNarrows()
    {
        var configured = new[] { @"private-area", @"nested\restricted" };

        Assert.True(SensitivePathPolicy.MatchesConfigured(configured, new[] { "PRIVATE-AREA", "child.txt" }));
        Assert.True(SensitivePathPolicy.MatchesConfigured(configured, new[] { "nested", "restricted", "file.txt" }));
        Assert.False(SensitivePathPolicy.MatchesConfigured(configured, new[] { "nested", "allowed.txt" }));
        Assert.False(SensitivePathPolicy.MatchesConfigured(Array.Empty<string>(), new[] { ".ssh" }));
        Assert.True(SensitivePathPolicy.MatchesBuiltIn(new[] { ".ssh" }));
    }

    [Fact]
    public void LexicalPolicy_DeniesBuiltInAndConfiguredNamespacesWithoutTargetFacts()
    {
        using var workspace = new ContainmentTestWorkspace();
        var root = workspace.Registry.Roots.Single();
        var configuredRoot = new LocalMcp.Roots.ValidatedRoot(root.Id, root.Description, ["configured-private"],
            root.CanonicalPath, root.ObjectIdentity, root.Handle);
        var policy = new SensitivePathPolicy();

        Assert.True(policy.IsLexicallyDenied(configuredRoot, @".ENV.missing"));
        Assert.True(policy.IsLexicallyDenied(configuredRoot, @"CONFIGURED-PRIVATE\missing.txt"));
        Assert.False(policy.IsLexicallyDenied(configuredRoot, "ordinary-missing.txt"));
    }
}

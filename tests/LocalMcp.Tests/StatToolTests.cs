using System.Text.Json;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class StatToolTests
{
    [Fact]
    public void AllowedFileAndDirectory_ReturnOnlyGovernedMetadata()
    {
        using var workspace = new AuthorityTestWorkspace();
        var file = Path.Combine(workspace.ValidRootPath, "allowed.txt");
        var directory = Path.Combine(workspace.ValidRootPath, "allowed-directory");
        File.WriteAllText(file, "hello");
        Directory.CreateDirectory(directory);
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var tool = new StatTool(registry!);

        var fileResult = tool.Stat("valid", "allowed.txt");
        var directoryResult = tool.Stat("valid", "allowed-directory");
        var json = JsonSerializer.Serialize(new[] { fileResult, directoryResult });

        Assert.Null(fileResult.ErrorCode);
        Assert.Equal("file", fileResult.Type);
        Assert.Equal(5, fileResult.Size);
        Assert.False(fileResult.ReadableAsText);
        Assert.NotNull(fileResult.ModifiedTime);
        Assert.Null(directoryResult.ErrorCode);
        Assert.Equal("directory", directoryResult.Type);
        Assert.Null(directoryResult.Size);
        Assert.DoesNotContain(workspace.BasePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("canonical", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("file_id", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("owner", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("acl", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("reparse", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(@".ssh\config")]
    [InlineData(@".git\config")]
    [InlineData(".env")]
    [InlineData(".env.production")]
    [InlineData("server.pem")]
    [InlineData("id_ed25519")]
    [InlineData("credentials.json")]
    [InlineData(@"secrets\value.txt")]
    [InlineData(@"token-store\tokens.db")]
    public void DirectStatOfBuiltInDeniedObject_IsGenericAndDisclosureSafe(string relativePath)
    {
        using var workspace = new AuthorityTestWorkspace();
        CreateFile(workspace.ValidRootPath, relativePath);
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;

        var response = new StatTool(registry!).Stat("valid", relativePath);
        var json = JsonSerializer.Serialize(response);

        Assert.Equal("ACCESS_DENIED", response.ErrorCode);
        Assert.DoesNotContain(relativePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(workspace.BasePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("{\"error_code\":\"ACCESS_DENIED\"}", json);
    }

    [Fact]
    public void ConfiguredDenyNarrowsAccess_WhileNearbyPositiveControlRemainsUsable()
    {
        using var workspace = new AuthorityTestWorkspace();
        CreateFile(workspace.ValidRootPath, @"private-area\denied.txt");
        CreateFile(workspace.ValidRootPath, @"public-area\allowed.txt");
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\ndeny=['private-area']\n");
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var tool = new StatTool(registry!);

        Assert.Equal("ACCESS_DENIED", tool.Stat("root", @"private-area\denied.txt").ErrorCode);
        Assert.Null(tool.Stat("root", @"public-area\allowed.txt").ErrorCode);
    }

    [Fact]
    public void ActiveConfigurationInsideRoot_IsAlwaysDeniedByObjectIdentity()
    {
        using var workspace = new AuthorityTestWorkspace(configurationInsideRoot: true);
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;

        var response = new StatTool(registry!).Stat("valid", "authority.toml");

        Assert.Equal("ACCESS_DENIED", response.ErrorCode);
        Assert.Null(response.RelativePath);
    }

    [Fact]
    public void InvalidAndMissingObjects_ReturnStableSafeCategories()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var tool = new StatTool(registry!);

        Assert.Equal("PATH_INVALID", tool.Stat("valid", @"..\outside").ErrorCode);
        Assert.Equal("NOT_FOUND", tool.Stat("valid", "missing.txt").ErrorCode);
        Assert.Equal("ROOT_NOT_FOUND", tool.Stat("unknown", "missing.txt").ErrorCode);
    }

    [Fact]
    public void BuiltInSensitiveTarget_PresentAndAbsentHaveIdenticalGenericDenial()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var tool = new StatTool(registry!);

        var absent = JsonSerializer.Serialize(tool.Stat("valid", ".env"));
        File.WriteAllText(Path.Combine(workspace.ValidRootPath, ".env"), "sensitive fixture");
        var present = JsonSerializer.Serialize(tool.Stat("valid", ".env"));

        Assert.Equal("{\"error_code\":\"ACCESS_DENIED\"}", absent);
        Assert.Equal(absent, present);
    }

    [Fact]
    public void ConfiguredDenyTarget_PresentAndAbsentHaveIdenticalGenericDenial()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\ndeny=['configured-private']\n");
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var tool = new StatTool(registry!);
        const string relativePath = @"configured-private\target.txt";

        var absent = JsonSerializer.Serialize(tool.Stat("root", relativePath));
        CreateFile(workspace.ValidRootPath, relativePath);
        var present = JsonSerializer.Serialize(tool.Stat("root", relativePath));

        Assert.Equal("{\"error_code\":\"ACCESS_DENIED\"}", absent);
        Assert.Equal(absent, present);
    }

    [Fact]
    public void CanonicalInRootJunctionAliasToSensitiveDirectory_IsDenied()
    {
        using var workspace = new AuthorityTestWorkspace();
        var sensitive = Path.Combine(workspace.ValidRootPath, ".ssh");
        Directory.CreateDirectory(sensitive);
        File.WriteAllText(Path.Combine(sensitive, "config"), "not returned");
        WindowsLinkTestSupport.CreateJunction(Path.Combine(workspace.ValidRootPath, "safe-looking-alias"), sensitive);
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;

        var response = new StatTool(registry!).Stat("valid", @"safe-looking-alias\config");

        Assert.Equal("ACCESS_DENIED", response.ErrorCode);
    }

    [Fact]
    public void CanonicalInRootJunctionAliasCannotBypassConfiguredDeny()
    {
        using var workspace = new AuthorityTestWorkspace();
        var denied = Path.Combine(workspace.ValidRootPath, "configured-private");
        Directory.CreateDirectory(denied);
        File.WriteAllText(Path.Combine(denied, "file.txt"), "not returned");
        WindowsLinkTestSupport.CreateJunction(Path.Combine(workspace.ValidRootPath, "allowed-looking-alias"), denied);
        workspace.WriteConfiguration($"schema_version = 1\n[[roots]]\nid='root'\npath='{workspace.ValidRootPath}'\nenabled=true\ndeny=['configured-private']\n");
        var loaded = workspace.Load();
        using var registry = loaded.Registry;

        var response = new StatTool(registry!).Stat("root", @"allowed-looking-alias\file.txt");

        Assert.Equal("ACCESS_DENIED", response.ErrorCode);
    }

    [WindowsShortNameFact]
    public void ShortNameAliasToSensitiveFile_IsDenied()
    {
        using var workspace = new AuthorityTestWorkspace();
        var sensitive = Path.Combine(workspace.ValidRootPath, "private-key-material-for-alias.pem");
        File.WriteAllText(sensitive, "not returned");
        Assert.True(WindowsLinkTestSupport.TryGetShortPath(sensitive, out var shortPath));
        workspace.WriteConfiguration();
        var loaded = workspace.Load();
        using var registry = loaded.Registry;

        var response = new StatTool(registry!).Stat("valid", Path.GetFileName(shortPath!));

        Assert.Equal("ACCESS_DENIED", response.ErrorCode);
    }

    [Fact]
    public void NoFileLogDestinationExistsSoNoGovernedLogObjectCanBeExposed()
    {
        var source = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Diagnostics", "ProtocolSafeLogger.cs"));
        Assert.Contains("Console.Error", source);
        Assert.DoesNotContain("File.", source, StringComparison.Ordinal);
        Assert.DoesNotContain("FileStream", source, StringComparison.Ordinal);
    }

    [Fact]
    public void StatImplementationUsesMetadataOnlyAndContainsNoContentReadPath()
    {
        var source = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Tools", "StatTool.cs"));
        Assert.Contains("GetMetadata(target.Handle", source);
        Assert.DoesNotContain("OpenReadOnly", source, StringComparison.Ordinal);
        Assert.DoesNotContain("FileStream", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ReadAll", source, StringComparison.Ordinal);
        Assert.DoesNotContain("ReadExactly", source, StringComparison.Ordinal);
    }

    private static void CreateFile(string root, string relativePath)
    {
        var fullPath = Path.Combine(root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, "fixture");
    }
}

using System.Security.Cryptography;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using LocalMcp.Configuration;
using LocalMcp.Roots;
using LocalMcp.Security;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
public class ListDirectorySecurityTests
{
    [Fact]
    public void BuiltInDeniedChildIsOmittedWithoutPlaceholderOrMetadata()
    {
        using var workspace = new ContainmentTestWorkspace();
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, ".git"));
        File.WriteAllText(Path.Combine(workspace.RootPath, "visible"), "x");
        using var cursors = new DirectoryCursorProtector();

        var result = Tool(workspace, cursors).ListDirectory("root", "");
        var json = JsonSerializer.Serialize(result);

        Assert.Single(result.Entries!);
        Assert.Equal("visible", result.Entries![0].Name);
        Assert.DoesNotContain(".git", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("denied", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ConfiguredDeniedChildIsOmitted()
    {
        using var workspace = new AuthorityTestWorkspace();
        Directory.CreateDirectory(Path.Combine(workspace.ValidRootPath, "private"));
        File.WriteAllText(Path.Combine(workspace.ValidRootPath, "public"), "x");
        workspace.WriteConfiguration(Config(workspace.ValidRootPath, "deny = ['private']"));
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        using var cursors = new DirectoryCursorProtector();

        var result = new ListDirectoryTool(registry!, cursors).ListDirectory("root", "");

        Assert.Equal(["public"], result.Entries!.Select(entry => entry.Name));
    }

    [Fact]
    public void ActiveConfigurationInsideRootIsOmittedByObjectIdentity()
    {
        using var workspace = new AuthorityTestWorkspace(configurationInsideRoot: true);
        File.WriteAllText(Path.Combine(workspace.ValidRootPath, "visible"), "x");
        workspace.WriteConfiguration(Config(workspace.ValidRootPath));
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        using var cursors = new DirectoryCursorProtector();

        var result = new ListDirectoryTool(registry!, cursors).ListDirectory("root", "");

        Assert.Equal(["visible"], result.Entries!.Select(entry => entry.Name));
    }

    [Fact]
    public void DeniedChildrenDoNotCreateVisiblePaginationGapsOrCounts()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "a"), "x");
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, ".git"));
        File.WriteAllText(Path.Combine(workspace.RootPath, "b"), "x");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);

        var first = tool.ListDirectory("root", "", 1);
        var second = tool.ListDirectory("root", "", cursor: first.ContinuationToken);

        Assert.Equal(["a"], first.Entries!.Select(entry => entry.Name));
        Assert.Equal(["b"], second.Entries!.Select(entry => entry.Name));
        Assert.True(first.Truncated);
        Assert.False(second.Truncated);
        Assert.DoesNotContain("count", JsonSerializer.Serialize(first), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InRootAliasToBuiltInDeniedDirectoryIsOmitted()
    {
        using var workspace = new ContainmentTestWorkspace();
        var denied = Directory.CreateDirectory(Path.Combine(workspace.RootPath, ".git")).FullName;
        WindowsLinkTestSupport.CreateJunction(Path.Combine(workspace.RootPath, "innocent-alias"), denied);
        using var cursors = new DirectoryCursorProtector();

        Assert.Empty(Tool(workspace, cursors).ListDirectory("root", "").Entries!);
    }

    [Fact]
    public void OutsideRootJunctionIsOmittedAndCannotBeListed()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.OutsidePath, "outside-secret"), "secret");
        WindowsLinkTestSupport.CreateJunction(Path.Combine(workspace.RootPath, "escape"), workspace.OutsidePath);
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);

        Assert.Empty(tool.ListDirectory("root", "").Entries!);
        Assert.Equal("PATH_OUTSIDE_ROOT", tool.ListDirectory("root", "escape").ErrorCode);
    }

    [Fact]
    public void SupportedInRootJunctionRemainsContainedAndCanBeListedExplicitly()
    {
        using var workspace = new ContainmentTestWorkspace();
        var target = Directory.CreateDirectory(Path.Combine(workspace.RootPath, "target")).FullName;
        File.WriteAllText(Path.Combine(target, "child"), "x");
        WindowsLinkTestSupport.CreateJunction(Path.Combine(workspace.RootPath, "alias"), target);
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);

        Assert.Contains(tool.ListDirectory("root", "").Entries!, entry => entry.Name == "alias");
        Assert.Equal(@"alias\child", tool.ListDirectory("root", "alias").Entries!.Single().RelativePath);
    }

    [WindowsSymlinkFact]
    public void OutsideRootSymbolicLinkIsOmittedWhenFixtureIsAvailable()
    {
        using var workspace = new ContainmentTestWorkspace();
        Directory.CreateSymbolicLink(Path.Combine(workspace.RootPath, "escape-link"), workspace.OutsidePath);
        using var cursors = new DirectoryCursorProtector();
        Assert.Empty(Tool(workspace, cursors).ListDirectory("root", "").Entries!);
    }

    [Fact]
    public void ForgedCursorReturnsOnlyInvalidCursor()
    {
        using var workspace = PopulatedWorkspace("a", "b");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var first = tool.ListDirectory("root", "", 1);
        var chars = first.ContinuationToken!.ToCharArray();
        chars[^2] = chars[^2] == 'A' ? 'B' : 'A';

        var result = tool.ListDirectory("root", "", 1, new string(chars));

        Assert.Equal("INVALID_CURSOR", result.ErrorCode);
        Assert.Null(result.Entries);
    }

    [Fact]
    public void CursorCopiedAcrossRootsIsRejected()
    {
        using var workspace = new AuthorityTestWorkspace();
        var secondRoot = Directory.CreateDirectory(Path.Combine(workspace.BasePath, "second-root")).FullName;
        foreach (var root in new[] { workspace.ValidRootPath, secondRoot })
        {
            File.WriteAllText(Path.Combine(root, "a"), "x");
            File.WriteAllText(Path.Combine(root, "b"), "x");
        }
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("one", workspace.ValidRootPath, null, true), ("two", secondRoot, null, true)));
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        using var cursors = new DirectoryCursorProtector();
        var tool = new ListDirectoryTool(registry!, cursors);
        var cursor = tool.ListDirectory("one", "", 1).ContinuationToken;

        Assert.Equal("INVALID_CURSOR", tool.ListDirectory("two", "", 1, cursor).ErrorCode);
    }

    [Fact]
    public void CursorCopiedAcrossLogicalDirectoriesIsRejectedEvenForSameProcess()
    {
        using var workspace = new ContainmentTestWorkspace();
        foreach (var name in new[] { "one", "two" })
        {
            var path = Directory.CreateDirectory(Path.Combine(workspace.RootPath, name)).FullName;
            File.WriteAllText(Path.Combine(path, "a"), "x");
            File.WriteAllText(Path.Combine(path, "b"), "x");
        }
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var cursor = tool.ListDirectory("root", "one", 1).ContinuationToken;

        Assert.Equal("INVALID_CURSOR", tool.ListDirectory("root", "two", 1, cursor).ErrorCode);
    }

    [Fact]
    public void CursorWithDifferentPageContextIsRejected()
    {
        using var workspace = PopulatedWorkspace("a", "b", "c");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var cursor = tool.ListDirectory("root", "", 1).ContinuationToken;

        Assert.Equal("INVALID_CURSOR", tool.ListDirectory("root", "", 2, cursor).ErrorCode);
    }

    [Fact]
    public void CursorWithDifferentOrderingVersionIsRejected()
    {
        using var workspace = PopulatedWorkspace("a", "b");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var cursor = tool.ListDirectory("root", "", 1).ContinuationToken!;
        Assert.True(cursors.TryUnprotect(cursor, out var state));
        var changed = cursors.Protect(state! with { OrderingVersion = 999 });

        Assert.Equal("INVALID_CURSOR", tool.ListDirectory("root", "", 1, changed).ErrorCode);
    }

    [Fact]
    public void CursorWithDifferentConfigurationGenerationIsRejected()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "a"), "x");
        File.WriteAllText(Path.Combine(workspace.RootPath, "b"), "x");
        using var cursors = new DirectoryCursorProtector();
        var firstTool = Tool(workspace, cursors);
        var cursor = firstTool.ListDirectory("root", "", 1).ContinuationToken;
        using var secondRegistry = OpenRegistry(workspace.RootPath, 7);
        var secondTool = new ListDirectoryTool(secondRegistry, cursors);

        Assert.Equal("INVALID_CURSOR", secondTool.ListDirectory("root", "", 1, cursor).ErrorCode);
    }

    [Fact]
    public void CursorReplayAfterProcessRestartIsRejected()
    {
        using var workspace = PopulatedWorkspace("a", "b");
        string cursor;
        using (var firstProcessAuthority = new DirectoryCursorProtector())
            cursor = Tool(workspace, firstProcessAuthority).ListDirectory("root", "", 1).ContinuationToken!;
        using var restartedProcessAuthority = new DirectoryCursorProtector();

        Assert.Equal("INVALID_CURSOR", Tool(workspace, restartedProcessAuthority)
            .ListDirectory("root", "", 1, cursor).ErrorCode);
    }

    [Fact]
    public void MalformedCursorDoesNotLeakTokenOrHostDetails()
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        var supplied = "not-a-valid-cursor-secret";
        var result = Tool(workspace, cursors).ListDirectory("root", "", cursor: supplied);
        var json = JsonSerializer.Serialize(result);

        Assert.Equal("INVALID_CURSOR", result.ErrorCode);
        Assert.DoesNotContain(supplied, json);
        Assert.DoesNotContain(workspace.RootPath, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CursorTransportDoesNotExposeResumeNameHostPathOrNativeIds()
    {
        using var workspace = PopulatedWorkspace("distinct-resume-name", "z");
        using var cursors = new DirectoryCursorProtector();
        var token = Tool(workspace, cursors).ListDirectory("root", "", 1).ContinuationToken!;

        Assert.DoesNotContain("distinct-resume-name", token, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(workspace.RootPath, token, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("FileId", token, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ContinuationReenumeratesAndRefiltersCurrentDirectory()
    {
        using var workspace = PopulatedWorkspace("a", "c");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var first = tool.ListDirectory("root", "", 1);
        File.WriteAllText(Path.Combine(workspace.RootPath, "b"), "x");
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, ".git"));

        var second = tool.ListDirectory("root", "", 1, first.ContinuationToken);

        Assert.Equal(["b"], second.Entries!.Select(entry => entry.Name));
        Assert.DoesNotContain(second.Entries!, entry => entry.Name == ".git");
    }

    [Fact]
    public void DirectoryIdentityChangeBetweenPagesRejectsOldCursor()
    {
        using var workspace = new ContainmentTestWorkspace();
        var page = Directory.CreateDirectory(Path.Combine(workspace.RootPath, "page")).FullName;
        File.WriteAllText(Path.Combine(page, "a"), "x");
        File.WriteAllText(Path.Combine(page, "b"), "x");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var cursor = tool.ListDirectory("root", "page", 1).ContinuationToken;
        Directory.Delete(page, recursive: true);
        Directory.CreateDirectory(page);
        File.WriteAllText(Path.Combine(page, "b"), "x");

        Assert.Equal("INVALID_CURSOR", tool.ListDirectory("root", "page", 1, cursor).ErrorCode);
    }

    [Fact]
    public void DeletedBoundaryUsesLogicalOrderingAndNeverReturnsDeniedEntries()
    {
        using var workspace = PopulatedWorkspace("a", "b", "c");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);
        var cursor = tool.ListDirectory("root", "", 1).ContinuationToken;
        File.Delete(Path.Combine(workspace.RootPath, "a"));
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, ".git"));

        var next = tool.ListDirectory("root", "", 1, cursor);

        Assert.Equal(["b"], next.Entries!.Select(entry => entry.Name));
    }

    [Fact]
    public void SourceBoundaryAddsNoContentReadSearchNetworkOrMutationAuthority()
    {
        var source = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Tools", "ListDirectoryTool.cs"));
        Assert.DoesNotContain("OpenReadOnly", source);
        Assert.DoesNotContain("FileStream", source);
        Assert.DoesNotContain("ReadAll", source);
        Assert.DoesNotContain("HttpListener", source);
        Assert.DoesNotContain("Process.Start", source);
        Assert.DoesNotContain("Delete(", source);
        Assert.DoesNotContain("WriteAll", source);
    }

    [Fact]
    public void ProcessLocalCursorAuthorityIsCreatedAtStartupAndNeverPersisted()
    {
        var hosting = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Hosting", "LocalMcpApplication.cs"));
        var cursor = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Tools", "DirectoryCursorProtector.cs"));
        Assert.Contains("AddSingleton(new DirectoryCursorProtector())", hosting);
        Assert.Contains("RandomNumberGenerator.GetBytes(32)", cursor);
        Assert.DoesNotContain("WriteAll", cursor);
        Assert.DoesNotContain("FileStream", cursor);
        Assert.DoesNotContain("Console", cursor);
    }

    private static ListDirectoryTool Tool(ContainmentTestWorkspace workspace, DirectoryCursorProtector cursors) =>
        new(workspace.Registry, cursors, workspace.Native, new WindowsDirectoryEntryEnumerator());

    private static ContainmentTestWorkspace PopulatedWorkspace(params string[] files)
    {
        var workspace = new ContainmentTestWorkspace();
        foreach (var file in files) File.WriteAllText(Path.Combine(workspace.RootPath, file), file);
        return workspace;
    }

    private static string Config(string rootPath, string? extra = null) => $"""
        schema_version = 1

        [[roots]]
        id = 'root'
        path = '{rootPath}'
        enabled = true
        {extra}
        """;

    private static ValidatedRootRegistry OpenRegistry(string path, byte generation)
    {
        var opened = new WindowsFileSystemAuthority().OpenRoot(path);
        Assert.True(opened.IsSuccess, opened.ErrorCode);
        var root = new ValidatedRoot("root", null, [], opened.CanonicalPath!, opened.ObjectIdentity!, opened.Handle!);
        return new ValidatedRootRegistry([root], new ConfigurationAuthorityIdentity(
            opened.CanonicalPath!, new FileObjectIdentity(ulong.MaxValue, "config"), Enumerable.Repeat(generation, 32).ToArray()));
    }
}

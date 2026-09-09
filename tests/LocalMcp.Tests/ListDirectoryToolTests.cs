using System.Text.Json;
using System.Runtime.Versioning;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
public class ListDirectoryToolTests
{
    [Fact]
    public void EmptyPermittedDirectory_ReturnsCompleteEmptyPage()
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        var result = Tool(workspace, cursors).ListDirectory("root", "");

        Assert.Empty(result.Entries!);
        Assert.False(result.Truncated);
        Assert.Null(result.ContinuationToken);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public void RootListing_ReturnsPermittedFilesDirectoriesAndSafeMetadata()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "alpha.txt"), "abc");
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, "beta"));
        using var cursors = new DirectoryCursorProtector();

        var result = Tool(workspace, cursors).ListDirectory("root", "");

        var entries = Assert.IsAssignableFrom<IReadOnlyList<DirectoryEntryResponse>>(result.Entries);
        Assert.Equal(["alpha.txt", "beta"], entries.Select(entry => entry.Name));
        Assert.Equal("file", entries[0].Type);
        Assert.Equal(3, entries[0].Size);
        Assert.Equal("directory", entries[1].Type);
        Assert.Null(entries[1].Size);
        Assert.All(entries, entry => Assert.DoesNotContain(workspace.RootPath, entry.RelativePath));
    }

    [Fact]
    public void NestedListing_IsOnlyPerformedByExplicitSeparateRequest()
    {
        using var workspace = new ContainmentTestWorkspace();
        var nested = Directory.CreateDirectory(Path.Combine(workspace.RootPath, "nested")).FullName;
        File.WriteAllText(Path.Combine(nested, "child.txt"), "child");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);

        var root = tool.ListDirectory("root", "");
        var child = tool.ListDirectory("root", "nested");

        Assert.Single(root.Entries!);
        Assert.Equal("nested", root.Entries![0].RelativePath);
        Assert.Single(child.Entries!);
        Assert.Equal(@"nested\child.txt", child.Entries![0].RelativePath);
    }

    [Fact]
    public void FilesAndDirectoriesShareOrdinalCaseInsensitiveThenCaseSensitiveOrdering()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "b-file"), "b");
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, "A-dir"));
        File.WriteAllText(Path.Combine(workspace.RootPath, "a-file"), "a");
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, "B-dir"));
        using var cursors = new DirectoryCursorProtector();

        var first = Tool(workspace, cursors).ListDirectory("root", "");
        var second = Tool(workspace, cursors).ListDirectory("root", "");

        var expected = new[] { "A-dir", "a-file", "B-dir", "b-file" };
        Assert.Equal(expected, first.Entries!.Select(entry => entry.Name));
        Assert.Equal(expected, second.Entries!.Select(entry => entry.Name));
    }

    [Fact]
    public void SinglePage_HasNoContinuationToken()
    {
        using var workspace = PopulatedWorkspace("a", "b");
        using var cursors = new DirectoryCursorProtector();
        var result = Tool(workspace, cursors).ListDirectory("root", "", 2);

        Assert.False(result.Truncated);
        Assert.Null(result.TruncationReason);
        Assert.Null(result.ContinuationToken);
    }

    [Fact]
    public void MultiplePages_ResumeStrictlyAfterLogicalBoundary()
    {
        using var workspace = PopulatedWorkspace("d", "a", "c", "b", "e");
        using var cursors = new DirectoryCursorProtector();
        var tool = Tool(workspace, cursors);

        var first = tool.ListDirectory("root", "", 2);
        var second = tool.ListDirectory("root", "", cursor: first.ContinuationToken);
        var third = tool.ListDirectory("root", "", cursor: second.ContinuationToken);

        Assert.Equal(["a", "b"], first.Entries!.Select(entry => entry.Name));
        Assert.Equal(["c", "d"], second.Entries!.Select(entry => entry.Name));
        Assert.Equal(["e"], third.Entries!.Select(entry => entry.Name));
        Assert.True(first.Truncated);
        Assert.Equal("result_limit", first.TruncationReason);
        Assert.True(second.Truncated);
        Assert.False(third.Truncated);
        Assert.Null(third.ContinuationToken);
    }

    [Fact]
    public void ClientRequestedLimitBelowDefault_IsHonored()
    {
        using var workspace = PopulatedWorkspace("a", "b", "c");
        using var cursors = new DirectoryCursorProtector();
        var result = Tool(workspace, cursors).ListDirectory("root", "", 1);
        Assert.Single(result.Entries!);
        Assert.True(result.Truncated);
    }

    [Fact]
    public void ClientRequestedLimitAboveActiveAndHardCeilings_CannotEnlargePage()
    {
        using var workspace = new ContainmentTestWorkspace();
        for (var index = 0; index < 505; index++)
            File.WriteAllText(Path.Combine(workspace.RootPath, $"entry-{index:D4}"), "x");
        using var cursors = new DirectoryCursorProtector();

        var result = Tool(workspace, cursors).ListDirectory("root", "", 50_000);

        Assert.Equal(ListDirectoryTool.DefaultMaximumEntries, result.Entries!.Count);
        Assert.True(result.Truncated);
        Assert.Equal(2000, ListDirectoryTool.CompiledHardMaximumEntries);
    }

    [Fact]
    public void NonPositivePageSize_IsRejected()
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        Assert.Equal("PATH_INVALID", Tool(workspace, cursors).ListDirectory("root", "", 0).ErrorCode);
    }

    [Fact]
    public void FileTarget_IsNotADirectory()
    {
        using var workspace = PopulatedWorkspace("file.txt");
        using var cursors = new DirectoryCursorProtector();
        Assert.Equal("NOT_A_DIRECTORY", Tool(workspace, cursors).ListDirectory("root", "file.txt").ErrorCode);
    }

    [Fact]
    public void UnknownRoot_ReturnsGenericRootError()
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        Assert.Equal("ROOT_NOT_FOUND", Tool(workspace, cursors).ListDirectory("missing", "").ErrorCode);
    }

    [Theory]
    [InlineData(@"..\outside")]
    [InlineData(@"C:\Windows")]
    [InlineData(@"\\server\share")]
    [InlineData(@"\\?\C:\Windows")]
    [InlineData(@"\\.\C:\Windows")]
    [InlineData("file:stream")]
    [InlineData("folder/")]
    public void MalformedAbsoluteUncDeviceAndAlternatePathsRemainRejected(string path)
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        Assert.Equal("PATH_INVALID", Tool(workspace, cursors).ListDirectory("root", path).ErrorCode);
    }

    [Fact]
    public void CaseVariantOfAuthorizedDirectoryDoesNotAlterAuthorization()
    {
        using var workspace = new ContainmentTestWorkspace();
        Directory.CreateDirectory(Path.Combine(workspace.RootPath, "Folder"));
        File.WriteAllText(Path.Combine(workspace.RootPath, "Folder", "file"), "x");
        using var cursors = new DirectoryCursorProtector();
        Assert.Single(Tool(workspace, cursors).ListDirectory("ROOT", "fOlDeR").Entries!);
    }

    [Fact]
    public void OperationalTimeLimitFailsClosedWhenOrderedPartialPageIsUnsafe()
    {
        using var workspace = PopulatedWorkspace("a");
        using var cursors = new DirectoryCursorProtector();
        var tool = new ListDirectoryTool(workspace.Registry, cursors, workspace.Native,
            new WindowsDirectoryEntryEnumerator(), wallClockBudget: TimeSpan.Zero);

        Assert.Equal("RESOURCE_LIMIT", tool.ListDirectory("root", "").ErrorCode);
    }

    [Fact]
    public void EnumeratorFailureReturnsOnlyGenericPathChanged()
    {
        using var workspace = new ContainmentTestWorkspace();
        using var cursors = new DirectoryCursorProtector();
        var tool = new ListDirectoryTool(workspace.Registry, cursors, workspace.Native, new ThrowingEnumerator());

        Assert.Equal("PATH_CHANGED", tool.ListDirectory("root", "").ErrorCode);
    }

    [Fact]
    public void AmbiguousDuplicateResumeOrderingFailsClosed()
    {
        using var workspace = PopulatedWorkspace("a", "b");
        using var cursors = new DirectoryCursorProtector();
        var first = Tool(workspace, cursors).ListDirectory("root", "", 1);
        var ambiguous = new ListDirectoryTool(workspace.Registry, cursors, workspace.Native,
            new FixedEnumerator("a", "a", "b"));

        var result = ambiguous.ListDirectory("root", "", 1, first.ContinuationToken);

        Assert.Equal("PATH_CHANGED", result.ErrorCode);
    }

    [Fact]
    public void ResponseSerializationContainsNoAbsolutePathsOrNativeIdentifiers()
    {
        using var workspace = PopulatedWorkspace("safe.txt");
        using var cursors = new DirectoryCursorProtector();
        var json = JsonSerializer.Serialize(Tool(workspace, cursors).ListDirectory("root", ""));

        Assert.DoesNotContain(workspace.RootPath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("VolumeSerialNumber", json);
        Assert.DoesNotContain("FileIdHex", json);
        Assert.DoesNotContain("Reparse", json);
    }

    [Fact]
    public void ImplementationIsNonRecursiveAndHasGovernedWallClockConstants()
    {
        Assert.Equal(TimeSpan.FromSeconds(5), ListDirectoryTool.OperationalWallClockBudget);
        Assert.Equal(TimeSpan.FromSeconds(15), ListDirectoryTool.HardWallClockCeiling);
        var source = File.ReadAllText(Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Tools", "ListDirectoryTool.cs"));
        Assert.Contains("RecurseSubdirectories = false", source);
        Assert.DoesNotContain("SearchOption.AllDirectories", source);
    }

    private static ListDirectoryTool Tool(ContainmentTestWorkspace workspace, DirectoryCursorProtector cursors) =>
        new(workspace.Registry, cursors, workspace.Native, new WindowsDirectoryEntryEnumerator());

    private static ContainmentTestWorkspace PopulatedWorkspace(params string[] files)
    {
        var workspace = new ContainmentTestWorkspace();
        foreach (var file in files) File.WriteAllText(Path.Combine(workspace.RootPath, file), file);
        return workspace;
    }

    private sealed class FixedEnumerator(params string[] names) : IDirectoryEntryEnumerator
    {
        public IEnumerable<string> EnumerateNames(string authorizedCanonicalDirectory) => names;
    }

    private sealed class ThrowingEnumerator : IDirectoryEntryEnumerator
    {
        public IEnumerable<string> EnumerateNames(string authorizedCanonicalDirectory)
        {
            throw new IOException("test-only host detail");
        }
    }
}

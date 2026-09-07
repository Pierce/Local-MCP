using LocalMcp.Security;
using System.Diagnostics;
using System.Runtime.Versioning;
using Xunit.Abstractions;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
public class WindowsContainmentIntegrationTests
{
    private readonly ITestOutputHelper _output;

    public WindowsContainmentIntegrationTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public void OrdinaryInsideRootObject_IsAuthorizedFromOpenedFacts()
    {
        using var workspace = new ContainmentTestWorkspace();
        var directory = Path.Combine(workspace.RootPath, "inside");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "file.txt"), "fixture");

        using var result = workspace.Authorize(@"inside\file.txt").AuthorizedObject;

        Assert.NotNull(result);
        Assert.False(result.Handle.IsInvalid);
        Assert.Equal(NativeObjectKind.File, result.Facts.ObjectKind);
        Assert.Equal(@"inside\file.txt", result.RelativePath);
    }

    [Fact]
    public void OutsideRootJunction_IsDenied()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.OutsidePath, "outside.txt"), "outside");
        var junction = Path.Combine(workspace.RootPath, "junction");
        WindowsLinkTestSupport.CreateJunction(junction, workspace.OutsidePath);
        try
        {
            var result = workspace.Authorize(@"junction\outside.txt");

            Assert.False(result.IsAuthorized);
            Assert.Equal(AuthorizationOutcome.PathOutsideRoot, result.Outcome);
        }
        finally
        {
            Directory.Delete(junction);
        }
    }

    [Fact]
    public void InsideRootJunction_IsAuthorizedWithoutEnlargingAuthority()
    {
        using var workspace = new ContainmentTestWorkspace();
        var target = Path.Combine(workspace.RootPath, "junction-target");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "inside.txt"), "inside");
        var junction = Path.Combine(workspace.RootPath, "junction-inside");
        WindowsLinkTestSupport.CreateJunction(junction, target);
        try
        {
            using var authorized = workspace.Authorize(@"junction-inside\inside.txt").AuthorizedObject;

            Assert.NotNull(authorized);
            Assert.Equal(NativeObjectKind.File, authorized.Facts.ObjectKind);
        }
        finally
        {
            Directory.Delete(junction);
        }
    }

    [WindowsSymlinkFact]
    public void OutsideRootSymbolicLink_IsDenied()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.OutsidePath, "outside.txt"), "outside");
        var link = Path.Combine(workspace.RootPath, "symbolic-link");
        Directory.CreateSymbolicLink(link, workspace.OutsidePath);

        var result = workspace.Authorize(@"symbolic-link\outside.txt");
        try
        {
            Assert.Equal(AuthorizationOutcome.PathOutsideRoot, result.Outcome);
        }
        finally
        {
            Directory.Delete(link);
        }
    }

    [Fact]
    public void CaseVariant_ReachesTheSameAuthorizedObject()
    {
        using var workspace = new ContainmentTestWorkspace();
        var path = Path.Combine(workspace.RootPath, "CaseTarget.txt");
        File.WriteAllText(path, "case");
        using var exact = workspace.Authorize("CaseTarget.txt").AuthorizedObject;
        using var variant = workspace.Authorize("casetarget.TXT").AuthorizedObject;

        Assert.NotNull(exact);
        Assert.NotNull(variant);
        Assert.Equal(exact.Facts.Identity, variant.Facts.Identity);
    }

    [WindowsShortNameFact]
    public void ShortNameAlias_ReachesTheSameAuthorizedObject()
    {
        using var workspace = new ContainmentTestWorkspace();
        var directory = Path.Combine(workspace.RootPath, "LongDirectoryNameForAlias");
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(directory, "LongFileNameForAlias.txt"), "alias");
        Assert.True(WindowsLinkTestSupport.TryGetShortPath(directory, out var shortDirectory));

        var relativeDirectory = Path.GetFileName(shortDirectory!);
        using var longResult = workspace.Authorize(@"LongDirectoryNameForAlias\LongFileNameForAlias.txt").AuthorizedObject;
        using var shortResult = workspace.Authorize($@"{relativeDirectory}\LongFileNameForAlias.txt").AuthorizedObject;

        Assert.NotNull(longResult);
        Assert.NotNull(shortResult);
        Assert.Equal(longResult.Facts.Identity, shortResult.Facts.Identity);
    }

    [Fact]
    public void PathReplacementRace_RemainsBoundToTheAuthorizedOpenedObject()
    {
        using var workspace = new ContainmentTestWorkspace();
        var original = Path.Combine(workspace.RootPath, "race.txt");
        var moved = Path.Combine(workspace.RootPath, "race-original.txt");
        File.WriteAllText(original, "original");
        var authorization = workspace.Authorize("race.txt");
        Assert.True(authorization.IsAuthorized);
        using var authorizedObject = authorization.AuthorizedObject!;
        var authorizedIdentity = authorizedObject.Facts.Identity;

        try
        {
            File.Move(original, moved);
        }
        catch (IOException)
        {
            Assert.False(authorizedObject.Handle.IsClosed);
            var retainedAfterBlockedReplacement = workspace.Native.GetFacts(authorizedObject.Handle);
            Assert.True(retainedAfterBlockedReplacement.IsSuccess);
            Assert.Equal(authorizedIdentity, retainedAfterBlockedReplacement.Facts!.Identity);
            _output.WriteLine("replacement_attempt=blocked; retained_handle_binding=unchanged");
            return;
        }

        File.WriteAllText(original, "replacement");
        var retainedAfterReplacement = workspace.Native.GetFacts(authorizedObject.Handle);
        Assert.True(retainedAfterReplacement.IsSuccess);
        Assert.Equal(authorizedIdentity, retainedAfterReplacement.Facts!.Identity);

        using var replacement = workspace.Authorize("race.txt").AuthorizedObject;
        Assert.NotNull(replacement);
        Assert.NotEqual(authorizedIdentity, replacement.Facts.Identity);
        _output.WriteLine("replacement_attempt=succeeded; retained_handle_binding=unchanged; replacement_identity=different");
    }

    [Fact]
    public void RepeatedAuthorizationAndDisposal_DoesNotLeakProcessHandles()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "handle-lifetime.txt"), "fixture");

        using (var warmup = workspace.Authorize("handle-lifetime.txt").AuthorizedObject)
        {
            Assert.NotNull(warmup);
        }

        var process = Process.GetCurrentProcess();
        process.Refresh();
        var before = process.HandleCount;

        for (var iteration = 0; iteration < 500; iteration++)
        {
            using var authorized = workspace.Authorize("handle-lifetime.txt").AuthorizedObject;
            Assert.NotNull(authorized);
            Assert.False(authorized.Handle.IsClosed);
        }

        process.Refresh();
        var after = process.HandleCount;
        _output.WriteLine($"iterations=500; process_handle_count_before={before}; process_handle_count_after={after}; delta={after - before}");
        Assert.InRange(after - before, -8, 8);
    }

    [Fact]
    public void AuthorizedObject_DisposeIsDeterministicAndIdempotent()
    {
        using var workspace = new ContainmentTestWorkspace();
        File.WriteAllText(Path.Combine(workspace.RootPath, "dispose.txt"), "fixture");
        var authorized = workspace.Authorize("dispose.txt").AuthorizedObject;

        Assert.NotNull(authorized);
        Assert.False(authorized.Handle.IsClosed);
        authorized.Dispose();
        Assert.True(authorized.Handle.IsClosed);
        Assert.True(authorized.IsDisposed);

        authorized.Dispose();
        Assert.True(authorized.Handle.IsClosed);
    }
}

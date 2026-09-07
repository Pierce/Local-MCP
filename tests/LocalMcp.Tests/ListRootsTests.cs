using System.Text.Json;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class ListRootsTests
{
    [Fact]
    public void ListRoots_ReturnsOnlyValidatedLogicalIdsAndSafeDescriptions()
    {
        using var workspace = new AuthorityTestWorkspace();
        var missing = Path.Combine(workspace.BasePath, "missing-secret-location");
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("visible", workspace.ValidRootPath, "Safe description", true),
            ("invalid", missing, "Filtered", true)));
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        var response = new ListRootsTool(registry!).ListRoots();
        var json = JsonSerializer.Serialize(response);

        var root = Assert.Single(response.Roots);
        Assert.Equal("visible", root.RootId);
        Assert.Equal("Safe description", root.Description);
        Assert.Equal(new[] { "stat" }, root.Capabilities);
        Assert.DoesNotContain(workspace.BasePath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(workspace.ValidRootPath, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("invalid", json);
        Assert.DoesNotContain("missing-secret-location", json);
    }

    [Fact]
    public void NoValidRoots_ReturnsAnEmptyCollectionWithoutFallback()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("missing", Path.Combine(workspace.BasePath, "missing"), null, true)));
        var loaded = workspace.Load();
        using var registry = loaded.Registry;
        Assert.True(loaded.IsSuccess);
        Assert.Empty(new ListRootsTool(registry!).ListRoots().Roots);
    }
}

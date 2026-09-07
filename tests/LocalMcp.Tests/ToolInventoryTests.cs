namespace LocalMcp.Tests;

public class ToolInventoryTests
{
    [Fact]
    public void OnlyListRootsAndIncrementThreeStatTools_AreRegistered()
    {
        var source = ReadAllSource();
        Assert.Contains("WithTools<ListRootsTool>", source);
        Assert.Contains("Name = \"list_roots\"", source);
        Assert.Contains("WithTools<StatTool>", source);
        Assert.Contains("McpServerTool(Name = \"stat\"", source);
        Assert.DoesNotContain("list_directory", source);
        Assert.DoesNotContain("read_text", source);
        Assert.DoesNotContain("search_filenames", source);
        Assert.DoesNotContain("search_text", source);
        Assert.DoesNotContain("search_files", source);
        Assert.DoesNotContain("search_content", source);
    }

    [Fact]
    public void NoMcpConfigurationSelectionOrDiscoveryRouteExists()
    {
        var source = ReadAllSource();
        Assert.DoesNotContain("select_config", source);
        Assert.DoesNotContain("list_configs", source);
        Assert.DoesNotContain("discover_config", source);
        Assert.DoesNotContain("switch_profile", source);
        Assert.DoesNotContain("reload_config", source);
    }

    private static string ReadAllSource()
    {
        var sourceDir = Path.Combine(TestPaths.RepositoryRoot, "src");
        return string.Join("\n", Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories).Select(File.ReadAllText));
    }
}

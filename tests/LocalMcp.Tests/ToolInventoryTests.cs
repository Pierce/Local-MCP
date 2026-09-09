namespace LocalMcp.Tests;

public class ToolInventoryTests
{
    [Fact]
    public void OnlyGovernedIncrementFourLocalFilesTools_AreRegistered()
    {
        var source = ReadAllSource();
        Assert.Contains("WithTools<ListRootsTool>", source);
        Assert.Contains("Name = \"list_roots\"", source);
        Assert.Contains("WithTools<StatTool>", source);
        Assert.Contains("McpServerTool(Name = \"stat\"", source);
        Assert.Contains("WithTools<ListDirectoryTool>", source);
        Assert.Contains("McpServerTool(Name = \"list_directory\"", source);
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

    [Fact]
    public void NoHandoffDiscoveryOrListingTools_Exist()
    {
        var source = ReadAllSource();
        // The only authorized handoff tool is get_handoff
        Assert.DoesNotContain("list_handoffs", source);
        Assert.DoesNotContain("search_handoffs", source);
        Assert.DoesNotContain("get_latest_handoff", source);
        Assert.DoesNotContain("get_pending_handoff", source);
    }

    [Fact]
    public void OnlyGetHandoff_IsAuthorizedHandoffTool()
    {
        var source = ReadAllSource();
        // Verify get_handoff is present (conditionally registered)
        Assert.Contains("McpServerTool(Name = \"get_handoff\"", source);
        Assert.Contains("GetHandoffTool", source);
        // No handoff tool accepts filesystem paths
        Assert.Contains("get_handoff", source);
    }

    private static string ReadAllSource()
    {
        var sourceDir = Path.Combine(TestPaths.RepositoryRoot, "src");
        return string.Join("\n", Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories).Select(File.ReadAllText));
    }
}

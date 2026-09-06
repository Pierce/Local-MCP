// Verify that no filesystem MCP tools are registered and no
// placeholder tools exist. Increment 0 is a non-capability baseline.

namespace LocalMcp.Tests;

public class ToolInventoryTests
{
    [Fact]
    public void NoFilesystemTools_Registered()
    {
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Program.cs"));

        var programCode = File.ReadAllText(programFile);

        // The server must NOT use any MCP tool registration APIs
        Assert.DoesNotContain("WithTools", programCode);
        Assert.DoesNotContain("WithListToolsHandler", programCode);
        Assert.DoesNotContain("WithCallToolHandler", programCode);

        // Verify no MCP-facing tool names exist in the source
        var sourceDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src"));

        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            // Only check for MCP protocol tool names, not comments
            Assert.DoesNotContain("list_roots", content);
            Assert.DoesNotContain("list_directory", content);
            Assert.DoesNotContain("read_text", content);
        }
    }

    [Fact]
    public void NoToolRegistrations_InProject()
    {
        var sourceDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src"));

        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            Assert.DoesNotContain("McpServerTool", content);
        }
    }
}
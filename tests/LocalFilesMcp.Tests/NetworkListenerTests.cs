// Verify that normal startup does not create TCP, HTTP, or WebSocket listeners.
// The v1 architecture mandates stdio-only transport.

namespace LocalFilesMcp.Tests;

public class NetworkListenerTests
{
    [Fact]
    public void NoTcpListener_ByDefaultConfiguration()
    {
        // At the architecture level, verify that no TCP transport is configured.
        // The server only uses WithStdioServerTransport().
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalFilesMcp", "Program.cs"));
        var programCode = File.ReadAllText(programFile);

        Assert.DoesNotContain("HttpTransport", programCode);
        Assert.DoesNotContain("WithTransport", programCode);
        Assert.DoesNotContain("WithWebSocket", programCode);
        Assert.DoesNotContain("WithStreamServerTransport", programCode);
    }

    [Fact]
    public void OnlyStdioTransport_IsConfigured()
    {
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalFilesMcp", "Program.cs"));
        var programCode = File.ReadAllText(programFile);

        // The only transport configured must be stdio
        Assert.Contains("WithStdioServerTransport", programCode);
        Assert.DoesNotContain("WithHttpTransport", programCode);
        Assert.DoesNotContain("WithAspNetTransport", programCode);
    }

    [Fact]
    public void NoAspNetCoreDependency_IsPresent()
    {
        // Verify AspNetCore package is not referenced
        var csprojPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalFilesMcp", "LocalFilesMcp.csproj"));
        var csproj = File.ReadAllText(csprojPath);

        Assert.DoesNotContain("Microsoft.AspNetCore", csproj);
    }
}
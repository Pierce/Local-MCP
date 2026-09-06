// Verify dependency inventory and exact versions.

namespace LocalMcp.Tests;

public class DependencyInventoryTests
{
    private static string GetRepoRoot()
    {
        return TestPaths.RepositoryRoot;
    }

    [Fact]
    public void MainProject_HasExpectedDependencies()
    {
        var csprojPath = Path.Combine(GetRepoRoot(), "src", "LocalMcp", "LocalMcp.csproj");
        var csproj = File.ReadAllText(csprojPath);

        // Verify expected packages are present with versions pinned
        Assert.Contains("ModelContextProtocol", csproj);
        Assert.Contains("Version=\"2.2.0\"", csproj);

        Assert.Contains("Tomlyn", csproj);
        Assert.Contains("Version=\"2.10.1\"", csproj);

        Assert.Contains("Microsoft.Extensions.Hosting", csproj);
    }

    [Fact]
    public void TestProject_HasExpectedDependencies()
    {
        var csprojPath = Path.Combine(GetRepoRoot(), "tests", "LocalMcp.Tests", "LocalMcp.Tests.csproj");
        var csproj = File.ReadAllText(csprojPath);

        Assert.Contains("xunit", csproj);
        Assert.Contains("Microsoft.NET.Test.Sdk", csproj);
        Assert.Contains("coverlet.collector", csproj);
    }
}

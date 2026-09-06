// Verify dependency inventory and exact versions.

namespace LocalFilesMcp.Tests;

public class DependencyInventoryTests
{
    private static string GetRepoRoot()
    {
        // From test assembly: tests\LocalFilesMcp.Tests\bin\Debug\net10.0\
        return Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    }

    [Fact]
    public void MainProject_HasExpectedDependencies()
    {
        var csprojPath = Path.Combine(GetRepoRoot(), "src", "LocalFilesMcp", "LocalFilesMcp.csproj");
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
        var csprojPath = Path.Combine(GetRepoRoot(), "tests", "LocalFilesMcp.Tests", "LocalFilesMcp.Tests.csproj");
        var csproj = File.ReadAllText(csprojPath);

        Assert.Contains("xunit", csproj);
        Assert.Contains("Microsoft.NET.Test.Sdk", csproj);
        Assert.Contains("coverlet.collector", csproj);
    }
}
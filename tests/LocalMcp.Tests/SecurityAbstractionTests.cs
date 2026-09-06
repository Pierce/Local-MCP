// Verify that no shell-execution, process-execution, or filesystem-mutation
// abstractions have been introduced in Increment 0.

namespace LocalMcp.Tests;

public class SecurityAbstractionTests
{
    [Fact]
    public void NoShellAbstraction_Exists()
    {
        var sourceDir = GetSourceDir();
        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            Assert.DoesNotContain("ProcessStartInfo", content);
            Assert.DoesNotContain("ShellExecute", content);
            Assert.DoesNotContain("CreateProcess", content);
            Assert.DoesNotContain("Process.Start", content);
        }
    }

    [Fact]
    public void NoProcessExecutionAbstraction_Exists()
    {
        var sourceDir = GetSourceDir();
        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            Assert.DoesNotContain("System.Diagnostics.Process", content);
            Assert.DoesNotContain("ChildProcess", content);
            Assert.DoesNotContain("ExternalProcess", content);
            Assert.DoesNotContain("CommandExecution", content);
        }
    }

    [Fact]
    public void NoFilesystemMutationAbstraction_Exists()
    {
        var sourceDir = GetSourceDir();
        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            // No write-related filesystem APIs should be present
            Assert.DoesNotContain("File.Write", content);
            Assert.DoesNotContain("StreamWriter", content);
            Assert.DoesNotContain("File.Create", content);
            Assert.DoesNotContain("File.Delete", content);
            Assert.DoesNotContain("Directory.Create", content);
            Assert.DoesNotContain("Directory.Delete", content);
            Assert.DoesNotContain("File.Move", content);
            Assert.DoesNotContain("File.Copy", content);
        }
    }

    private static string GetSourceDir()
    {
        return Path.Combine(TestPaths.RepositoryRoot, "src");
    }
}

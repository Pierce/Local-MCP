using System.Diagnostics;
using System.Runtime.Versioning;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
public class WindowsProtectionIntegrationTests
{
    [Fact]
    public void ConfigurationWritableByEveryone_IsRejectedByRealAclEvaluation()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        workspace.GrantEveryoneWrite();

        var result = workspace.Load();
        Assert.False(result.IsSuccess);
        Assert.Equal("CONFIG_ACL_BROAD_WRITE", result.FatalErrorCode);
    }

    [Fact]
    public void ConfigurationReachedThroughDirectoryJunction_IsRejectedByRealReparseInspection()
    {
        using var workspace = new AuthorityTestWorkspace();
        workspace.WriteConfiguration();
        var linkedDirectory = Path.Combine(Path.GetDirectoryName(workspace.BasePath)!, $"local-mcp-junction-{Guid.NewGuid():N}");
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                ArgumentList = { "/d", "/c", "mklink", "/J", linkedDirectory, workspace.BasePath },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            })!;
            process.WaitForExit();
            Assert.Equal(0, process.ExitCode);

            var result = workspace.Load(Path.Combine(linkedDirectory, Path.GetFileName(workspace.ConfigurationPath)));
            Assert.False(result.IsSuccess);
            Assert.Equal("CONFIG_REPARSE_UNSAFE", result.FatalErrorCode);
        }
        finally
        {
            try { Directory.Delete(linkedDirectory); } catch { }
        }
    }
}

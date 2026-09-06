using System.Diagnostics;

namespace LocalMcp.Tests;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class ProcessLifecycleTests
{
    [Fact]
    public void Process_UsesHostingPattern_ForCleanStartup()
    {
        var applicationFile = Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp", "Hosting", "LocalMcpApplication.cs");
        var code = File.ReadAllText(applicationFile);
        Assert.Contains("Host.CreateApplicationBuilder", code);
        Assert.Contains("RunAsync", code);
        Assert.Contains("DisableDefaults = true", code);
    }

    [Fact]
    public async Task Process_FailsBeforeNormalStartup_WhenExplicitConfigurationIsMissing()
    {
        var result = await RunProcessAsync(["--config", Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.toml")], sendProtocol: false);
        Assert.Equal(2, result.ExitCode);
        Assert.Empty(result.Stdout);
        Assert.Contains("CONFIG_NOT_FOUND", result.Stderr);
    }

    [Fact]
    public async Task Process_ListsOnlyValidatedRoots_ThroughActualMcpProtocol()
    {
        using var workspace = new AuthorityTestWorkspace();
        var missing = Path.Combine(workspace.BasePath, "missing");
        workspace.WriteConfiguration(AuthorityTestWorkspace.CurrentConfiguration(
            ("valid-runtime", workspace.ValidRootPath, "Runtime root", true),
            ("invalid-runtime", missing, "Must not appear", true)));

        var before = workspace.HashConfiguration();
        var result = await RunProcessAsync(["--config", workspace.ConfigurationPath], sendProtocol: true);
        var after = workspace.HashConfiguration();

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(before, after);
        Assert.DoesNotContain(workspace.BasePath, result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("valid-runtime", result.Stdout);
        Assert.DoesNotContain("invalid-runtime", result.ToolCallResponse);
        Assert.DoesNotContain(workspace.ValidRootPath, result.ToolCallResponse, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("list_roots", result.ToolsListResponse);
        Assert.DoesNotContain("list_directory", result.ToolsListResponse);
        Assert.DoesNotContain("read_text", result.ToolsListResponse);
    }

    private static async Task<ProcessResult> RunProcessAsync(string[] arguments, bool sendProtocol)
    {
        var projectDir = Path.Combine(TestPaths.RepositoryRoot, "src", "LocalMcp");
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{projectDir}\" --no-build -- {string.Join(' ', arguments.Select(argument => $"\"{argument}\""))}",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        using var process = Process.Start(startInfo)!;
        string toolsList = string.Empty;
        string toolCall = string.Empty;
        if (sendProtocol)
        {
            await process.StandardInput.WriteLineAsync("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"increment-one-test\",\"version\":\"1.0\"}}}");
            await process.StandardInput.FlushAsync();
            _ = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await process.StandardInput.WriteLineAsync("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
            await process.StandardInput.WriteLineAsync("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}");
            await process.StandardInput.FlushAsync();
            toolsList = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)) ?? string.Empty;
            await process.StandardInput.WriteLineAsync("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"list_roots\",\"arguments\":{}}}");
            await process.StandardInput.FlushAsync();
            toolCall = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)) ?? string.Empty;
        }

        process.StandardInput.Close();
        var stdoutRemainder = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        var stdout = string.Join("\n", new[] { toolsList, toolCall, stdoutRemainder }.Where(value => value.Length > 0));
        return new ProcessResult(process.ExitCode, stdout, stderr, toolsList, toolCall);
    }

    private sealed record ProcessResult(int ExitCode, string Stdout, string Stderr, string ToolsListResponse, string ToolCallResponse);
}

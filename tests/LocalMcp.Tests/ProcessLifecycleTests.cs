// Process lifecycle verification: the MCP server configuration ensures
// clean startup and shutdown via the stdio transport SingleSessionMcpServerHostedService.
// These tests verify by code review that the architecture is correct.

using System.Diagnostics;

namespace LocalMcp.Tests;

public class ProcessLifecycleTests
{
    [Fact]
    public void Process_UsesHostingPattern_ForCleanStartup()
    {
        // Verify that the server uses Host.CreateApplicationBuilder + RunAsync
        // which provides clean startup and shutdown lifecycle.
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Program.cs"));

        var programCode = File.ReadAllText(programFile);

        Assert.Contains("Host.CreateApplicationBuilder", programCode);
        Assert.Contains("RunAsync", programCode);
    }

    [Fact]
    public void ProjectFileExists_ForPotentialProcessLaunch()
    {
        // Verify the project file is at the expected location
        var projectPath = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "LocalMcp.csproj"));
        Assert.True(File.Exists(projectPath), $"Project file not found: {projectPath}");
    }

    [Fact]
    public async Task Process_CanBeLaunched_WithDotnetRun()
    {
        // Launch the server process briefly and verify it starts
        var projectDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp"));

        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{projectDir}\" --no-build",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        Process? process = null;
        try
        {
            process = Process.Start(startInfo);
            Assert.NotNull(process);

            // Give it a moment to start
            await Task.Delay(TimeSpan.FromSeconds(2));

            // The process is running if we can write to stdin and read from stdout
            Assert.False(process.HasExited);

            // Send a proper MCP initialize request
            var initRequest = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-04-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test-client\",\"version\":\"1.0.0\"}}}\n";
            await process.StandardInput.WriteLineAsync(initRequest);
            await process.StandardInput.FlushAsync();

            // Wait briefly for response
            await Task.Delay(TimeSpan.FromSeconds(1));

            // Close stdin to trigger clean exit
            process.StandardInput.Close();

            // Wait for exit
            var exited = process.WaitForExit(5000);
            Assert.True(exited, "Process should exit cleanly within 5 seconds of stdin close");
            Assert.Equal(0, process.ExitCode);
        }
        finally
        {
            if (process is { HasExited: false })
            {
                try { process.Kill(); } catch { }
            }
            process?.Dispose();
        }
    }
}
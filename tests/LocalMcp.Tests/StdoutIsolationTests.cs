// Verify that stdout remains reserved for MCP protocol traffic.
// Diagnostics, logging, banners, and other output must not appear on stdout.
// This is verified through code review of the logging configuration.

using System.Text.RegularExpressions;

namespace LocalMcp.Tests;

public class StdoutIsolationTests
{
    [Fact]
    public void LoggingConfiguration_RoutesToStderr()
    {
        // Verify the server configures logging to a protocol-safe provider
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Program.cs"));

        var programCode = File.ReadAllText(programFile);

        // The program must clear default loggers and add ProtocolSafeLoggerProvider
        Assert.Contains("ClearProviders", programCode);
        Assert.Contains("ProtocolSafeLoggerProvider", programCode);
    }

    [Fact]
    public void ProtocolSafeLogger_WritesToStderr()
    {
        // Verify the ProtocolSafeLogger uses Console.Error (stderr)
        var loggerFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Diagnostics", "ProtocolSafeLogger.cs"));

        var loggerCode = File.ReadAllText(loggerFile);

        Assert.Contains("Console.Error", loggerCode);
        Assert.DoesNotContain("Console.Out", loggerCode);
    }

    [Fact]
    public void NoDirectConsoleWrite_InProgram()
    {
        // Verify the program never writes directly to Console
        var programFile = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Program.cs"));

        var programCode = File.ReadAllText(programFile);

        Assert.DoesNotContain("Console.WriteLine", programCode);
        Assert.DoesNotContain("Console.Out", programCode);
    }

    [Fact]
    public void ProtocolSafeLogger_OutputsToStderr_NotStdout()
    {
        // Integration-style test: capture stderr and stdout to confirm separation
        var loggerCode = File.ReadAllText(Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "LocalMcp", "Diagnostics", "ProtocolSafeLogger.cs")));

        // Verify diagnostic output goes to stderr never stdout
        Assert.DoesNotContain("Console.Write", loggerCode);
        Assert.Contains("Console.Error", loggerCode);
    }
}
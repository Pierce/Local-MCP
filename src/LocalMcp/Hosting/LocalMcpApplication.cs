using LocalMcp.Configuration;
using LocalMcp.Diagnostics;
using LocalMcp.Handoff;
using LocalMcp.Roots;
using LocalMcp.Security;
using LocalMcp.Tools;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;

namespace LocalMcp.Hosting;

public static class LocalMcpApplication
{
    public static async Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        var startup = StartupArguments.Parse(args);
        if (!startup.IsSuccess)
        {
            Console.Error.WriteLine($"Local MCP startup failed: {startup.ErrorCode}");
            return 2;
        }

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Local MCP startup failed: PLATFORM_UNSUPPORTED");
            return 2;
        }

        var authority = new ConfigurationAuthorityLoader(new WindowsFileSystemAuthority())
            .Load(startup.Value!.ConfigurationPath);
        if (!authority.IsSuccess)
        {
            Console.Error.WriteLine($"Local MCP startup failed: {authority.FatalErrorCode}");
            return 2;
        }

        var settings = new HostApplicationBuilderSettings { Args = Array.Empty<string>(), DisableDefaults = true };
        var builder = Host.CreateApplicationBuilder(settings);
        builder.Logging.AddProvider(new ProtocolSafeLoggerProvider());
        builder.Services.AddSingleton(authority.Registry!);

        // Local Files tools are registered unconditionally based on configuration
        // availability. They are independent of the Handoff Retrieval capability.
        var mcpBuilder = builder.Services.AddMcpServer().WithStdioServerTransport()
            .WithTools<ListRootsTool>().WithTools<StatTool>();

        // Handoff Retrieval capability (separately governed, independent authorization)
        var handoffConfig = authority.Configuration?.HandoffRetrieval ?? HandoffRetrievalConfig.Disabled();
        if (handoffConfig.IsEnabled)
        {
            var handoffStore = new HandoffStore(handoffConfig);
            builder.Services.AddSingleton(handoffStore);
            mcpBuilder.WithTools<GetHandoffTool>();
        }

        using var app = builder.Build();
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("LocalMcp.Startup");
        foreach (var issue in authority.RootIssues)
            logger.LogWarning("Configured root {RootId} disabled: {ErrorCode}", issue.RootId, issue.ErrorCode);

        if (handoffConfig.IsEnabled)
        {
            logger.LogInformation("Handoff Retrieval capability enabled with recipient reference: {Recipient}",
                handoffConfig.IntendedRecipientReference);
        }

        logger.LogInformation("Local MCP server starting with {RootCount} validated root(s)", authority.Registry!.Roots.Count);
        try
        {
            await app.RunAsync(cancellationToken);
            return 0;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            logger.LogInformation("Server operation cancelled, shutting down gracefully");
            return 0;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unhandled server error");
            return 1;
        }
    }
}

using LocalMcp.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ModelContextProtocol;
using ModelContextProtocol.Server;

// Create a minimal host builder.
var builder = Host.CreateApplicationBuilder(args);

// Configure diagnostics to stderr, preserving stdout exclusively for MCP protocol traffic.
builder.Logging.ClearProviders();
builder.Logging.AddProvider(new ProtocolSafeLoggerProvider());

// Add the MCP server with stdio transport only.
// No filesystem tools, no placeholder tools, no shell tools, no process tools, no network tools.
builder.Services
    .AddMcpServer()
    .WithStdioServerTransport();

// NO tools are registered. Increment 0 is a non-capability baseline.

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("Local MCP server starting (Increment 0 scaffold)");

try
{
    await app.RunAsync();
}
catch (OperationCanceledException)
{
    logger.LogInformation("Server operation cancelled, shutting down gracefully");
}
catch (Exception ex)
{
    logger.LogError(ex, "Unhandled server error");
    throw;
}

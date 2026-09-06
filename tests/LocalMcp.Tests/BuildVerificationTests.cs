using LocalMcp.Configuration;
using LocalMcp.Diagnostics;
using LocalMcp.Results;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

public class BuildVerificationTests
{
    [Fact]
    public void IncrementOneTypes_AreReachable()
    {
        var config = new McpConfig(1, [new RootDefinition("root-a", @"C:\safe", "Safe", true)]);
        Assert.Equal(1, config.SchemaVersion);
        Assert.Single(config.Roots);
        Assert.Equal(SchemaCompatibility.Current, SchemaCompatibilityPolicy.Classify(1L));
        Assert.Equal(SchemaCompatibility.Future, SchemaCompatibilityPolicy.Classify(2L));
        Assert.Equal(SchemaCompatibility.Unsupported, SchemaCompatibilityPolicy.Classify(0L));
        Assert.Equal(SchemaCompatibility.Ambiguous, SchemaCompatibilityPolicy.Classify("1"));

        Assert.NotNull(typeof(ListRootsTool));
        using var provider = new ProtocolSafeLoggerProvider();
        Assert.NotNull(provider.CreateLogger("Test"));
        Assert.True(OperationResult.Success().IsSuccess);
    }
}

// Build verification: confirms the entire solution compiles successfully.
// This is covered by the test runner itself, but this class explicitly
// verifies that key types from the Increment 0 scaffold are reachable.

using LocalMcp.Configuration;
using LocalMcp.Diagnostics;
using LocalMcp.Results;

namespace LocalMcp.Tests;

public class BuildVerificationTests
{
    [Fact]
    public void ConfigurationTypes_AreReachable()
    {
        var config = new McpConfig();
        Assert.NotNull(config);
        Assert.NotNull(config.Logging);
        Assert.NotNull(config.Roots);
    }

    [Fact]
    public void RootDefinition_IsReachable()
    {
        var root = new RootDefinition();
        Assert.NotNull(root);
        Assert.Empty(root.Path);
        Assert.Null(root.Name);
    }

    [Fact]
    public void ProtocolSafeLoggerProvider_IsReachable()
    {
        var provider = new ProtocolSafeLoggerProvider();
        Assert.NotNull(provider);
        var logger = provider.CreateLogger("Test");
        Assert.NotNull(logger);
        provider.Dispose();
    }

    [Fact]
    public void OperationResult_Types_AreReachable()
    {
        var success = OperationResult.Success();
        Assert.True(success.IsSuccess);
        Assert.False(success.IsFailure);

        var failure = OperationResult.Failure("test error");
        Assert.True(failure.IsFailure);
        Assert.Equal("test error", failure.ErrorMessage);

        var typedSuccess = OperationResult<int>.Success(42);
        Assert.True(typedSuccess.IsSuccess);
        Assert.Equal(42, typedSuccess.Value);

        var typedFailure = OperationResult<int>.Failure("error");
        Assert.True(typedFailure.IsFailure);
        Assert.Equal("error", typedFailure.ErrorMessage);
    }
}
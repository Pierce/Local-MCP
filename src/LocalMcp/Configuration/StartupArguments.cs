namespace LocalMcp.Configuration;

public sealed record StartupArguments(string ConfigurationPath)
{
    public static StartupArgumentResult Parse(IReadOnlyList<string> arguments)
    {
        if (arguments.Count != 2 || !string.Equals(arguments[0], "--config", StringComparison.Ordinal))
        {
            return StartupArgumentResult.Failure("CONFIG_PATH_REQUIRED");
        }

        var path = arguments[1];
        if (string.IsNullOrWhiteSpace(path))
        {
            return StartupArgumentResult.Failure("CONFIG_PATH_REQUIRED");
        }

        return StartupArgumentResult.Success(new StartupArguments(path));
    }
}

public sealed record StartupArgumentResult(StartupArguments? Value, string? ErrorCode)
{
    public bool IsSuccess => Value is not null;

    public static StartupArgumentResult Success(StartupArguments value) => new(value, null);

    public static StartupArgumentResult Failure(string errorCode) => new(null, errorCode);
}

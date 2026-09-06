using Microsoft.Extensions.Logging;

namespace LocalMcp.Diagnostics;

/// <summary>
/// A logger that writes all diagnostic output to stderr, never to stdout.
/// stdout is reserved exclusively for MCP protocol traffic.
/// 
/// This provider ensures that application diagnostics, debugging information,
/// normal logs, exception dumps, dependency messages, banners, startup notices,
/// and similar information do not contaminate the protocol stream.
/// </summary>
public sealed class ProtocolSafeLoggerProvider : ILoggerProvider
{
    private readonly object _lock = new();

    public ILogger CreateLogger(string categoryName) => new ProtocolSafeLogger(categoryName);

    public void Dispose() { }
}

/// <summary>
/// Routes log output to stderr using the standard error stream.
/// </summary>
public sealed class ProtocolSafeLogger : ILogger
{
    private readonly string _categoryName;

    public ProtocolSafeLogger(string categoryName)
    {
        _categoryName = categoryName ?? string.Empty;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        var message = formatter(state, exception);
        if (string.IsNullOrEmpty(message))
            return;

        var timestamp = DateTime.UtcNow.ToString("O");
        var logLevelName = logLevel switch
        {
            LogLevel.Trace => "trce",
            LogLevel.Debug => "dbug",
            LogLevel.Information => "info",
            LogLevel.Warning => "warn",
            LogLevel.Error => "fail",
            LogLevel.Critical => "crit",
            _ => "----"
        };

        // All diagnostic output goes to stderr — never to stdout.
        var output = $"[{timestamp}][{logLevelName}][{_categoryName}] {message}";
        if (exception is not null)
        {
            // Exception text can contain host paths. Preserve only the stable type in local diagnostics.
            output += $" ({exception.GetType().Name})";
        }

        System.Console.Error.WriteLine(output);
    }
}

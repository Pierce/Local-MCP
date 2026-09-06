// Internal result and error types for Local Files MCP operations.
// These types are designed for internal use only and avoid exposing
// host absolute paths, native object identifiers, or sensitive local
// information in MCP-facing layers.

namespace LocalFilesMcp.Results;

/// <summary>
/// Represents the outcome of an internal operation.
/// This is a simple discriminated union pattern for success/failure results.
/// </summary>
public sealed class OperationResult
{
    private OperationResult(bool isSuccess, string? errorMessage, Exception? exception)
    {
        IsSuccess = isSuccess;
        ErrorMessage = errorMessage;
        Exception = exception;
    }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets a value indicating whether the operation failed.
    /// </summary>
    public bool IsFailure => !IsSuccess;

    /// <summary>
    /// Gets the error message if the operation failed; otherwise null.
    /// Messages do not contain host absolute paths or sensitive information.
    /// </summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// Gets the exception if one was captured; otherwise null.
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>
    /// Creates a successful result.
    /// </summary>
    public static OperationResult Success() => new(true, null, null);

    /// <summary>
    /// Creates a failure result with a descriptive message.
    /// The message must not contain host absolute paths or sensitive information.
    /// </summary>
    public static OperationResult Failure(string errorMessage) =>
        new(false, errorMessage ?? "An unknown error occurred", null);

    /// <summary>
    /// Creates a failure result from an exception.
    /// The exception's message is captured, but stack traces are not
    /// propagated to MCP-facing layers.
    /// </summary>
    public static OperationResult Failure(Exception exception) =>
        new(false, exception.Message, exception);
}

/// <summary>
/// Represents the outcome of an internal operation that produces a value.
/// </summary>
public sealed class OperationResult<T>
{
    private OperationResult(bool isSuccess, T? value, string? errorMessage, Exception? exception)
    {
        IsSuccess = isSuccess;
        Value = value;
        ErrorMessage = errorMessage;
        Exception = exception;
    }

    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets a value indicating whether the operation failed.
    /// </summary>
    public bool IsFailure => !IsSuccess;

    /// <summary>
    /// Gets the value if the operation succeeded; otherwise default.
    /// </summary>
    public T? Value { get; }

    /// <summary>
    /// Gets the error message if the operation failed; otherwise null.
    /// </summary>
    public string? ErrorMessage { get; }

    /// <summary>
    /// Gets the exception if one was captured; otherwise null.
    /// </summary>
    public Exception? Exception { get; }

    /// <summary>
    /// Creates a successful result with the given value.
    /// </summary>
    public static OperationResult<T> Success(T value) => new(true, value, null, null);

    /// <summary>
    /// Creates a failure result with a descriptive message.
    /// </summary>
    public static OperationResult<T> Failure(string errorMessage) =>
        new(false, default, errorMessage ?? "An unknown error occurred", null);

    /// <summary>
    /// Creates a failure result from an exception.
    /// </summary>
    public static OperationResult<T> Failure(Exception exception) =>
        new(false, default, exception.Message, exception);
}
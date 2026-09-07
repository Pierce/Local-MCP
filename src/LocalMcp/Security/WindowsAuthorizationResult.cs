using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

internal enum AuthorizationOutcome
{
    Authorized,
    RootNotFound,
    PathInvalid,
    PathOutsideRoot,
    NotFound,
    AccessDenied,
    UnsupportedFileSystem,
    UnsupportedObject,
    PathChanged,
    InternalError,
}

internal sealed record WindowsRelativePath(string Value, IReadOnlyList<string> Components)
{
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    };

    public static bool TryParse(string? value, out WindowsRelativePath? result)
    {
        result = null;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 32760 || value[0] == '\\' ||
            value.Contains('/') || value.Contains(':') || value.Contains('\0') ||
            value.Any(char.IsControl) || value.EndsWith('\\'))
        {
            return false;
        }

        var components = value.Split('\\');
        if (components.Length > 256 || components.Any(IsUnsafeComponent))
        {
            return false;
        }

        result = new WindowsRelativePath(string.Join('\\', components), components);
        return true;
    }

    private static bool IsUnsafeComponent(string component)
    {
        if (component.Length == 0 || component is "." or ".." ||
            component.EndsWith('.') || component.EndsWith(' ') || component.Contains('*') || component.Contains('?'))
        {
            return true;
        }

        var baseName = component.Split('.', 2)[0];
        return ReservedDeviceNames.Contains(baseName);
    }
}

internal sealed class AuthorizedFileSystemObject : IDisposable
{
    private bool _disposed;

    internal AuthorizedFileSystemObject(string rootId, string relativePath, SafeFileHandle handle, NativeObjectFacts facts)
    {
        RootId = rootId;
        RelativePath = relativePath;
        Handle = handle;
        Facts = facts;
    }

    public string RootId { get; }
    public string RelativePath { get; }
    internal SafeFileHandle Handle { get; }
    internal NativeObjectFacts Facts { get; }
    internal bool IsDisposed => _disposed;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Handle.Dispose();
        _disposed = true;
    }
}

internal sealed record WindowsAuthorizationResult(
    AuthorizationOutcome Outcome,
    AuthorizedFileSystemObject? AuthorizedObject)
{
    public bool IsAuthorized => Outcome == AuthorizationOutcome.Authorized && AuthorizedObject is not null;

    public static WindowsAuthorizationResult Allow(AuthorizedFileSystemObject authorizedObject) =>
        new(AuthorizationOutcome.Authorized, authorizedObject);

    public static WindowsAuthorizationResult Deny(AuthorizationOutcome outcome) => new(outcome, null);
}

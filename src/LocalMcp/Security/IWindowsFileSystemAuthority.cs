using LocalMcp.Roots;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

internal interface IWindowsFileSystemAuthority
{
    AuthorityOpenResult OpenConfiguration(string explicitPath);
    AuthorityOpenResult OpenRoot(string configuredPath);
    AuthorityOpenResult OpenStore(string configuredPath);
    AclEvaluationResult EvaluateConfigurationAcl(SafeFileHandle handle);
}

internal sealed record AuthorityOpenResult(SafeFileHandle? Handle, string? CanonicalPath, FileObjectIdentity? ObjectIdentity, string? ErrorCode)
{
    public bool IsSuccess => Handle is not null && CanonicalPath is not null && ObjectIdentity is not null && ErrorCode is null;
    public static AuthorityOpenResult Failure(string code) => new(null, null, null, code);
    public static AuthorityOpenResult Success(SafeFileHandle handle, string path, FileObjectIdentity identity) => new(handle, path, identity, null);
}

internal sealed record AclEvaluationResult(bool IsTrusted, string? ErrorCode)
{
    public static AclEvaluationResult Trusted() => new(true, null);
    public static AclEvaluationResult Untrusted(string code) => new(false, code);
}

using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Roots;

public sealed record FileObjectIdentity(ulong VolumeSerialNumber, string FileIdHex);

public sealed class ValidatedRoot : IDisposable
{
    public ValidatedRoot(string id, string? description, string canonicalPath, FileObjectIdentity objectIdentity, SafeFileHandle handle)
    {
        Id = id;
        Description = description;
        CanonicalPath = canonicalPath;
        ObjectIdentity = objectIdentity;
        Handle = handle;
    }

    public string Id { get; }
    public string? Description { get; }
    internal string CanonicalPath { get; }
    internal FileObjectIdentity ObjectIdentity { get; }
    internal SafeFileHandle Handle { get; }

    public void Dispose() => Handle.Dispose();
}

public sealed record RootValidationIssue(string RootId, string ErrorCode);

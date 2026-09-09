using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

[SupportedOSPlatform("windows")]
internal sealed class WindowsFileSystemAuthority : IWindowsFileSystemAuthority
{
    private const int WriteAuthorityMask = unchecked((int)0x500D0156);
    private readonly IWindowsNativeFileSystem _native;

    public WindowsFileSystemAuthority() : this(new WindowsNativeFileSystem()) { }

    internal WindowsFileSystemAuthority(IWindowsNativeFileSystem native) => _native = native;

    public AuthorityOpenResult OpenConfiguration(string explicitPath)
    {
        var normalized = ValidateAbsoluteLocalPath(explicitPath);
        if (normalized.ErrorCode is not null)
        {
            return AuthorityOpenResult.Failure("CONFIG_PATH_UNSUPPORTED");
        }

        var componentError = RejectConfigurationReparseComponents(normalized.Path!);
        if (componentError is not null)
        {
            return AuthorityOpenResult.Failure(componentError);
        }

        var opened = _native.OpenReadOnly(normalized.Path!, followReparse: true);
        if (!opened.IsSuccess)
        {
            return AuthorityOpenResult.Failure(MapOpenFailure(opened.Failure, "CONFIG"));
        }

        var handle = opened.Handle!;
        var facts = _native.GetFacts(handle);
        if (!facts.IsSuccess)
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("CONFIG_IDENTITY_UNAVAILABLE");
        }

        if (facts.Facts!.ObjectKind != NativeObjectKind.File)
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("CONFIG_NOT_REGULAR_FILE");
        }

        if (!WindowsCanonicalPath.EqualsAbsolutePath(facts.Facts.CanonicalPath, normalized.Path!))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("CONFIG_REPARSE_UNSAFE");
        }

        return AuthorityOpenResult.Success(handle, facts.Facts.CanonicalPath, facts.Facts.Identity);
    }

    public AuthorityOpenResult OpenRoot(string configuredPath)
    {
        var normalized = ValidateAbsoluteLocalPath(configuredPath);
        if (normalized.ErrorCode is not null)
        {
            return AuthorityOpenResult.Failure("ROOT_TARGET_UNSUPPORTED");
        }

        var opened = _native.OpenMetadata(normalized.Path!, followReparse: true);
        if (!opened.IsSuccess)
        {
            return AuthorityOpenResult.Failure(MapOpenFailure(opened.Failure, "ROOT"));
        }

        var handle = opened.Handle!;
        var facts = _native.GetFacts(handle);
        if (!facts.IsSuccess)
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("ROOT_IDENTITY_UNAVAILABLE");
        }

        if (facts.Facts!.ObjectKind != NativeObjectKind.Directory ||
            facts.Facts.ReparseKind == NativeReparseKind.Unsupported ||
            !WindowsCanonicalPath.TryParse(facts.Facts.CanonicalPath, out _))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("ROOT_TARGET_UNSUPPORTED");
        }

        return AuthorityOpenResult.Success(handle, facts.Facts.CanonicalPath, facts.Facts.Identity);
    }

    /// <summary>
    /// Opens the governed Handoff Retrieval store directory through the same
    /// opened-object/native filesystem identity machinery used for Local Files
    /// roots. Following reparse points means a configured junction/spelling that
    /// looks disjoint is resolved to its physical target so that R-01 structural
    /// non-exposure validation compares real filesystem identity, not lexical
    /// spelling. Handles are never exposed client-side and only the resolved
    /// canonical path + identity are returned.
    /// </summary>
    public AuthorityOpenResult OpenStore(string configuredPath)
    {
        var normalized = ValidateAbsoluteLocalPath(configuredPath);
        if (normalized.ErrorCode is not null)
        {
            return AuthorityOpenResult.Failure("HANDOFF_STORE_TARGET_UNSUPPORTED");
        }

        var opened = _native.OpenMetadata(normalized.Path!, followReparse: true);
        if (!opened.IsSuccess)
        {
            return AuthorityOpenResult.Failure(MapOpenFailure(opened.Failure, "HANDOFF_STORE"));
        }

        var handle = opened.Handle!;
        var facts = _native.GetFacts(handle);
        if (!facts.IsSuccess)
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("HANDOFF_STORE_IDENTITY_UNAVAILABLE");
        }

        if (facts.Facts!.ObjectKind != NativeObjectKind.Directory ||
            facts.Facts.ReparseKind == NativeReparseKind.Unsupported ||
            !WindowsCanonicalPath.TryParse(facts.Facts.CanonicalPath, out _))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure("HANDOFF_STORE_TARGET_UNSUPPORTED");
        }

        return AuthorityOpenResult.Success(handle, facts.Facts.CanonicalPath, facts.Facts.Identity);
    }

    public AclEvaluationResult EvaluateConfigurationAcl(SafeFileHandle handle)
    {
        var security = _native.GetSecurityDescriptor(handle);
        if (!security.IsSuccess)
        {
            return AclEvaluationResult.Untrusted("CONFIG_ACL_UNAVAILABLE");
        }

        try
        {
            var descriptor = new RawSecurityDescriptor(security.SecurityDescriptor!, 0);
            if (descriptor.Owner is null || descriptor.DiscretionaryAcl is null)
            {
                return AclEvaluationResult.Untrusted("CONFIG_ACL_AMBIGUOUS");
            }

            var allowedSids = GetAllowedAdministrativeSids();
            if (!allowedSids.Contains(descriptor.Owner.Value))
            {
                return AclEvaluationResult.Untrusted("CONFIG_OWNER_UNTRUSTED");
            }

            foreach (GenericAce ace in descriptor.DiscretionaryAcl)
            {
                if (ace is not QualifiedAce qualified)
                {
                    return AclEvaluationResult.Untrusted("CONFIG_ACL_AMBIGUOUS");
                }

                if (qualified.AceQualifier == AceQualifier.AccessAllowed &&
                    (qualified.AccessMask & WriteAuthorityMask) != 0 &&
                    !allowedSids.Contains(qualified.SecurityIdentifier.Value))
                {
                    return AclEvaluationResult.Untrusted("CONFIG_ACL_BROAD_WRITE");
                }
            }

            return AclEvaluationResult.Trusted();
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            return AclEvaluationResult.Untrusted("CONFIG_ACL_AMBIGUOUS");
        }
    }

    private static HashSet<string> GetAllowedAdministrativeSids()
    {
        var current = WindowsIdentity.GetCurrent().User?.Value;
        if (current is null)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }

        return new HashSet<string>(StringComparer.Ordinal)
        {
            current,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
        };
    }

    private (string? Path, string? ErrorCode) ValidateAbsoluteLocalPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            path.StartsWith("\\\\", StringComparison.Ordinal) || path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            path.StartsWith("\\\\.\\", StringComparison.Ordinal) || path.Length < 3 || path[1] != ':' || path[2] != '\\')
        {
            return (null, "PATH_UNSUPPORTED");
        }

        try
        {
            var fullPath = Path.GetFullPath(path);
            var driveRoot = Path.GetPathRoot(fullPath);
            if (driveRoot is null || !_native.IsFixedLocalDrive(driveRoot))
            {
                return (null, "PATH_UNSUPPORTED");
            }

            return (fullPath.TrimEnd(Path.DirectorySeparatorChar), null);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return (null, "PATH_UNSUPPORTED");
        }
    }

    private string? RejectConfigurationReparseComponents(string path)
    {
        var root = Path.GetPathRoot(path)!;
        var relative = path[root.Length..];
        var current = root.TrimEnd(Path.DirectorySeparatorChar);

        foreach (var component in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = current + Path.DirectorySeparatorChar + component;
            var opened = _native.OpenMetadata(current, followReparse: false);
            if (!opened.IsSuccess)
            {
                return MapOpenFailure(opened.Failure, "CONFIG");
            }

            using var handle = opened.Handle!;
            var facts = _native.GetFacts(handle);
            if (!facts.IsSuccess)
            {
                return "CONFIG_REPARSE_AMBIGUOUS";
            }

            if (facts.Facts!.ReparseKind != NativeReparseKind.None)
            {
                return facts.Facts.ReparseKind == NativeReparseKind.Unsupported
                    ? "CONFIG_REPARSE_AMBIGUOUS"
                    : "CONFIG_REPARSE_UNSAFE";
            }
        }

        return null;
    }

    private static string MapOpenFailure(NativeFailure failure, string subject) => failure switch
    {
        NativeFailure.NotFound => $"{subject}_NOT_FOUND",
        NativeFailure.AccessDenied => $"{subject}_INACCESSIBLE",
        NativeFailure.Unsupported or NativeFailure.InvalidPath => $"{subject}_TARGET_UNSUPPORTED",
        _ => $"{subject}_OPEN_FAILED",
    };
}

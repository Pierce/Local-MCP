using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using LocalMcp.Roots;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

[SupportedOSPlatform("windows")]
internal sealed class WindowsFileSystemAuthority : IWindowsFileSystemAuthority
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int SeFileObject = 1;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileIdInfoClass = 18;
    private const int WriteAuthorityMask = unchecked((int)0x500D0156);

    public AuthorityOpenResult OpenConfiguration(string explicitPath)
    {
        var normalized = ValidateAbsoluteLocalPath(explicitPath);
        if (normalized.ErrorCode is not null)
        {
            return AuthorityOpenResult.Failure("CONFIG_PATH_UNSUPPORTED");
        }

        var componentError = RejectReparseComponents(normalized.Path!);
        if (componentError is not null)
        {
            return AuthorityOpenResult.Failure(componentError);
        }

        var opened = Open(normalized.Path!, requireDirectory: false);
        if (!opened.IsSuccess)
        {
            return opened;
        }

        if (!string.Equals(NormalizeFinalPath(opened.CanonicalPath!), normalized.Path, StringComparison.OrdinalIgnoreCase))
        {
            opened.Handle!.Dispose();
            return AuthorityOpenResult.Failure("CONFIG_REPARSE_UNSAFE");
        }

        return opened;
    }

    public AuthorityOpenResult OpenRoot(string configuredPath)
    {
        var normalized = ValidateAbsoluteLocalPath(configuredPath);
        return normalized.ErrorCode is null
            ? Open(normalized.Path!, requireDirectory: true)
            : AuthorityOpenResult.Failure("ROOT_TARGET_UNSUPPORTED");
    }

    public AclEvaluationResult EvaluateConfigurationAcl(SafeFileHandle handle)
    {
        var result = GetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation | DaclSecurityInformation,
            out _, out _, out _, out _, out var securityDescriptor);
        if (result != 0 || securityDescriptor == IntPtr.Zero)
        {
            return AclEvaluationResult.Untrusted("CONFIG_ACL_UNAVAILABLE");
        }

        try
        {
            var length = checked((int)GetSecurityDescriptorLength(securityDescriptor));
            if (length <= 0)
            {
                return AclEvaluationResult.Untrusted("CONFIG_ACL_UNAVAILABLE");
            }

            var bytes = new byte[length];
            Marshal.Copy(securityDescriptor, bytes, 0, length);
            var descriptor = new RawSecurityDescriptor(bytes, 0);
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
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or OverflowException)
        {
            return AclEvaluationResult.Untrusted("CONFIG_ACL_AMBIGUOUS");
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
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

    private static (string? Path, string? ErrorCode) ValidateAbsoluteLocalPath(string path)
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
            if (driveRoot is null || GetDriveTypeW(driveRoot) != 3)
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

    private static string? RejectReparseComponents(string path)
    {
        var root = Path.GetPathRoot(path)!;
        var relative = path[root.Length..];
        var current = root.TrimEnd(Path.DirectorySeparatorChar);

        foreach (var component in relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            current = current + Path.DirectorySeparatorChar + component;
            using var handle = CreateFileW(current, 0, FileShareRead, IntPtr.Zero, OpenExisting,
                FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                return MapOpenError(Marshal.GetLastWin32Error(), "CONFIG");
            }

            if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out FileAttributeTagInfo tagInfo, Marshal.SizeOf<FileAttributeTagInfo>()))
            {
                return "CONFIG_REPARSE_AMBIGUOUS";
            }

            if ((tagInfo.FileAttributes & FileAttributeReparsePoint) != 0)
            {
                return "CONFIG_REPARSE_UNSAFE";
            }
        }

        return null;
    }

    private static AuthorityOpenResult Open(string path, bool requireDirectory)
    {
        var handle = CreateFileW(path, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            return AuthorityOpenResult.Failure(MapOpenError(error, requireDirectory ? "ROOT" : "CONFIG"));
        }

        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out FileAttributeTagInfo attributes, Marshal.SizeOf<FileAttributeTagInfo>()))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure(requireDirectory ? "ROOT_IDENTITY_UNAVAILABLE" : "CONFIG_IDENTITY_UNAVAILABLE");
        }

        var isDirectory = (attributes.FileAttributes & FileAttributeDirectory) != 0;
        if (isDirectory != requireDirectory)
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure(requireDirectory ? "ROOT_TARGET_UNSUPPORTED" : "CONFIG_NOT_REGULAR_FILE");
        }

        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId, Marshal.SizeOf<FileIdInfo>()))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure(requireDirectory ? "ROOT_IDENTITY_UNAVAILABLE" : "CONFIG_IDENTITY_UNAVAILABLE");
        }

        var canonicalPath = GetFinalPath(handle);
        if (canonicalPath is null || !canonicalPath.StartsWith("\\\\?\\", StringComparison.Ordinal) || canonicalPath.StartsWith("\\\\?\\UNC\\", StringComparison.OrdinalIgnoreCase))
        {
            handle.Dispose();
            return AuthorityOpenResult.Failure(requireDirectory ? "ROOT_TARGET_UNSUPPORTED" : "CONFIG_TARGET_UNSUPPORTED");
        }

        return AuthorityOpenResult.Success(handle, canonicalPath,
            new FileObjectIdentity(fileId.VolumeSerialNumber, Convert.ToHexString(fileId.FileId)));
    }

    private static string? GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32768)
        {
            var buffer = new char[capacity];
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0) return null;
            if (length < buffer.Length) return new string(buffer, 0, checked((int)length));
            capacity = checked((int)length + 1);
        }
        return null;
    }

    private static string NormalizeFinalPath(string path) =>
        path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path[4..].TrimEnd(Path.DirectorySeparatorChar) : path;

    private static string MapOpenError(int error, string subject) => error switch
    {
        2 or 3 => $"{subject}_NOT_FOUND",
        5 => $"{subject}_INACCESSIBLE",
        _ => $"{subject}_OPEN_FAILED",
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint FileAttributes; public uint ReparseTag; }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, [Out] char[] path, uint pathLength, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, out FileAttributeTagInfo information, int bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass, out FileIdInfo information, int bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern uint GetDriveTypeW(string rootPathName);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInformation, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

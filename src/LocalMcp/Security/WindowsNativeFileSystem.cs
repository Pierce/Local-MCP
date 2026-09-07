using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using LocalMcp.Roots;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

internal enum NativeFailure
{
    None,
    NotFound,
    AccessDenied,
    SharingViolation,
    InvalidPath,
    Unsupported,
    Failed,
}

internal enum NativeObjectKind
{
    File,
    Directory,
    Unsupported,
}

internal enum NativeReparseKind
{
    None,
    SymbolicLink,
    MountPoint,
    Unsupported,
}

internal sealed record NativeObjectFacts(
    string CanonicalPath,
    FileObjectIdentity Identity,
    NativeObjectKind ObjectKind,
    NativeReparseKind ReparseKind);

internal sealed record NativeOpenResult(SafeFileHandle? Handle, NativeFailure Failure)
{
    public bool IsSuccess => Handle is not null && !Handle.IsInvalid && Failure == NativeFailure.None;
    public static NativeOpenResult Success(SafeFileHandle handle) => new(handle, NativeFailure.None);
    public static NativeOpenResult Failed(NativeFailure failure) => new(null, failure);
}

internal sealed record NativeFactsResult(NativeObjectFacts? Facts, NativeFailure Failure)
{
    public bool IsSuccess => Facts is not null && Failure == NativeFailure.None;
    public static NativeFactsResult Success(NativeObjectFacts facts) => new(facts, NativeFailure.None);
    public static NativeFactsResult Failed(NativeFailure failure) => new(null, failure);
}

internal sealed record NativeSecurityResult(byte[]? SecurityDescriptor, NativeFailure Failure)
{
    public bool IsSuccess => SecurityDescriptor is not null && Failure == NativeFailure.None;
    public static NativeSecurityResult Success(byte[] descriptor) => new(descriptor, NativeFailure.None);
    public static NativeSecurityResult Failed(NativeFailure failure) => new(null, failure);
}

internal interface IWindowsNativeFileSystem
{
    NativeOpenResult OpenMetadata(string path, bool followReparse);
    NativeOpenResult OpenReadOnly(string path, bool followReparse);
    NativeFactsResult GetFacts(SafeFileHandle handle);
    NativeSecurityResult GetSecurityDescriptor(SafeFileHandle handle);
    bool IsFixedLocalDrive(string driveRoot);
}

/// <summary>
/// Narrow Windows-only interop boundary. It returns filesystem facts and handles;
/// application authorization policy remains in managed callers.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed class WindowsNativeFileSystem : IWindowsNativeFileSystem
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeDevice = 0x00000040;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint IoReparseTagMountPoint = 0xA0000003;
    private const uint IoReparseTagSymbolicLink = 0xA000000C;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint DaclSecurityInformation = 0x00000004;
    private const int SeFileObject = 1;
    private const int FileAttributeTagInfoClass = 9;
    private const int FileIdInfoClass = 18;

    public NativeOpenResult OpenMetadata(string path, bool followReparse) =>
        Open(path, FileReadAttributes, FileShareRead | FileShareWrite, followReparse);

    public NativeOpenResult OpenReadOnly(string path, bool followReparse) =>
        Open(path, GenericRead, FileShareRead, followReparse);

    public NativeFactsResult GetFacts(SafeFileHandle handle)
    {
        if (handle.IsInvalid || handle.IsClosed)
        {
            return NativeFactsResult.Failed(NativeFailure.Failed);
        }

        if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out FileAttributeTagInfo attributeInfo,
                checked((uint)Marshal.SizeOf<FileAttributeTagInfo>())))
        {
            return NativeFactsResult.Failed(MapError(Marshal.GetLastWin32Error()));
        }

        if (!GetFileInformationByHandleEx(handle, FileIdInfoClass, out FileIdInfo fileId,
                checked((uint)Marshal.SizeOf<FileIdInfo>())))
        {
            return NativeFactsResult.Failed(MapError(Marshal.GetLastWin32Error()));
        }

        var canonicalPath = GetFinalPath(handle);
        if (canonicalPath is null)
        {
            return NativeFactsResult.Failed(NativeFailure.Unsupported);
        }

        var objectKind = (attributeInfo.FileAttributes & FileAttributeDevice) != 0
            ? NativeObjectKind.Unsupported
            : (attributeInfo.FileAttributes & FileAttributeDirectory) != 0
                ? NativeObjectKind.Directory
                : NativeObjectKind.File;

        var reparseKind = (attributeInfo.FileAttributes & FileAttributeReparsePoint) == 0
            ? NativeReparseKind.None
            : attributeInfo.ReparseTag switch
            {
                IoReparseTagSymbolicLink => NativeReparseKind.SymbolicLink,
                IoReparseTagMountPoint => NativeReparseKind.MountPoint,
                _ => NativeReparseKind.Unsupported,
            };

        return NativeFactsResult.Success(new NativeObjectFacts(
            canonicalPath,
            new FileObjectIdentity(fileId.VolumeSerialNumber, Convert.ToHexString(fileId.FileId)),
            objectKind,
            reparseKind));
    }

    public NativeSecurityResult GetSecurityDescriptor(SafeFileHandle handle)
    {
        var result = GetSecurityInfo(handle, SeFileObject, OwnerSecurityInformation | DaclSecurityInformation,
            out _, out _, out _, out _, out var securityDescriptor);
        if (result != 0 || securityDescriptor == IntPtr.Zero)
        {
            return NativeSecurityResult.Failed(result == 0 ? NativeFailure.Failed : MapError(checked((int)result)));
        }

        try
        {
            var length = checked((int)GetSecurityDescriptorLength(securityDescriptor));
            if (length <= 0)
            {
                return NativeSecurityResult.Failed(NativeFailure.Failed);
            }

            var bytes = new byte[length];
            Marshal.Copy(securityDescriptor, bytes, 0, length);
            return NativeSecurityResult.Success(bytes);
        }
        catch (Exception exception) when (exception is OverflowException or OutOfMemoryException)
        {
            return NativeSecurityResult.Failed(NativeFailure.Failed);
        }
        finally
        {
            _ = LocalFree(securityDescriptor);
        }
    }

    public bool IsFixedLocalDrive(string driveRoot) => GetDriveTypeW(driveRoot) == 3;

    private static NativeOpenResult Open(string path, uint desiredAccess, uint shareMode, bool followReparse)
    {
        var flags = FileFlagBackupSemantics | (followReparse ? 0 : FileFlagOpenReparsePoint);
        var handle = CreateFileW(path, desiredAccess, shareMode, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var failure = MapError(Marshal.GetLastWin32Error());
            handle.Dispose();
            return NativeOpenResult.Failed(failure);
        }

        return NativeOpenResult.Success(handle);
    }

    private static string? GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (capacity <= 32768)
        {
            var buffer = new char[capacity];
            var length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (length == 0)
            {
                return null;
            }

            if (length < buffer.Length)
            {
                return new string(buffer, 0, checked((int)length));
            }

            capacity = checked((int)length + 1);
        }

        return null;
    }

    private static NativeFailure MapError(int error) => error switch
    {
        2 or 3 => NativeFailure.NotFound,
        5 => NativeFailure.AccessDenied,
        32 => NativeFailure.SharingViolation,
        87 or 123 or 161 => NativeFailure.InvalidPath,
        50 => NativeFailure.Unsupported,
        _ => NativeFailure.Failed,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfo
    {
        public ulong VolumeSerialNumber;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] FileId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, [Out] char[] path,
        uint pathLength, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
        out FileAttributeTagInfo information, uint bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle file, int informationClass,
        out FileIdInfo information, uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint GetDriveTypeW(string rootPathName);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType, uint securityInformation,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr securityDescriptor);

    [DllImport("advapi32.dll")]
    private static extern uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
}

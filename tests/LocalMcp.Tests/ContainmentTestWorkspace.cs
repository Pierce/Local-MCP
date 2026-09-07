using LocalMcp.Configuration;
using LocalMcp.Roots;
using LocalMcp.Security;
using System.Runtime.Versioning;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
internal sealed class ContainmentTestWorkspace : IDisposable
{
    public ContainmentTestWorkspace()
    {
        BasePath = Path.Combine(Path.GetTempPath(), $"local-mcp-inc2-{Guid.NewGuid():N}");
        RootPath = Path.Combine(BasePath, "authorized-root");
        OutsidePath = Path.Combine(BasePath, "outside-root");
        Directory.CreateDirectory(RootPath);
        Directory.CreateDirectory(OutsidePath);

        var authority = new WindowsFileSystemAuthority();
        var opened = authority.OpenRoot(RootPath);
        if (!opened.IsSuccess)
        {
            throw new InvalidOperationException(opened.ErrorCode);
        }

        var root = new ValidatedRoot("root", "Test root", [], opened.CanonicalPath!, opened.ObjectIdentity!, opened.Handle!);
        Registry = new ValidatedRootRegistry([root], new ConfigurationAuthorityIdentity(
            opened.CanonicalPath!, new FileObjectIdentity(ulong.MaxValue, "configuration"), new byte[32]));
        Native = new WindowsNativeFileSystem();
        Authorizer = new WindowsPathAuthorizer(Native);
    }

    public string BasePath { get; }
    public string RootPath { get; }
    public string OutsidePath { get; }
    public ValidatedRootRegistry Registry { get; }
    public WindowsNativeFileSystem Native { get; }
    public WindowsPathAuthorizer Authorizer { get; }

    public WindowsAuthorizationResult Authorize(string relativePath) => Authorizer.Authorize(Registry, "root", relativePath);

    public void Dispose()
    {
        Registry.Dispose();
        try { Directory.Delete(BasePath, recursive: true); }
        catch { }
    }
}

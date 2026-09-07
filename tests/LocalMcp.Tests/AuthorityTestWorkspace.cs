using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using LocalMcp.Configuration;
using LocalMcp.Security;

namespace LocalMcp.Tests;

[SupportedOSPlatform("windows")]
internal sealed class AuthorityTestWorkspace : IDisposable
{
    public AuthorityTestWorkspace(bool configurationInsideRoot = false)
    {
        BasePath = Path.Combine(Path.GetTempPath(), $"local-mcp-inc1-{Guid.NewGuid():N}");
        Directory.CreateDirectory(BasePath);
        ValidRootPath = Path.Combine(BasePath, "valid-root");
        Directory.CreateDirectory(ValidRootPath);
        ConfigurationPath = Path.Combine(configurationInsideRoot ? ValidRootPath : BasePath, "authority.toml");
    }

    public string BasePath { get; }
    public string ValidRootPath { get; }
    public string ConfigurationPath { get; }

    public void WriteConfiguration(string? text = null)
    {
        text ??= CurrentConfiguration(("valid", ValidRootPath, "Validated root", true));
        File.WriteAllText(ConfigurationPath, text, new System.Text.UTF8Encoding(false));
        ProtectConfigurationAcl();
    }

    public ConfigurationLoadResult Load(string? path = null, IWindowsFileSystemAuthority? authority = null) =>
        new ConfigurationAuthorityLoader(authority ?? new WindowsFileSystemAuthority()).Load(path ?? ConfigurationPath);

    public byte[] HashConfiguration() => SHA256.HashData(File.ReadAllBytes(ConfigurationPath));

    public static string CurrentConfiguration(params (string Id, string Path, string? Description, bool Enabled)[] roots)
    {
        var lines = new List<string> { "schema_version = 1", string.Empty };
        foreach (var root in roots)
        {
            lines.Add("[[roots]]");
            lines.Add($"id = '{root.Id}'");
            lines.Add($"path = '{root.Path}'");
            if (root.Description is not null) lines.Add($"description = '{root.Description}'");
            lines.Add($"enabled = {root.Enabled.ToString().ToLowerInvariant()}");
            lines.Add(string.Empty);
        }
        return string.Join(Environment.NewLine, lines);
    }

    public void GrantEveryoneWrite()
    {
        var file = new FileInfo(ConfigurationPath);
        var security = file.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteAttributes,
            AccessControlType.Allow));
        file.SetAccessControl(security);
    }

    private void ProtectConfigurationAcl()
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var security = new FileSecurity();
        security.SetOwner(current);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(current, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(ConfigurationPath).SetAccessControl(security);
    }

    public void Dispose()
    {
        try { Directory.Delete(BasePath, recursive: true); }
        catch { }
    }
}

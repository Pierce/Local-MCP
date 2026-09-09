using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using LocalMcp.Configuration;
using LocalMcp.Security;

namespace LocalMcp.Tests;

/// <summary>
/// DCA-HR-001 targeted R-01 structural Local Files non-exposure tests.
/// Validates the governed Handoff Retrieval store is rejected when it is
/// physically contained by, or containing, an active Local Files root,
/// including when a reparse/junction alias hides the relationship on either side.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class HandoffRetrievalR01TargetedTests : IDisposable
{
    private const string Recipient = "r01-test-recipient-v1";
    private static readonly byte[] HmacKey = RandomNumberGenerator.GetBytes(32);
    private readonly string _basePath;
    private readonly string _rootPath;
    private readonly string _storePath;
    private string _configPath = string.Empty;

    public HandoffRetrievalR01TargetedTests()
    {
        _basePath = Path.Combine(Path.GetTempPath(), $"local-mcp-dca-hr-001-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_basePath);
        _rootPath = Path.Combine(_basePath, "root");
        _storePath = Path.Combine(_basePath, "store");
    }

    public void Dispose()
    {
        try { DeleteDirectoryTraversingJunctions(_basePath); }
        catch { }
    }

    private static void DeleteDirectoryTraversingJunctions(string root)
    {
        if (!Directory.Exists(root)) return;

        // Manual depth-first enumeration that never descends into reparse points,
        // so a junction link is treated as a leaf and never followed.
        var ordered = new List<string>();
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            ordered.Add(current);
            foreach (var dir in Directory.GetDirectories(current))
            {
                var info = new DirectoryInfo(dir);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0)
                    stack.Push(dir);
            }
        }

        foreach (var dir in ordered.OrderByDescending(d => d.Length))
        {
            if (!Directory.Exists(dir)) continue;
            var info = new DirectoryInfo(dir);
            if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                // Directory.Delete on a junction removes only the link, never the target.
                Directory.Delete(dir, recursive: false);
                continue;
            }

            try { Directory.Delete(dir, recursive: true); }
            catch { }
        }
    }

    private string WriteConfig(string storePath, params string[] rootPaths)
    {
        _configPath = Path.Combine(_basePath, "authority-r01.toml");
        File.WriteAllText(_configPath, BuildToml(storePath, rootPaths), new UTF8Encoding(false));
        ProtectConfigAcl(_configPath);
        return _configPath;
    }

    private ConfigurationLoadResult Load() =>
        new ConfigurationAuthorityLoader(new WindowsFileSystemAuthority()).Load(_configPath);

    private static void ProtectConfigAcl(string path)
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
        new FileInfo(path).SetAccessControl(security);
    }

    private static void AssertRejected(ConfigurationLoadResult result, string testId)
    {
        Assert.False(result.IsSuccess, $"{testId}: expected startup rejection, but configuration was accepted.");
        Assert.Equal("HANOFF_STORE_EXPOSED_BY_ROOT", result.FatalErrorCode);
    }

    private static string BuildToml(string storePath, string[] rootPaths)
    {
        var sb = new StringBuilder();
        sb.AppendLine("schema_version = 1");
        foreach (var rootPath in rootPaths)
        {
            sb.AppendLine("[[roots]]");
            sb.AppendLine("id = 'root'");
            sb.AppendLine($"path = '{rootPath}'");
            sb.AppendLine("enabled = true");
            sb.AppendLine();
        }

        sb.AppendLine("[handoff_retrieval]");
        sb.AppendLine("enabled = true");
        sb.AppendLine($"store_path = '{storePath}'");
        sb.AppendLine($"intended_recipient_reference = '{Recipient}'");
        sb.AppendLine($"hmac_key_base64 = '{Convert.ToBase64String(HmacKey)}'");
        return sb.ToString();
    }

    // ----------------------------- R01-P1 --------------------------------
    // Safe disjoint positive control: physical store and root are disjoint.
    [Fact]
    public void R01P1_SafeDisjointRootAndStore_IsAccepted()
    {
        Directory.CreateDirectory(_rootPath);
        Directory.CreateDirectory(_storePath);
        WriteConfig(_storePath, _rootPath);

        var result = Load();
        Assert.True(result.IsSuccess, result.FatalErrorCode);
        Assert.Equal(Recipient, result.Configuration!.HandoffRetrieval.IntendedRecipientReference);
    }

    // ----------------------------- R01-N1 --------------------------------
    // Direct store under active Local Files root.
    [Fact]
    public void R01N1_StoreDirectlyUnderRoot_IsRejected()
    {
        Directory.CreateDirectory(_rootPath);
        var storeUnderRoot = Path.Combine(_rootPath, "store");
        Directory.CreateDirectory(storeUnderRoot);
        WriteConfig(storeUnderRoot, _rootPath);

        AssertRejected(Load(), "R01-N1");
    }

    // ----------------------------- R01-N2 --------------------------------
    // Active Local Files root under the store (governed structural rule).
    [Fact]
    public void R01N2_RootUnderStore_IsRejected()
    {
        Directory.CreateDirectory(_storePath);
        var rootUnderStore = Path.Combine(_storePath, "root");
        Directory.CreateDirectory(rootUnderStore);
        WriteConfig(_storePath, rootUnderStore);

        AssertRejected(Load(), "R01-N2");
    }

    // ----------------------------- R01-N3 --------------------------------
    // Local Files root junction resolves into the store (real junction fixture).
    // Previously failed closed; the repair must preserve that behavior.
    [Fact]
    public void R01N3_RootJunctionResolvingIntoStore_IsRejected()
    {
        Directory.CreateDirectory(_storePath);
        var aliasBase = Path.Combine(_basePath, "alias");
        Directory.CreateDirectory(aliasBase);
        var rootView = Path.Combine(aliasBase, "root-view");
        WindowsLinkTestSupport.CreateJunction(rootView, _storePath);

        WriteConfig(_storePath, rootView);
        AssertRejected(Load(), "R01-N3");
    }

    // ----------------------------- R01-N4 --------------------------------
    // Handoff store junction resolves beneath an active Local Files root.
    // Configured store spelling appears outside the root; physical target is
    // inside it. The exact DCA-HR-001 case (mandatory for closure).
    [Fact]
    public void R01N4_StoreJunctionResolvingUnderRoot_IsRejected()
    {
        Directory.CreateDirectory(_rootPath);
        var physicalStore = Path.Combine(_rootPath, "handoff-store");
        Directory.CreateDirectory(physicalStore);
        var aliasBase = Path.Combine(_basePath, "alias");
        Directory.CreateDirectory(aliasBase);
        var storeView = Path.Combine(aliasBase, "store-view");
        WindowsLinkTestSupport.CreateJunction(storeView, physicalStore);

        WriteConfig(storeView, _rootPath);
        AssertRejected(Load(), "R01-N4");
    }

    // ----------------------------- R01-N5 --------------------------------
    // Configuration change from safe to unsafe: fresh validation rejects the
    // changed authority configuration that would physically expose the store.
    // Each phase is an independent per-startup validation (no hot-reload).
    [Fact]
    public void R01N5_ConfigChangeFromSafeToUnsafe_IsRejectedOnFreshValidation()
    {
        Directory.CreateDirectory(_rootPath);
        Directory.CreateDirectory(_storePath);

        // Phase 1: safe configuration accepted on fresh validation.
        WriteConfig(_storePath, _rootPath);
        var safe = Load();
        Assert.True(safe.IsSuccess, safe.FatalErrorCode);

        // Phase 2: a changed authority configuration that physically exposes the
        // store through Local Files (store moved under root) must be rejected.
        var storeUnderRoot = Path.Combine(_rootPath, "store");
        Directory.CreateDirectory(storeUnderRoot);
        WriteConfig(storeUnderRoot, _rootPath);
        AssertRejected(Load(), "R01-N5");
    }
}

using System.Security.Cryptography;
using LocalMcp.Handoff;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

public class HandoffRetrievalClientVisibleTests
{
    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);
    private const string Store = @"C:\Users\Wayne\Development\Local-MCP\tests\LocalMcp.Tests\test-handoff-store-client";
    private const string Recipient = "test-recipient-v1";
    private const string Id = "r4-test-id";
    private const string Schema = "0.2";

    public HandoffRetrievalClientVisibleTests() { Clean(); }

    private static void Clean()
    {
        foreach (var d in new[] { Path.Combine(Store, "manifests"), Path.Combine(Store, "payloads") })
            if (Directory.Exists(d))
                foreach (var f in Directory.GetFiles(d)) try { File.Delete(f); } catch { }
    }

    private void Setup(bool avail = true) =>
        HandoffTestHelpers.CreateStagedRecord(Store, Id, Schema, Recipient, "test payload", Key, available: avail);

    private HandoffStore S(string? r = null) => new(HandoffTestHelpers.CreateTestConfig(Store, r ?? Recipient, Key));

    [Fact]
    public void SensitiveFailures_CollapseToGeneric_IsNonEnumerating()
    {
        Setup();
        var store = S();
        var tool = new GetHandoffTool(store);

        // Known good - success
        var ok = tool.GetHandoff(Id);
        Assert.Null(ok.ErrorCode);
        Assert.Equal(Id, ok.HandoffId);

        // Unknown ID
        var unk = tool.GetHandoff("unknown-test-id");
        Assert.Equal("HANOFF_NOT_RETRIEVABLE", unk.ErrorCode);

        // Cross-recipient
        var cross = new GetHandoffTool(S("different-recipient")).GetHandoff(Id);
        Assert.Equal("HANOFF_NOT_RETRIEVABLE", cross.ErrorCode);

        // Unavailable
        Setup(avail: false);
        var una = new GetHandoffTool(store).GetHandoff(Id);
        Assert.Equal("HANOFF_NOT_RETRIEVABLE", una.ErrorCode);

        // All sensitive failures produce identical code
        Assert.Equal(unk.ErrorCode, cross.ErrorCode);
        Assert.Equal(cross.ErrorCode, una.ErrorCode);

        Setup(avail: true);
    }

    [Fact]
    public void MalformedSyntax_IsDistinguishable()
    {
        var tool = new GetHandoffTool(S());
        Assert.Equal("HANDOFF_ID_SYNTAX_INVALID", tool.GetHandoff("a/b").ErrorCode);
        Assert.Equal("HANDOFF_ID_SYNTAX_INVALID", tool.GetHandoff("").ErrorCode);
        Assert.Equal("HANDOFF_ID_SYNTAX_INVALID", tool.GetHandoff("..").ErrorCode);
    }

    [Fact]
    public void ToolInventory_ContainsOnlyGetHandoff()
    {
        var methods = typeof(GetHandoffTool).GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance)
            .Select(m => m.Name).ToArray();
        Assert.Contains("GetHandoff", methods);
        Assert.DoesNotContain("ListHandoffs", methods);
        Assert.DoesNotContain("SearchHandoffs", methods);
        Assert.DoesNotContain("GetLatestHandoff", methods);
        Assert.DoesNotContain("GetPendingHandoff", methods);
    }
}
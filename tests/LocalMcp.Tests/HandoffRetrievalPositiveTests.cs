using System.Security.Cryptography;
using System.Text;
using LocalMcp.Handoff;

namespace LocalMcp.Tests;

/// <summary>
/// Positive / acceptance tests for DSR-2026-0014 Handoff Retrieval capability.
/// Uses its own isolated store directory.
/// </summary>
public class HandoffRetrievalPositiveTests
{
    private static readonly byte[] TestHmacKey = RandomNumberGenerator.GetBytes(32);
    internal const string TestStorePath = @"C:\Users\Wayne\Development\Local-MCP\tests\LocalMcp.Tests\test-handoff-store-positive";
    private const string TestRecipient = "test-recipient-v1";
    private const string TestHandoffId = "test-handoff-001";
    private const string TestTransportSchema = "0.2";
    private const string TestPayload = "This is a governed handoff payload for testing.";

    public HandoffRetrievalPositiveTests() => CleanStore();

    private static void CleanStore()
    {
        foreach (var dir in new[] { Path.Combine(TestStorePath, "manifests"), Path.Combine(TestStorePath, "payloads") })
            if (Directory.Exists(dir))
                foreach (var f in Directory.GetFiles(dir)) try { File.Delete(f); } catch { }
    }

    private string SetupRecord(string? id = null, string? recipient = null, string? payload = null, bool avail = true)
    {
        var i = id ?? TestHandoffId;
        var r = recipient ?? TestRecipient;
        var p = payload ?? TestPayload;
        return HandoffTestHelpers.CreateStagedRecord(TestStorePath, i, TestTransportSchema, r, p, TestHmacKey, available: avail);
    }

    private HandoffStore CreateStore() => new(HandoffTestHelpers.CreateTestConfig(TestStorePath, TestRecipient, TestHmacKey));

    [Fact]
    public void ExactIdLookup_RetrievesExactlyOneCorrectGovernedRecord()
    {
        SetupRecord();
        var result = CreateStore().TryGetHandoff(TestHandoffId);
        Assert.True(result.IsSuccess);
        Assert.Equal(TestHandoffId, result.Record!.HandoffId);
        Assert.Equal(TestTransportSchema, result.Record.TransportSchemaVersion);
        Assert.Equal(TestRecipient, result.Record.IntendedRecipientReference);
    }

    [Fact]
    public void PayloadIdentity_VerifiedImmediatelyBeforeReturn()
    {
        SetupRecord();
        var result = CreateStore().TryGetHandoff(TestHandoffId);
        Assert.True(result.IsSuccess);
        var expected = HandoffTestHelpers.ComputeSha256Hex(Encoding.UTF8.GetBytes(TestPayload));
        Assert.Equal(expected, result.Record!.PayloadIdentity);
        Assert.Equal(expected, HandoffTestHelpers.ComputeSha256Hex(result.PayloadBytes!));
    }

    [Fact]
    public void ConfiguredRecipientMatch_IsExactAndMechanicalOnly()
    {
        SetupRecord();
        var result = CreateStore().TryGetHandoff(TestHandoffId);
        Assert.True(result.IsSuccess);
        Assert.Equal(TestRecipient, result.Record!.IntendedRecipientReference);
    }

    [Fact]
    public void GovernedStagingProvenance_IsIndependentlyTestable()
    {
        SetupRecord();
        var result = CreateStore().TryGetHandoff(TestHandoffId);
        Assert.True(result.IsSuccess);
        Assert.True(StagingIntegrity.VerifyHmac(TestHmacKey, result.Record!));
        Assert.True(StagingIntegrity.VerifyPayloadIdentity(result.Record!.PayloadIdentity, result.PayloadBytes!));
    }

    [Fact]
    public void RepeatedRetrieval_ReturnsSameBytesAndIdentity()
    {
        SetupRecord();
        var store = CreateStore();
        var r1 = store.TryGetHandoff(TestHandoffId);
        var r2 = store.TryGetHandoff(TestHandoffId);
        Assert.True(r1.IsSuccess && r2.IsSuccess);
        Assert.Equal(r1.PayloadBytes!, r2.PayloadBytes!);
        Assert.Equal(r1.Record!.PayloadIdentity, r2.Record!.PayloadIdentity);
    }

    [Fact]
    public void RepeatedRetrieval_DoesNotMutateContentOrLifecycle()
    {
        SetupRecord();
        var store = CreateStore();
        var r1 = store.TryGetHandoff(TestHandoffId);
        Assert.True(r1.IsSuccess);
        var r2 = store.TryGetHandoff(TestHandoffId);
        Assert.True(r2.IsSuccess);
        var r3 = store.TryGetHandoff(TestHandoffId);
        Assert.True(r3.IsSuccess);
        Assert.Equal(r1.PayloadBytes, r2.PayloadBytes);
        Assert.Equal(r1.PayloadBytes, r3.PayloadBytes);
    }

    [Fact]
    public void Retrieval_DoesNotMutateHandoffFiles()
    {
        SetupRecord();
        var store = CreateStore();
        var mPath = Path.Combine(TestStorePath, "manifests", $"{TestHandoffId}.manifest.json");
        var pPath = Path.Combine(TestStorePath, "payloads", $"{TestHandoffId}.payload.bin");
        var beforeManifest = File.ReadAllBytes(mPath);
        var beforePayload = File.ReadAllBytes(pPath);
        store.TryGetHandoff(TestHandoffId);
        Assert.Equal(beforeManifest, File.ReadAllBytes(mPath));
        Assert.Equal(beforePayload, File.ReadAllBytes(pPath));
    }

    [Fact]
    public void StagingAvailability_IsMechanicalOnly_NoLifecycleMeaning()
    {
        SetupRecord(avail: false);
        var result = CreateStore().TryGetHandoff(TestHandoffId);
        Assert.False(result.IsSuccess);
        Assert.Equal(RetrievalFailureCategory.Unavailable, result.Category);
    }
}
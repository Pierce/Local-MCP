using System.Security.Cryptography;
using System.Text;
using LocalMcp.Configuration;
using LocalMcp.Handoff;

namespace LocalMcp.Tests;

public class HandoffRetrievalAuthNTests
{
    private static readonly byte[] TestHmacKey = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] WrongHmacKey = Encoding.UTF8.GetBytes("wrong-key-for-testing");
    private const string Store = @"C:\Users\Wayne\Development\Local-MCP\tests\LocalMcp.Tests\test-handoff-store-authn";
    private const string Recipient = "test-recipient-v1";
    private const string Id = "auth-test-id";
    private const string Schema = "0.2";
    private const string Payload = "Auth test payload.";

    public HandoffRetrievalAuthNTests() { Clean(); }

    private static void Clean()
    {
        foreach (var d in new[] { Path.Combine(Store, "manifests"), Path.Combine(Store, "payloads") })
            if (Directory.Exists(d))
                foreach (var f in Directory.GetFiles(d)) try { File.Delete(f); } catch { }
    }

    private void Setup(string? id = null, string? payload = null, bool avail = true) =>
        HandoffTestHelpers.CreateStagedRecord(Store, id ?? Id, Schema, Recipient, payload ?? Payload, TestHmacKey, available: avail);

    private HandoffStore S() => new(HandoffTestHelpers.CreateTestConfig(Store, Recipient, TestHmacKey));

    private HandoffStore X() => new(HandoffTestHelpers.CreateTestConfig(Store, "other-recipient", TestHmacKey));

    [Fact] public void MalformedId_Rejected()
    {
        var s = S();
        Assert.False(s.TryGetHandoff("").IsSuccess);
        Assert.False(s.TryGetHandoff("a/b").IsSuccess);
        Assert.False(s.TryGetHandoff("..").IsSuccess);
        Assert.False(s.TryGetHandoff("a b").IsSuccess);
        Assert.False(s.TryGetHandoff("a:b").IsSuccess);
    }

    [Fact] public void UnknownId_ReturnsFailure() { Setup(); Assert.Equal(RetrievalFailureCategory.UnknownId, S().TryGetHandoff("nope").Category); }

    [Fact] public void CrossRecipient_ReturnsFailure() { Setup(); Assert.Equal(RetrievalFailureCategory.CrossRecipient, X().TryGetHandoff(Id).Category); }

    [Fact] public void Unavailable_ReturnsFailure() { Setup(avail: false); Assert.Equal(RetrievalFailureCategory.Unavailable, S().TryGetHandoff(Id).Category); }

    [Fact] public void PayloadTampered_CausesIntegrityFailure()
    {
        Setup();
        File.WriteAllBytes(Path.Combine(Store, "payloads", $"{Id}.payload.bin"), Encoding.UTF8.GetBytes("X"));
        Assert.Equal(RetrievalFailureCategory.PayloadIntegrityFailed, S().TryGetHandoff(Id).Category);
        File.WriteAllBytes(Path.Combine(Store, "payloads", $"{Id}.payload.bin"), Encoding.UTF8.GetBytes(Payload));
    }

    [Fact] public void PayloadIdentitySubstituted_CausesIntegrityFailure()
    {
        Setup();
        File.WriteAllBytes(Path.Combine(Store, "payloads", $"{Id}.payload.bin"), Encoding.UTF8.GetBytes("DIFFERENT"));
        Assert.Equal(RetrievalFailureCategory.PayloadIntegrityFailed, S().TryGetHandoff(Id).Category);
        File.WriteAllBytes(Path.Combine(Store, "payloads", $"{Id}.payload.bin"), Encoding.UTF8.GetBytes(Payload));
    }

    [Fact] public void UnauthorizedRecord_WithoutKey_FailsProvenance()
    {
        HandoffTestHelpers.CreateUnauthorizedRecord(Store, "bad-handoff", Schema, Recipient, "bad", WrongHmacKey);
        Assert.Equal(RetrievalFailureCategory.ManifestIntegrityFailed, S().TryGetHandoff("bad-handoff").Category);
    }

    [Fact] public void SelfConsistentButUnauthorized_FailsProvenance()
    {
        HandoffTestHelpers.CreateStagedRecord(Store, "zero-attack", Schema, Recipient, "self-consistent", new byte[32], stagingWriter: "attacker");
        Assert.False(S().TryGetHandoff("zero-attack").IsSuccess);
    }

    [Fact] public void TransportSchemaSubstitution_Fails()
    {
        Setup();
        var m = Path.Combine(Store, "manifests", $"{Id}.manifest.json");
        File.WriteAllText(m, File.ReadAllText(m).Replace("\"0.2\"", "\"9.9\""));
        Assert.False(S().TryGetHandoff(Id).IsSuccess);
        Setup();
    }

    [Fact] public void CrossPayloadRecordSwap_FailsIntegrity()
    {
        Setup(id: "a", payload: "A"); Setup(id: "b", payload: "B");
        File.WriteAllBytes(Path.Combine(Store, "payloads", "a.payload.bin"), Encoding.UTF8.GetBytes("B"));
        Assert.Equal(RetrievalFailureCategory.PayloadIntegrityFailed, S().TryGetHandoff("a").Category);
        File.WriteAllBytes(Path.Combine(Store, "payloads", "a.payload.bin"), Encoding.UTF8.GetBytes("A"));
    }

    [Fact] public void OversizedPayload_Rejected()
    {
        var tight = new HandoffRetrievalConfig(true, Store, Recipient, TestHmacKey, 50, 65536);
        Setup(payload: new string('X', 200));
        Assert.Equal(RetrievalFailureCategory.PayloadSizeExceeded, new HandoffStore(tight).TryGetHandoff(Id).Category);
        Setup();
    }

    [Fact] public void HandoffIdInManifestSubstituted_Fails()
    {
        Setup();
        var m = Path.Combine(Store, "manifests", $"{Id}.manifest.json");
        File.WriteAllText(m, File.ReadAllText(m).Replace(Id, "x-different"));
        Assert.False(S().TryGetHandoff(Id).IsSuccess);
        Setup();
    }
}
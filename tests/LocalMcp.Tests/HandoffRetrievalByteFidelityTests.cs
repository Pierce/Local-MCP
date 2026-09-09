using System.Security.Cryptography;
using System.Text;
using LocalMcp.Handoff;
using LocalMcp.Tools;

namespace LocalMcp.Tests;

/// <summary>
/// R-03 Exact byte fidelity tests for Handoff Retrieval.
/// Tests that payload bytes round-trip exactly through Base64 MCP representation.
/// </summary>
public class HandoffRetrievalByteFidelityTests
{
    private static readonly byte[] TestHmacKey = RandomNumberGenerator.GetBytes(32);
    private const string TestStorePath = @"C:\Users\Wayne\Development\Local-MCP\tests\LocalMcp.Tests\test-handoff-store-bytes";
    private const string TestRecipient = "test-recipient-v1";
    private const string TestTransportSchema = "0.2";

    private readonly HandoffStore _store;

    public HandoffRetrievalByteFidelityTests()
    {
        CleanStore();
        _store = new HandoffStore(HandoffTestHelpers.CreateTestConfig(TestStorePath, TestRecipient, TestHmacKey));
    }

    private static void CleanStore()
    {
        foreach (var dir in new[] { Path.Combine(TestStorePath, "manifests"), Path.Combine(TestStorePath, "payloads") })
            if (Directory.Exists(dir))
                foreach (var f in Directory.GetFiles(dir)) try { File.Delete(f); } catch { }
    }

    /// <summary>
    /// Tests every required byte-fidelity edge case: exact original bytes,
    /// expected SHA-256, MCP representation, reconstructed bytes,
    /// reconstructed SHA-256, and byte-equivalence result.
    /// </summary>
    [Fact]
    public void AllRequiredByteEdgeCases_RoundTripExactly()
    {
        var results = new List<ByteFidelityResult>();

        foreach (var kvp in HandoffTestHelpers.ByteFidelityCases)
        {
            var caseName = kvp.Key;
            var content = kvp.Value;
            var originalBytes = HandoffTestHelpers.GetPayloadBytes(content);
            var expectedSha256 = HandoffTestHelpers.ComputeSha256Hex(originalBytes);

            var id = $"byte-{caseName}";
            HandoffTestHelpers.CreateStagedRecord(TestStorePath, id, TestTransportSchema, TestRecipient, content, TestHmacKey);

            var retrieval = _store.TryGetHandoff(id);
            Assert.True(retrieval.IsSuccess, $"'{caseName}' retrieval should succeed");
            Assert.Equal(expectedSha256, retrieval.Record!.PayloadIdentity);

            // Verify payload identity against reconstructed bytes
            var reconstructedSha256 = HandoffTestHelpers.ComputeSha256Hex(retrieval.PayloadBytes!);
            Assert.Equal(expectedSha256, reconstructedSha256);

            // Exact byte comparison
            Assert.Equal(originalBytes.Length, retrieval.PayloadBytes!.Length);
            Assert.Equal(originalBytes, retrieval.PayloadBytes);

            // MCP Base64 round-trip
            var base64 = Convert.ToBase64String(originalBytes);
            var fromBase64 = Convert.FromBase64String(base64);
            var base64Sha256 = HandoffTestHelpers.ComputeSha256Hex(fromBase64);
            Assert.Equal(expectedSha256, base64Sha256);
            Assert.Equal(originalBytes, fromBase64);

            results.Add(new ByteFidelityResult(caseName, expectedSha256, base64, reconstructedSha256, true));
        }

        // All cases must pass - report any failures
        Assert.All(results, r => Assert.True(r.Passed, $"Byte fidelity case '{r.CaseName}' passed"));
    }

    /// <summary>
    /// Verify GetHandoffTool response Base64 round-trip preserves byte identity.
    /// </summary>
    [Fact]
    public void GetHandoffResponse_Base64RoundTrip_PreservesByteIdentity()
    {
        var testPayload = "Test payload with special chars: 🌍 \u00E9 \u20DE";
        var originalBytes = Encoding.UTF8.GetBytes(testPayload);
        var expectedSha256 = HandoffTestHelpers.ComputeSha256Hex(originalBytes);

        HandoffTestHelpers.CreateStagedRecord(TestStorePath, "base64-roundtrip-test",
            TestTransportSchema, TestRecipient, testPayload, TestHmacKey);

        var tool = new GetHandoffTool(_store);
        var response = tool.GetHandoff("base64-roundtrip-test");

        Assert.Null(response.ErrorCode);
        Assert.Equal(expectedSha256, response.PayloadIdentity);

        var reconstructed = Convert.FromBase64String(response.PayloadBase64!);
        var reconstructedSha256 = HandoffTestHelpers.ComputeSha256Hex(reconstructed);

        Assert.Equal(expectedSha256, reconstructedSha256);
        Assert.Equal(originalBytes, reconstructed);
    }
}

public sealed record ByteFidelityResult(
    string CaseName,
    string ExpectedSha256Hex,
    string MimeBase64,
    string ReconstructedSha256Hex,
    bool Passed);
using System.ComponentModel;
using System.Text.Json.Serialization;
using LocalMcp.Roots;
using ModelContextProtocol.Server;

namespace LocalMcp.Tools;

[McpServerToolType]
public sealed class ListRootsTool
{
    private readonly ValidatedRootRegistry _registry;

    public ListRootsTool(ValidatedRootRegistry registry) => _registry = registry;

    [McpServerTool(Name = "list_roots", ReadOnly = true, Idempotent = true)]
    [Description("Lists validated logical roots without exposing host filesystem paths.")]
    public ListRootsResponse ListRoots() => new(
        _registry.Roots.OrderBy(root => root.Id, StringComparer.Ordinal)
            .Select(root => new RootSummary(root.Id, root.Description, Array.Empty<string>())).ToArray());
}

public sealed record ListRootsResponse(
    [property: JsonPropertyName("roots")] IReadOnlyList<RootSummary> Roots);

public sealed record RootSummary(
    [property: JsonPropertyName("root_id")] string RootId,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("capabilities")] IReadOnlyList<string> Capabilities);

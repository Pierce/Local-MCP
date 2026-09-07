using System.ComponentModel;
using System.Text.Json.Serialization;
using LocalMcp.Roots;
using LocalMcp.Security;
using ModelContextProtocol.Server;

namespace LocalMcp.Tools;

[McpServerToolType]
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class StatTool
{
    private readonly ValidatedRootRegistry _registry;
    private readonly WindowsPathAuthorizer _authorizer;
    private readonly IWindowsNativeFileSystem _native;
    private readonly SensitivePathPolicy _policy;

    public StatTool(ValidatedRootRegistry registry)
        : this(registry, new WindowsNativeFileSystem())
    {
    }

    internal StatTool(ValidatedRootRegistry registry, IWindowsNativeFileSystem native)
    {
        _registry = registry;
        _native = native;
        _authorizer = new WindowsPathAuthorizer(native);
        _policy = new SensitivePathPolicy();
    }

    [McpServerTool(Name = "stat", ReadOnly = true, Idempotent = true)]
    [Description("Returns minimized metadata for one authorized file or directory.")]
    public StatResponse Stat(string root_id, string path)
    {
        if (!_registry.TryGet(root_id, out var root) || root is null)
            return StatResponse.Failure("ROOT_NOT_FOUND");

        // Deny valid lexical sensitive namespaces before opening the target. This makes present
        // and absent directly named denied objects indistinguishable to the caller.
        if (_policy.IsLexicallyDenied(root, path))
            return StatResponse.Failure("ACCESS_DENIED");

        var authorization = _authorizer.Authorize(_registry, root_id, path);
        if (!authorization.IsAuthorized)
            return StatResponse.Failure(MapAuthorizationFailure(authorization.Outcome));

        using var target = authorization.AuthorizedObject!;
        // Retain the post-open check for canonical aliases and object-identity-only exclusions.
        if (_policy.IsDenied(root, target, _registry.DeniedConfiguration))
            return StatResponse.Failure("ACCESS_DENIED");

        var metadata = _native.GetMetadata(target.Handle, target.Facts.ObjectKind);
        if (!metadata.IsSuccess)
            return StatResponse.Failure(MapMetadataFailure(metadata.Failure));

        return StatResponse.Success(
            root.Id,
            target.RelativePath,
            target.Facts.ObjectKind == NativeObjectKind.Directory ? "directory" : "file",
            metadata.Metadata!.Size,
            metadata.Metadata.ModifiedTimeUtc,
            readableAsText: false);
    }

    private static string MapAuthorizationFailure(AuthorizationOutcome outcome) => outcome switch
    {
        AuthorizationOutcome.RootNotFound => "ROOT_NOT_FOUND",
        AuthorizationOutcome.PathInvalid => "PATH_INVALID",
        AuthorizationOutcome.PathOutsideRoot => "PATH_OUTSIDE_ROOT",
        AuthorizationOutcome.NotFound => "NOT_FOUND",
        AuthorizationOutcome.PathChanged => "PATH_CHANGED",
        AuthorizationOutcome.InternalError => "INTERNAL_ERROR",
        _ => "ACCESS_DENIED",
    };

    private static string MapMetadataFailure(NativeFailure failure) => failure switch
    {
        NativeFailure.NotFound => "NOT_FOUND",
        NativeFailure.SharingViolation => "PATH_CHANGED",
        NativeFailure.Failed => "INTERNAL_ERROR",
        _ => "ACCESS_DENIED",
    };
}

public sealed record StatResponse(
    [property: JsonPropertyName("root_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RootId,
    [property: JsonPropertyName("relative_path"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RelativePath,
    [property: JsonPropertyName("type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Type,
    [property: JsonPropertyName("size"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Size,
    [property: JsonPropertyName("modified_time"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTimeOffset? ModifiedTime,
    [property: JsonPropertyName("readable_as_text"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? ReadableAsText,
    [property: JsonPropertyName("error_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ErrorCode)
{
    public static StatResponse Success(string rootId, string relativePath, string type, long? size,
        DateTimeOffset modifiedTime, bool readableAsText) =>
        new(rootId, relativePath, type, size, modifiedTime, readableAsText, null);

    public static StatResponse Failure(string errorCode) =>
        new(null, null, null, null, null, null, errorCode);
}

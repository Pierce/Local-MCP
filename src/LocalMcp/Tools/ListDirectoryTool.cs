using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json.Serialization;
using LocalMcp.Roots;
using LocalMcp.Security;
using ModelContextProtocol.Server;

namespace LocalMcp.Tools;

internal interface IDirectoryEntryEnumerator
{
    IEnumerable<string> EnumerateNames(string authorizedCanonicalDirectory);
}

internal sealed class WindowsDirectoryEntryEnumerator : IDirectoryEntryEnumerator
{
    public IEnumerable<string> EnumerateNames(string authorizedCanonicalDirectory)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
            IgnoreInaccessible = false,
            AttributesToSkip = 0,
        };

        foreach (var fullPath in Directory.EnumerateFileSystemEntries(authorizedCanonicalDirectory, "*", options))
            yield return Path.GetFileName(fullPath);
    }
}

[McpServerToolType]
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public sealed class ListDirectoryTool
{
    internal const int DefaultMaximumEntries = 500;
    internal const int CompiledHardMaximumEntries = 2000;
    internal const int OrderingVersion = 1;
    internal static readonly TimeSpan OperationalWallClockBudget = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan HardWallClockCeiling = TimeSpan.FromSeconds(15);

    private readonly ValidatedRootRegistry _registry;
    private readonly IWindowsNativeFileSystem _native;
    private readonly WindowsPathAuthorizer _authorizer;
    private readonly SensitivePathPolicy _policy;
    private readonly DirectoryCursorProtector _cursors;
    private readonly IDirectoryEntryEnumerator _enumerator;
    private readonly int _activeMaximumEntries;
    private readonly TimeSpan _wallClockBudget;

    public ListDirectoryTool(ValidatedRootRegistry registry, DirectoryCursorProtector cursors)
        : this(registry, cursors, new WindowsNativeFileSystem(), new WindowsDirectoryEntryEnumerator(),
            DefaultMaximumEntries, OperationalWallClockBudget)
    {
    }

    internal ListDirectoryTool(
        ValidatedRootRegistry registry,
        DirectoryCursorProtector cursors,
        IWindowsNativeFileSystem native,
        IDirectoryEntryEnumerator enumerator,
        int activeMaximumEntries = DefaultMaximumEntries,
        TimeSpan? wallClockBudget = null)
    {
        _registry = registry;
        _cursors = cursors;
        _native = native;
        _authorizer = new WindowsPathAuthorizer(native);
        _policy = new SensitivePathPolicy();
        _enumerator = enumerator;
        _activeMaximumEntries = Math.Clamp(activeMaximumEntries, 1, CompiledHardMaximumEntries);
        _wallClockBudget = wallClockBudget ?? OperationalWallClockBudget;
    }

    [McpServerTool(Name = "list_directory", ReadOnly = true, Idempotent = true)]
    [Description("Lists one bounded page of direct permitted children of an authorized directory.")]
    public ListDirectoryResponse ListDirectory(
        string root_id,
        string path,
        int? max_entries = null,
        string? cursor = null)
    {
        var started = Stopwatch.GetTimestamp();
        if (!_registry.TryGet(root_id, out var root) || root is null)
            return ListDirectoryResponse.Failure("ROOT_NOT_FOUND");
        if (path is null || (path.Length > 0 && !WindowsRelativePath.TryParse(path, out _)))
            return ListDirectoryResponse.Failure("PATH_INVALID");
        if (_policy.IsLexicallyDenied(root, path))
            return ListDirectoryResponse.Failure("ACCESS_DENIED");
        if (max_entries is <= 0)
            return ListDirectoryResponse.Failure("PATH_INVALID");

        DirectoryCursorState? cursorState = null;
        if (cursor is not null && !_cursors.TryUnprotect(cursor, out cursorState))
            return ListDirectoryResponse.Failure("INVALID_CURSOR");

        var requestedPageSize = max_entries.HasValue
            ? Math.Min(max_entries.Value, _activeMaximumEntries)
            : cursorState?.PageSize ?? _activeMaximumEntries;
        if (cursorState is not null && (cursorState.TokenVersion != 1 ||
            cursorState.OrderingVersion != OrderingVersion || cursorState.PageSize != requestedPageSize))
        {
            return ListDirectoryResponse.Failure("INVALID_CURSOR");
        }

        var authorization = _authorizer.AuthorizeDirectory(_registry, root.Id, path);
        if (!authorization.IsAuthorized)
            return ListDirectoryResponse.Failure(MapAuthorizationFailure(authorization.Outcome));

        using var directory = authorization.AuthorizedObject!;
        if (directory.Facts.ObjectKind != NativeObjectKind.Directory)
            return ListDirectoryResponse.Failure("NOT_A_DIRECTORY");
        if (_policy.IsDenied(root, directory, _registry.DeniedConfiguration))
            return ListDirectoryResponse.Failure("ACCESS_DENIED");

        var rootBinding = _cursors.BindRoot(root.Id);
        var directoryBinding = _cursors.BindDirectory(directory);
        var configurationBinding = _cursors.BindConfiguration(_registry);
        if (cursorState is not null &&
            (!FixedEquals(cursorState.RootBinding, rootBinding) ||
             !FixedEquals(cursorState.DirectoryBinding, directoryBinding) ||
             !FixedEquals(cursorState.ConfigurationBinding, configurationBinding)))
        {
            return ListDirectoryResponse.Failure("INVALID_CURSOR");
        }

        var visible = new List<DirectoryEntryResponse>();
        var observedNames = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var name in _enumerator.EnumerateNames(directory.Facts.CanonicalPath))
            {
                if (Elapsed(started) >= _wallClockBudget)
                    return ListDirectoryResponse.Failure("RESOURCE_LIMIT");
                if (!IsSingleSafeName(name))
                    return ListDirectoryResponse.Failure("PATH_CHANGED");

                var childPath = directory.RelativePath.Length == 0 ? name : directory.RelativePath + "\\" + name;
                if (_policy.IsLexicallyDenied(root, childPath))
                    continue;

                var childAuthorization = _authorizer.Authorize(_registry, root.Id, childPath);
                if (!childAuthorization.IsAuthorized)
                    continue;

                using var child = childAuthorization.AuthorizedObject!;
                if (_policy.IsDenied(root, child, _registry.DeniedConfiguration))
                    continue;

                var metadata = _native.GetMetadata(child.Handle, child.Facts.ObjectKind);
                if (!metadata.IsSuccess)
                    continue;

                if (!observedNames.Add(name))
                    return ListDirectoryResponse.Failure("PATH_CHANGED");

                visible.Add(new DirectoryEntryResponse(
                    name,
                    child.RelativePath,
                    child.Facts.ObjectKind == NativeObjectKind.Directory ? "directory" : "file",
                    metadata.Metadata!.Size,
                    metadata.Metadata.ModifiedTimeUtc));
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           DirectoryNotFoundException or PathTooLongException)
        {
            return ListDirectoryResponse.Failure("PATH_CHANGED");
        }

        if (Elapsed(started) >= _wallClockBudget)
            return ListDirectoryResponse.Failure("RESOURCE_LIMIT");
        if (_authorizer.RevalidateDirectory(_registry, directory) != AuthorizationOutcome.Authorized)
            return ListDirectoryResponse.Failure("PATH_CHANGED");

        visible.Sort(DirectoryEntryComparer.Instance);
        var resumeIndex = 0;
        if (cursorState is not null)
        {
            resumeIndex = FindResumeIndex(visible, cursorState.LastVisibleName);
            if (resumeIndex < 0)
                return ListDirectoryResponse.Failure("INVALID_CURSOR");
        }

        var page = visible.Skip(resumeIndex).Take(requestedPageSize).ToArray();
        var truncated = resumeIndex + page.Length < visible.Count;
        string? continuation = null;
        if (truncated)
        {
            continuation = _cursors.Protect(new DirectoryCursorState(
                1, OrderingVersion, requestedPageSize, rootBinding, directoryBinding,
                configurationBinding, page[^1].Name));
        }

        return ListDirectoryResponse.Success(page, truncated,
            truncated ? "result_limit" : null, continuation);
    }

    private static int FindResumeIndex(IReadOnlyList<DirectoryEntryResponse> visible, string lastName)
    {
        var equalCount = 0;
        var firstAfter = visible.Count;
        for (var index = 0; index < visible.Count; index++)
        {
            var comparison = DirectoryEntryComparer.CompareNames(visible[index].Name, lastName);
            if (comparison == 0) equalCount++;
            if (comparison > 0)
            {
                firstAfter = index;
                break;
            }
        }

        return equalCount > 1 ? -1 : firstAfter;
    }

    private static bool IsSingleSafeName(string name) =>
        WindowsRelativePath.TryParse(name, out var parsed) && parsed!.Components.Count == 1;

    private TimeSpan Elapsed(long started) => Stopwatch.GetElapsedTime(started);

    private static bool FixedEquals(string left, string right)
    {
        var leftBytes = System.Text.Encoding.UTF8.GetBytes(left);
        var rightBytes = System.Text.Encoding.UTF8.GetBytes(right);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
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

    private sealed class DirectoryEntryComparer : IComparer<DirectoryEntryResponse>
    {
        public static DirectoryEntryComparer Instance { get; } = new();
        public int Compare(DirectoryEntryResponse? left, DirectoryEntryResponse? right) =>
            CompareNames(left!.Name, right!.Name);
        public static int CompareNames(string left, string right)
        {
            var primary = StringComparer.OrdinalIgnoreCase.Compare(left, right);
            return primary != 0 ? primary : StringComparer.Ordinal.Compare(left, right);
        }
    }
}

public sealed record DirectoryEntryResponse(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("relative_path")] string RelativePath,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("size"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Size,
    [property: JsonPropertyName("modified_time")] DateTimeOffset ModifiedTime);

public sealed record ListDirectoryResponse(
    [property: JsonPropertyName("entries"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<DirectoryEntryResponse>? Entries,
    [property: JsonPropertyName("truncated"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Truncated,
    [property: JsonPropertyName("truncation_reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TruncationReason,
    [property: JsonPropertyName("continuation_token"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ContinuationToken,
    [property: JsonPropertyName("error_code"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ErrorCode)
{
    public static ListDirectoryResponse Success(IReadOnlyList<DirectoryEntryResponse> entries, bool truncated,
        string? truncationReason, string? continuationToken) =>
        new(entries, truncated, truncationReason, continuationToken, null);

    public static ListDirectoryResponse Failure(string errorCode) =>
        new(null, null, null, null, errorCode);
}

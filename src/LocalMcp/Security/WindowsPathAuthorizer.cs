using LocalMcp.Roots;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Security;

/// <summary>
/// Internal Increment 2 authorization primitive. It never returns filesystem content
/// and transfers ownership of only the already-authorized opened target handle.
/// </summary>
internal sealed class WindowsPathAuthorizer
{
    private readonly IWindowsNativeFileSystem _native;

    public WindowsPathAuthorizer(IWindowsNativeFileSystem native) => _native = native;

    public WindowsAuthorizationResult Authorize(
        ValidatedRootRegistry registry,
        string rootId,
        string? clientRelativePath)
    {
        if (!registry.TryGet(rootId, out var root) || root is null)
        {
            return WindowsAuthorizationResult.Deny(AuthorizationOutcome.RootNotFound);
        }

        if (!WindowsRelativePath.TryParse(clientRelativePath, out var relativePath))
        {
            return WindowsAuthorizationResult.Deny(AuthorizationOutcome.PathInvalid);
        }

        var rootState = ValidateRetainedRoot(root);
        if (rootState.Outcome != AuthorizationOutcome.Authorized)
        {
            return WindowsAuthorizationResult.Deny(rootState.Outcome);
        }

        var currentHandle = rootState.Handle!;
        var currentFacts = rootState.Facts!;
        var rootFacts = currentFacts;

        for (var index = 0; index < relativePath!.Components.Count; index++)
        {
            var parentBinding = ValidatePathBinding(currentFacts);
            if (parentBinding != AuthorizationOutcome.Authorized)
            {
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(parentBinding);
            }

            var candidatePath = currentFacts.CanonicalPath.TrimEnd('\\') + "\\" + relativePath.Components[index];
            var inspectionOpen = _native.OpenMetadata(candidatePath, followReparse: false);
            if (!inspectionOpen.IsSuccess)
            {
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(MapFailure(inspectionOpen.Failure));
            }

            var inspectionHandle = inspectionOpen.Handle!;
            var inspectionFactsResult = _native.GetFacts(inspectionHandle);
            if (!inspectionFactsResult.IsSuccess)
            {
                inspectionHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(MapFailure(inspectionFactsResult.Failure));
            }

            var inspectionFacts = inspectionFactsResult.Facts!;
            SafeFileHandle selectedHandle;
            NativeObjectFacts selectedFacts;

            if (inspectionFacts.ReparseKind == NativeReparseKind.Unsupported)
            {
                inspectionHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(AuthorizationOutcome.UnsupportedFileSystem);
            }

            if (inspectionFacts.ReparseKind == NativeReparseKind.None)
            {
                selectedHandle = inspectionHandle;
                selectedFacts = inspectionFacts;
            }
            else
            {
                var followedOpen = _native.OpenMetadata(candidatePath, followReparse: true);
                if (!followedOpen.IsSuccess)
                {
                    inspectionHandle.Dispose();
                    currentHandle.Dispose();
                    return WindowsAuthorizationResult.Deny(MapFailure(followedOpen.Failure));
                }

                selectedHandle = followedOpen.Handle!;
                var selectedFactsResult = _native.GetFacts(selectedHandle);
                if (!selectedFactsResult.IsSuccess)
                {
                    inspectionHandle.Dispose();
                    selectedHandle.Dispose();
                    currentHandle.Dispose();
                    return WindowsAuthorizationResult.Deny(MapFailure(selectedFactsResult.Failure));
                }

                selectedFacts = selectedFactsResult.Facts!;
                if (selectedFacts.ReparseKind == NativeReparseKind.Unsupported)
                {
                    inspectionHandle.Dispose();
                    selectedHandle.Dispose();
                    currentHandle.Dispose();
                    return WindowsAuthorizationResult.Deny(AuthorizationOutcome.UnsupportedFileSystem);
                }

                var reparseState = RevalidateReparse(candidatePath, inspectionFacts);
                inspectionHandle.Dispose();
                if (reparseState != AuthorizationOutcome.Authorized)
                {
                    selectedHandle.Dispose();
                    currentHandle.Dispose();
                    return WindowsAuthorizationResult.Deny(reparseState);
                }
            }

            if (selectedFacts.ObjectKind == NativeObjectKind.Unsupported)
            {
                selectedHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(AuthorizationOutcome.UnsupportedObject);
            }

            if (!IsContained(rootFacts, selectedFacts))
            {
                selectedHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(AuthorizationOutcome.PathOutsideRoot);
            }

            var parentState = RevalidateOpenHandle(currentHandle, currentFacts);
            if (parentState == AuthorizationOutcome.Authorized)
            {
                parentState = ValidatePathBinding(currentFacts);
            }

            if (parentState != AuthorizationOutcome.Authorized)
            {
                selectedHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(parentState);
            }

            var isLast = index == relativePath.Components.Count - 1;
            if (!isLast && selectedFacts.ObjectKind != NativeObjectKind.Directory)
            {
                selectedHandle.Dispose();
                currentHandle.Dispose();
                return WindowsAuthorizationResult.Deny(AuthorizationOutcome.UnsupportedObject);
            }

            currentHandle.Dispose();
            currentHandle = selectedHandle;
            currentFacts = selectedFacts;
        }

        var finalState = RevalidateOpenHandle(currentHandle, currentFacts);
        if (finalState != AuthorizationOutcome.Authorized || !IsContained(rootFacts, currentFacts))
        {
            currentHandle.Dispose();
            return WindowsAuthorizationResult.Deny(finalState == AuthorizationOutcome.Authorized
                ? AuthorizationOutcome.PathOutsideRoot
                : finalState);
        }

        var rootRecheck = ValidateRetainedRoot(root);
        if (rootRecheck.Outcome != AuthorizationOutcome.Authorized)
        {
            currentHandle.Dispose();
            rootRecheck.Handle?.Dispose();
            return WindowsAuthorizationResult.Deny(rootRecheck.Outcome);
        }

        rootRecheck.Handle!.Dispose();
        return WindowsAuthorizationResult.Allow(new AuthorizedFileSystemObject(
            root.Id, relativePath.Value, currentHandle, currentFacts));
    }

    private (AuthorizationOutcome Outcome, SafeFileHandle? Handle, NativeObjectFacts? Facts) ValidateRetainedRoot(
        ValidatedRoot root)
    {
        var retainedFacts = _native.GetFacts(root.Handle);
        if (!retainedFacts.IsSuccess || retainedFacts.Facts!.ReparseKind == NativeReparseKind.Unsupported ||
            retainedFacts.Facts.Identity != root.ObjectIdentity ||
            !CanonicalEquivalent(retainedFacts.Facts.CanonicalPath, root.CanonicalPath))
        {
            return (AuthorizationOutcome.PathChanged, null, null);
        }

        var currentOpen = _native.OpenMetadata(root.CanonicalPath, followReparse: true);
        if (!currentOpen.IsSuccess)
        {
            return (MapBindingFailure(currentOpen.Failure), null, null);
        }

        var handle = currentOpen.Handle!;
        var currentFacts = _native.GetFacts(handle);
        if (!currentFacts.IsSuccess || currentFacts.Facts!.ReparseKind == NativeReparseKind.Unsupported ||
            currentFacts.Facts.Identity != root.ObjectIdentity ||
            currentFacts.Facts.ObjectKind != NativeObjectKind.Directory ||
            !CanonicalEquivalent(currentFacts.Facts.CanonicalPath, root.CanonicalPath))
        {
            handle.Dispose();
            return (AuthorizationOutcome.PathChanged, null, null);
        }

        return (AuthorizationOutcome.Authorized, handle, currentFacts.Facts);
    }

    private AuthorizationOutcome ValidatePathBinding(NativeObjectFacts expected)
    {
        var opened = _native.OpenMetadata(expected.CanonicalPath, followReparse: true);
        if (!opened.IsSuccess)
        {
            return MapBindingFailure(opened.Failure);
        }

        using var handle = opened.Handle!;
        var facts = _native.GetFacts(handle);
        return facts.IsSuccess && facts.Facts!.Identity == expected.Identity &&
               CanonicalEquivalent(facts.Facts.CanonicalPath, expected.CanonicalPath)
            ? AuthorizationOutcome.Authorized
            : AuthorizationOutcome.PathChanged;
    }

    private AuthorizationOutcome RevalidateReparse(string candidatePath, NativeObjectFacts expected)
    {
        var opened = _native.OpenMetadata(candidatePath, followReparse: false);
        if (!opened.IsSuccess)
        {
            return MapBindingFailure(opened.Failure);
        }

        using var handle = opened.Handle!;
        var facts = _native.GetFacts(handle);
        return facts.IsSuccess && facts.Facts!.Identity == expected.Identity &&
               facts.Facts.ReparseKind == expected.ReparseKind
            ? AuthorizationOutcome.Authorized
            : AuthorizationOutcome.PathChanged;
    }

    private AuthorizationOutcome RevalidateOpenHandle(SafeFileHandle handle, NativeObjectFacts expected)
    {
        var facts = _native.GetFacts(handle);
        return facts.IsSuccess && facts.Facts!.Identity == expected.Identity &&
               CanonicalEquivalent(facts.Facts.CanonicalPath, expected.CanonicalPath)
            ? AuthorizationOutcome.Authorized
            : AuthorizationOutcome.PathChanged;
    }

    private static bool IsContained(NativeObjectFacts root, NativeObjectFacts target)
    {
        if (root.Identity.VolumeSerialNumber != target.Identity.VolumeSerialNumber ||
            !WindowsCanonicalPath.TryParse(root.CanonicalPath, out var rootPath) ||
            !WindowsCanonicalPath.TryParse(target.CanonicalPath, out var targetPath))
        {
            return false;
        }

        return WindowsCanonicalPath.Contains(rootPath!, targetPath!);
    }

    private static bool CanonicalEquivalent(string left, string right) =>
        WindowsCanonicalPath.TryParse(left, out var leftPath) &&
        WindowsCanonicalPath.TryParse(right, out var rightPath) &&
        WindowsCanonicalPath.Equivalent(leftPath!, rightPath!);

    private static AuthorizationOutcome MapFailure(NativeFailure failure) => failure switch
    {
        NativeFailure.NotFound => AuthorizationOutcome.NotFound,
        NativeFailure.AccessDenied => AuthorizationOutcome.AccessDenied,
        NativeFailure.SharingViolation => AuthorizationOutcome.PathChanged,
        NativeFailure.InvalidPath => AuthorizationOutcome.PathInvalid,
        NativeFailure.Unsupported => AuthorizationOutcome.UnsupportedFileSystem,
        _ => AuthorizationOutcome.InternalError,
    };

    private static AuthorizationOutcome MapBindingFailure(NativeFailure failure) => failure switch
    {
        NativeFailure.AccessDenied => AuthorizationOutcome.AccessDenied,
        NativeFailure.Unsupported => AuthorizationOutcome.UnsupportedFileSystem,
        _ => AuthorizationOutcome.PathChanged,
    };
}

using LocalMcp.Configuration;
using LocalMcp.Roots;
using LocalMcp.Security;
using Microsoft.Win32.SafeHandles;

namespace LocalMcp.Tests;

public class WindowsPathAuthorizerPolicyTests
{
    private const string RootPath = @"\\?\C:\authorized-root";

    [Fact]
    public void UnknownReparseTag_IsDeniedFailClosed()
    {
        using var fixture = new FakeAuthorizationFixture();
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\unknown", false,
            Facts(RootPath + @"\unknown", "unknown", NativeObjectKind.Directory, NativeReparseKind.Unsupported));

        var result = fixture.Authorize("unknown");

        Assert.Equal(AuthorizationOutcome.UnsupportedFileSystem, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void MountPointResolvingOutsideRoot_IsDenied()
    {
        using var fixture = new FakeAuthorizationFixture();
        var link = Facts(RootPath + @"\mount", "mount-link", NativeObjectKind.Directory, NativeReparseKind.MountPoint);
        var outside = Facts(@"\\?\D:\outside", "outside", NativeObjectKind.Directory);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\mount", false, link);
        fixture.Native.QueueOpen(RootPath + @"\mount", true, outside);
        fixture.Native.QueueOpen(RootPath + @"\mount", false, link);

        var result = fixture.Authorize("mount");

        Assert.Equal(AuthorizationOutcome.PathOutsideRoot, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void SymbolicLinkResolvingOutsideRoot_IsDenied()
    {
        using var fixture = new FakeAuthorizationFixture();
        var link = Facts(RootPath + @"\symbolic-link", "symbolic-link", NativeObjectKind.Directory,
            NativeReparseKind.SymbolicLink);
        var outside = Facts(@"\\?\D:\outside", "outside", NativeObjectKind.Directory);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\symbolic-link", false, link);
        fixture.Native.QueueOpen(RootPath + @"\symbolic-link", true, outside);
        fixture.Native.QueueOpen(RootPath + @"\symbolic-link", false, link);

        var result = fixture.Authorize("symbolic-link");

        Assert.Equal(AuthorizationOutcome.PathOutsideRoot, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void ReparseRetargetDuringValidation_IsDetectedAndDenied()
    {
        using var fixture = new FakeAuthorizationFixture();
        var originalLink = Facts(RootPath + @"\link", "link-a", NativeObjectKind.Directory, NativeReparseKind.SymbolicLink);
        var retargetedLink = Facts(RootPath + @"\link", "link-b", NativeObjectKind.Directory, NativeReparseKind.SymbolicLink);
        var inside = Facts(RootPath + @"\inside", "inside", NativeObjectKind.Directory);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\link", false, originalLink);
        fixture.Native.QueueOpen(RootPath + @"\link", true, inside);
        fixture.Native.QueueOpen(RootPath + @"\link", false, retargetedLink);

        var result = fixture.Authorize("link");

        Assert.Equal(AuthorizationOutcome.PathChanged, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void ParentPathRetargetAfterChildOpen_IsDetectedAndDenied()
    {
        using var fixture = new FakeAuthorizationFixture();
        var parent = Facts(RootPath + @"\folder", "parent-a", NativeObjectKind.Directory);
        var retargetedParent = Facts(RootPath + @"\folder", "parent-b", NativeObjectKind.Directory);
        var child = Facts(RootPath + @"\folder\file.txt", "file", NativeObjectKind.File);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\folder", false, parent);
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\folder", true, parent);
        fixture.Native.QueueOpen(RootPath + @"\folder\file.txt", false, child);
        fixture.Native.QueueOpen(RootPath + @"\folder", true, retargetedParent);

        var result = fixture.Authorize(@"folder\file.txt");

        Assert.Equal(AuthorizationOutcome.PathChanged, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void KnownLinkResolvingToUnsupportedReparseBehavior_IsDeniedFailClosed()
    {
        using var fixture = new FakeAuthorizationFixture();
        var link = Facts(RootPath + @"\link", "link", NativeObjectKind.Directory, NativeReparseKind.SymbolicLink);
        var unsupportedTarget = Facts(
            RootPath + @"\target", "target", NativeObjectKind.Directory, NativeReparseKind.Unsupported);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\link", false, link);
        fixture.Native.QueueOpen(RootPath + @"\link", true, unsupportedTarget);

        var result = fixture.Authorize("link");

        Assert.Equal(AuthorizationOutcome.UnsupportedFileSystem, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void UnsupportedFinalObjectKind_IsDeniedFailClosed()
    {
        using var fixture = new FakeAuthorizationFixture();
        var unsupported = Facts(RootPath + @"\device", "device", NativeObjectKind.Unsupported);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\device", false, unsupported);

        var result = fixture.Authorize("device");

        Assert.Equal(AuthorizationOutcome.UnsupportedObject, result.Outcome);
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void SuccessfulTraversal_DisposesIntermediatesAndRetainsOnlyAuthorizedTarget()
    {
        using var fixture = new FakeAuthorizationFixture();
        var directory = Facts(RootPath + @"\folder", "folder", NativeObjectKind.Directory);
        var file = Facts(RootPath + @"\folder\file.txt", "file", NativeObjectKind.File);
        fixture.Native.QueueRootValidation();
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\folder", false, directory);
        fixture.Native.QueueOpen(RootPath, true, fixture.RootFacts);
        fixture.Native.QueueOpen(RootPath + @"\folder", true, directory);
        fixture.Native.QueueOpen(RootPath + @"\folder\file.txt", false, file);
        fixture.Native.QueueOpen(RootPath + @"\folder", true, directory);
        fixture.Native.QueueRootValidation();

        var result = fixture.Authorize(@"folder\file.txt");

        Assert.True(result.IsAuthorized);
        var retained = result.AuthorizedObject!;
        Assert.False(retained.Handle.IsClosed);
        Assert.Single(fixture.Native.OpenedHandles, handle => !handle.IsClosed);
        Assert.Same(retained.Handle, fixture.Native.OpenedHandles.Single(handle => !handle.IsClosed));

        retained.Dispose();
        Assert.All(fixture.Native.OpenedHandles, handle => Assert.True(handle.IsClosed));
    }

    [Fact]
    public void ComponentContainment_DoesNotTreatStringPrefixAsAuthority()
    {
        Assert.True(WindowsCanonicalPath.TryParse(@"\\?\C:\safe", out var root));
        Assert.True(WindowsCanonicalPath.TryParse(@"\\?\C:\safe\child", out var child));
        Assert.True(WindowsCanonicalPath.TryParse(@"\\?\C:\safe-escape\child", out var prefixCollision));

        Assert.True(WindowsCanonicalPath.Contains(root!, child!));
        Assert.False(WindowsCanonicalPath.Contains(root!, prefixCollision!));
    }

    private static NativeObjectFacts Facts(
        string canonicalPath,
        string id,
        NativeObjectKind kind,
        NativeReparseKind reparse = NativeReparseKind.None) =>
        new(canonicalPath, new FileObjectIdentity(canonicalPath[4] == 'C' ? 100UL : 200UL, id), kind, reparse);

    private sealed class FakeAuthorizationFixture : IDisposable
    {
        private readonly SafeFileHandle _rootHandle = FakeWindowsNativeFileSystem.NewHandle();

        public FakeAuthorizationFixture()
        {
            RootFacts = Facts(RootPath, "root", NativeObjectKind.Directory);
            Native = new FakeWindowsNativeFileSystem(_rootHandle, RootFacts);
            var root = new ValidatedRoot("root", "test", [], RootPath, RootFacts.Identity, _rootHandle);
            Registry = new ValidatedRootRegistry([root], new ConfigurationAuthorityIdentity(
                RootPath, RootFacts.Identity, new byte[32]));
            Authorizer = new WindowsPathAuthorizer(Native);
        }

        public NativeObjectFacts RootFacts { get; }
        public FakeWindowsNativeFileSystem Native { get; }
        public ValidatedRootRegistry Registry { get; }
        public WindowsPathAuthorizer Authorizer { get; }

        public WindowsAuthorizationResult Authorize(string path) => Authorizer.Authorize(Registry, "root", path);

        public void Dispose() => Registry.Dispose();
    }

    private sealed class FakeWindowsNativeFileSystem : IWindowsNativeFileSystem
    {
        private static long _nextHandle = 1000;
        private readonly SafeFileHandle _retainedRoot;
        private readonly NativeObjectFacts _rootFacts;
        private readonly Dictionary<nint, NativeObjectFacts> _facts = [];
        private readonly Dictionary<(string Path, bool Follow), Queue<NativeObjectFacts>> _opens = [];

        public FakeWindowsNativeFileSystem(SafeFileHandle retainedRoot, NativeObjectFacts rootFacts)
        {
            _retainedRoot = retainedRoot;
            _rootFacts = rootFacts;
            _facts[retainedRoot.DangerousGetHandle()] = rootFacts;
        }

        public List<SafeFileHandle> OpenedHandles { get; } = [];

        public static SafeFileHandle NewHandle() =>
            new(new IntPtr(Interlocked.Increment(ref _nextHandle)), ownsHandle: false);

        public void QueueRootValidation() => QueueOpen(RootPath, true, _rootFacts);

        public void QueueOpen(string path, bool follow, NativeObjectFacts facts)
        {
            var key = (path, follow);
            if (!_opens.TryGetValue(key, out var queue))
            {
                queue = new Queue<NativeObjectFacts>();
                _opens[key] = queue;
            }

            queue.Enqueue(facts);
        }

        public NativeOpenResult OpenMetadata(string path, bool followReparse)
        {
            if (!_opens.TryGetValue((path, followReparse), out var queue) || queue.Count == 0)
            {
                return NativeOpenResult.Failed(NativeFailure.NotFound);
            }

            var handle = NewHandle();
            OpenedHandles.Add(handle);
            _facts[handle.DangerousGetHandle()] = queue.Dequeue();
            return NativeOpenResult.Success(handle);
        }

        public NativeOpenResult OpenReadOnly(string path, bool followReparse) =>
            NativeOpenResult.Failed(NativeFailure.Unsupported);

        public NativeFactsResult GetFacts(SafeFileHandle handle) =>
            !handle.IsClosed && _facts.TryGetValue(handle.DangerousGetHandle(), out var facts)
                ? NativeFactsResult.Success(facts)
                : NativeFactsResult.Failed(NativeFailure.Failed);

        public NativeMetadataResult GetMetadata(SafeFileHandle handle, NativeObjectKind objectKind) =>
            NativeMetadataResult.Failed(NativeFailure.Unsupported);

        public NativeSecurityResult GetSecurityDescriptor(SafeFileHandle handle) =>
            NativeSecurityResult.Failed(NativeFailure.Unsupported);

        public bool IsFixedLocalDrive(string driveRoot) => true;
    }
}

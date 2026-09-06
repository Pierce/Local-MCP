using LocalMcp.Configuration;

namespace LocalMcp.Roots;

public sealed class ValidatedRootRegistry : IDisposable
{
    private readonly IReadOnlyDictionary<string, ValidatedRoot> _roots;

    public ValidatedRootRegistry(IEnumerable<ValidatedRoot> roots, ConfigurationAuthorityIdentity deniedConfiguration)
    {
        _roots = roots.ToDictionary(root => root.Id, StringComparer.OrdinalIgnoreCase);
        DeniedConfiguration = deniedConfiguration;
    }

    public IReadOnlyCollection<ValidatedRoot> Roots => _roots.Values.ToArray();
    internal ConfigurationAuthorityIdentity DeniedConfiguration { get; }

    public bool TryGet(string rootId, out ValidatedRoot? root) => _roots.TryGetValue(rootId, out root);

    public void Dispose()
    {
        foreach (var root in _roots.Values)
        {
            root.Dispose();
        }
    }
}

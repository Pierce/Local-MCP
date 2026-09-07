using LocalMcp.Configuration;
using LocalMcp.Roots;

namespace LocalMcp.Security;

/// <summary>
/// Shared additive exclusion policy for every filesystem-facing operation. Policy decisions use
/// both the caller spelling and the canonical opened-object path so aliases cannot bypass policy.
/// </summary>
internal sealed class SensitivePathPolicy
{
    private static readonly HashSet<string> DeniedExactNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ssh", ".git", ".aws", ".azure", ".kube", ".docker",
        "credential", "credentials", ".credentials", "secret", "secrets", ".secrets",
        "token", "tokens", ".tokens", "token-store", "token_store",
        "keystore", "key-store", "browser-profile", "browser-profiles", "user data",
        "login data", "web data", "cookies", "history", "logins.json", "key4.db", "cookies.sqlite",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "private_key", "private-key",
    };

    private static readonly HashSet<string> DeniedPrivateKeyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pem", ".key", ".pfx", ".p12", ".ppk",
    };

    public bool IsLexicallyDenied(ValidatedRoot root, string relativePath) =>
        WindowsRelativePath.TryParse(relativePath, out var requestedPath) &&
        (MatchesBuiltIn(requestedPath!.Components) || MatchesConfigured(root.DenyPaths, requestedPath.Components));

    public bool IsDenied(ValidatedRoot root, AuthorizedFileSystemObject target,
        ConfigurationAuthorityIdentity activeConfiguration)
    {
        if (target.Facts.Identity == activeConfiguration.ObjectIdentity) return true;

        var requested = WindowsRelativePath.TryParse(target.RelativePath, out var requestedPath)
            ? requestedPath!.Components
            : Array.Empty<string>();
        var canonical = GetCanonicalRelativeComponents(root.CanonicalPath, target.Facts.CanonicalPath);
        var canonicalFull = WindowsCanonicalPath.TryParse(target.Facts.CanonicalPath, out var openedPath)
            ? openedPath!.Components
            : Array.Empty<string>();

        return MatchesBuiltIn(requested) || MatchesBuiltIn(canonicalFull) ||
               MatchesConfigured(root.DenyPaths, requested) || MatchesConfigured(root.DenyPaths, canonical);
    }

    internal static bool MatchesBuiltIn(IReadOnlyList<string> components) =>
        components.Any(IsBuiltInDeniedName);

    internal static bool MatchesConfigured(
        IReadOnlyList<string> configuredDenyPaths,
        IReadOnlyList<string> candidateComponents)
    {
        foreach (var configured in configuredDenyPaths)
        {
            if (!WindowsRelativePath.TryParse(configured, out var denyPath) ||
                candidateComponents.Count < denyPath!.Components.Count)
            {
                continue;
            }

            var matches = true;
            for (var index = 0; index < denyPath.Components.Count; index++)
            {
                if (!string.Equals(candidateComponents[index], denyPath.Components[index],
                        StringComparison.OrdinalIgnoreCase))
                {
                    matches = false;
                    break;
                }
            }

            if (matches) return true;
        }

        return false;
    }

    private static bool IsBuiltInDeniedName(string name)
    {
        if (DeniedExactNames.Contains(name) || string.Equals(name, ".env", StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith(".env.", StringComparison.OrdinalIgnoreCase) ||
            DeniedPrivateKeyExtensions.Contains(Path.GetExtension(name)))
        {
            return true;
        }

        var stem = Path.GetFileNameWithoutExtension(name);
        var tokens = stem.Split(['.', '-', '_', ' '], StringSplitOptions.RemoveEmptyEntries);
        return tokens.Any(token => token.Equals("credential", StringComparison.OrdinalIgnoreCase) ||
                                   token.Equals("credentials", StringComparison.OrdinalIgnoreCase) ||
                                   token.Equals("secret", StringComparison.OrdinalIgnoreCase) ||
                                   token.Equals("secrets", StringComparison.OrdinalIgnoreCase) ||
                                   token.Equals("token", StringComparison.OrdinalIgnoreCase) ||
                                   token.Equals("tokens", StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<string> GetCanonicalRelativeComponents(string rootPath, string targetPath)
    {
        if (!WindowsCanonicalPath.TryParse(rootPath, out var root) ||
            !WindowsCanonicalPath.TryParse(targetPath, out var target) ||
            !WindowsCanonicalPath.Contains(root!, target!))
        {
            return Array.Empty<string>();
        }

        return target!.Components.Skip(root!.Components.Count).ToArray();
    }
}

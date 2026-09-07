namespace LocalMcp.Security;

internal sealed record WindowsCanonicalPath(char DriveLetter, IReadOnlyList<string> Components)
{
    public static bool TryParse(string value, out WindowsCanonicalPath? result)
    {
        result = null;
        if (string.IsNullOrEmpty(value) || value.Length < 7 ||
            !value.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            !char.IsAsciiLetter(value[4]) || value[5] != ':' || value[6] != '\\')
        {
            return false;
        }

        var components = value[7..].TrimEnd('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (components.Any(component => component is "." or ".." || component.Contains(':')))
        {
            return false;
        }

        result = new WindowsCanonicalPath(char.ToUpperInvariant(value[4]), components);
        return true;
    }

    public static bool Contains(WindowsCanonicalPath root, WindowsCanonicalPath target)
    {
        if (root.DriveLetter != target.DriveLetter || target.Components.Count < root.Components.Count)
        {
            return false;
        }

        for (var index = 0; index < root.Components.Count; index++)
        {
            if (!string.Equals(root.Components[index], target.Components[index], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    public static bool Equivalent(WindowsCanonicalPath left, WindowsCanonicalPath right) =>
        left.Components.Count == right.Components.Count && Contains(left, right) && Contains(right, left);

    public static bool EqualsAbsolutePath(string canonicalPath, string absolutePath)
    {
        if (!TryParse(canonicalPath, out var canonical) || absolutePath.Length < 3 ||
            !char.IsAsciiLetter(absolutePath[0]) || absolutePath[1] != ':' || absolutePath[2] != '\\')
        {
            return false;
        }

        var absoluteComponents = absolutePath[3..].TrimEnd('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
        var absolute = new WindowsCanonicalPath(char.ToUpperInvariant(absolutePath[0]), absoluteComponents);
        return Equivalent(canonical!, absolute);
    }
}

namespace LocalMcp.Tests;

internal static class TestPaths
{
    public static string RepositoryRoot { get; } = FindRepositoryRoot();

    private static string FindRepositoryRoot([System.Runtime.CompilerServices.CallerFilePath] string sourceFile = "")
    {
        return Path.GetFullPath(Path.Combine(Path.GetDirectoryName(sourceFile)!, "..", ".."));
    }
}

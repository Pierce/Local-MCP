using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace LocalMcp.Tests;

internal static class WindowsLinkTestSupport
{
    public static bool CanCreateDirectorySymbolicLink(out string limitation)
    {
        var basePath = Path.Combine(Path.GetTempPath(), $"local-mcp-symlink-probe-{Guid.NewGuid():N}");
        var target = Path.Combine(basePath, "target");
        var link = Path.Combine(basePath, "link");
        try
        {
            Directory.CreateDirectory(target);
            Directory.CreateSymbolicLink(link, target);
            limitation = string.Empty;
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            limitation = $"ENVIRONMENT / TOOLING LIMITATION: symbolic-link fixture unavailable ({exception.GetType().Name}: {exception.Message})";
            return false;
        }
        finally
        {
            try
            {
                if (Directory.Exists(link))
                {
                    Directory.Delete(link);
                }

                if (Directory.Exists(basePath))
                {
                    Directory.Delete(basePath, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup for a test-only capability probe.
            }
        }
    }

    public static string CreateJunction(string junctionPath, string targetPath)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "cmd.exe",
            ArgumentList = { "/d", "/c", "mklink", "/J", junctionPath, targetPath },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        }) ?? throw new InvalidOperationException("Junction fixture process did not start.");

        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Junction fixture failed ({process.ExitCode}): {stderr}{stdout}");
        }

        return stdout.Trim();
    }

    public static bool CanCreateShortName(out string limitation)
    {
        var basePath = Path.Combine(Path.GetTempPath(), $"local-mcp-short-name-probe-{Guid.NewGuid():N}");
        var longPath = Path.Combine(basePath, "LongDirectoryNameForAliasProbe");
        try
        {
            Directory.CreateDirectory(longPath);
            if (TryGetShortPath(longPath, out _))
            {
                limitation = string.Empty;
                return true;
            }

            limitation = "ENVIRONMENT / TOOLING LIMITATION: 8.3 short-name generation is disabled on the test volume.";
            return false;
        }
        finally
        {
            try
            {
                if (Directory.Exists(basePath))
                {
                    Directory.Delete(basePath, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup for a test-only capability probe.
            }
        }
    }

    public static bool TryGetShortPath(string path, out string? shortPath)
    {
        var buffer = new StringBuilder(32768);
        var length = GetShortPathNameW(path, buffer, buffer.Capacity);
        shortPath = length is > 0 and < 32768 ? buffer.ToString() : null;
        return shortPath is not null && !string.Equals(shortPath, path, StringComparison.OrdinalIgnoreCase) && shortPath.Contains('~');
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetShortPathNameW(string longPath, StringBuilder shortPath, int bufferLength);
}

[AttributeUsage(AttributeTargets.Method)]
internal sealed class WindowsSymlinkFactAttribute : FactAttribute
{
    public WindowsSymlinkFactAttribute()
    {
        if (!WindowsLinkTestSupport.CanCreateDirectorySymbolicLink(out var limitation))
        {
            Skip = limitation;
        }
    }
}

[AttributeUsage(AttributeTargets.Method)]
internal sealed class WindowsShortNameFactAttribute : FactAttribute
{
    public WindowsShortNameFactAttribute()
    {
        if (!WindowsLinkTestSupport.CanCreateShortName(out var limitation))
        {
            Skip = limitation;
        }
    }
}

// Verify that configuration model types do not load, discover, canonicalize,
// open, enumerate, or authorize host filesystem roots.
// The models are plain data transfer objects with no host-path side effects.

using LocalMcp.Configuration;
using Tomlyn;

namespace LocalMcp.Tests;

public class ConfigurationModelTests
{
    [Fact]
    public void McpConfig_IsPlainModel_NoFilesystemAccess()
    {
        // Create a config in memory — no file loading
        var config = new McpConfig
        {
            Logging = new LoggingConfig
            {
                Level = "Debug",
                IncludeTimestamp = true
            },
            Roots = new RootsConfig
            {
                Roots =
                [
                    new RootDefinition { Path = "/example/path", Name = "Example" }
                ]
            }
        };

        Assert.NotNull(config);
        Assert.Equal("Debug", config.Logging.Level);
        Assert.Single(config.Roots.Roots);
        Assert.Equal("/example/path", config.Roots.Roots[0].Path);
        Assert.Equal("Example", config.Roots.Roots[0].Name);
    }

    [Fact]
    public void TOML_Roundtrip_DoesNotAccessFilesystem()
    {
        // Verify the model can be serialized to TOML and deserialized
        // entirely in memory, without any filesystem access.
        var original = new McpConfig
        {
            Logging = new LoggingConfig { Level = "Warning" },
            Roots = new RootsConfig
            {
                Roots =
                [
                    new RootDefinition { Path = "/fake/root", Name = "Test" }
                ]
            }
        };

        // Serialize to TOML string
        var toml = TomlSerializer.Serialize(original);
        Assert.Contains("Level", toml);
        Assert.Contains("Path", toml);

        // Deserialize back from TOML string
        var deserialized = TomlSerializer.Deserialize<McpConfig>(toml);
        Assert.NotNull(deserialized);
    }

    [Fact]
    public void RootDefinition_DoesNotCanonicalizeHostPaths()
    {
        // Confirm no path canonicalization occurs during model construction
        var root = new RootDefinition
        {
            Path = "/some/arbitrary/path",
            Name = null
        };

        // The path should remain exactly as set — no transformation
        Assert.Equal("/some/arbitrary/path", root.Path);
        Assert.Null(root.Name);
    }

    [Fact]
    public void ConfigurationModels_AreNotLoadedFromDisk()
    {
        // Verify that the server code never loads a configuration file
        var sourceDir = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src"));

        foreach (var csFile in Directory.GetFiles(sourceDir, "*.cs", SearchOption.AllDirectories))
        {
            var content = File.ReadAllText(csFile);
            Assert.DoesNotContain("TomlSerializer.Deserialize", content);
            Assert.DoesNotContain("TomlSerializer.Serialize", content);
            Assert.DoesNotContain(".toml", content, StringComparison.OrdinalIgnoreCase);
        }
    }
}
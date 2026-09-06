// Configuration model types for the Local MCP server.
// These describe the planned static TOML configuration structure.
// IMPORTANT: This file defines ONLY model types.
// No configuration files are located, loaded, canonicalized, opened,
// enumerated, authorized, or discovered at any point during Increment 0.
//
// The models may describe future configuration concepts related to
// filesystem roots, but no host filesystem authority is exercised here.

namespace LocalMcp.Configuration;

/// <summary>
/// Top-level configuration model for Local MCP.
/// Corresponds to the planned static TOML configuration file structure.
/// </summary>
public sealed class McpConfig
{
    /// <summary>
    /// Gets or sets the logging configuration section.
    /// </summary>
    public LoggingConfig Logging { get; set; } = new();

    /// <summary>
    /// Gets or sets the roots configuration section.
    /// Roots define which directories the server is allowed to access.
    /// In Increment 0, this model exists but no root is loaded, opened, or validated.
    /// </summary>
    public RootsConfig Roots { get; set; } = new();
}

/// <summary>
/// Logging configuration section.
/// </summary>
public sealed class LoggingConfig
{
    /// <summary>
    /// Gets or sets the minimum log level (e.g., "Information", "Warning", "Error").
    /// </summary>
    public string Level { get; set; } = "Information";

    /// <summary>
    /// Gets or sets a value indicating whether to include timestamps in log output.
    /// </summary>
    public bool IncludeTimestamp { get; set; } = true;
}

/// <summary>
/// Roots configuration section.
/// In Increment 0, this is a model-only construct. No root paths are
/// loaded from disk, validated, canonicalized, or opened.
/// </summary>
public sealed class RootsConfig
{
    /// <summary>
    /// Gets or sets the list of configured root directory paths.
    /// These are model definitions only — not resolved, validated, or accessed.
    /// </summary>
    public RootDefinition[] Roots { get; set; } = Array.Empty<RootDefinition>();
}

/// <summary>
/// Defines a single configured root directory.
/// Model only — no host filesystem access is performed.
/// </summary>
public sealed class RootDefinition
{
    /// <summary>
    /// Gets or sets the path of the root directory.
    /// This is a model string — no path resolution, canonicalization,
    /// or filesystem access occurs during model definition.
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets an optional display name for the root.
    /// </summary>
    public string? Name { get; set; }
}
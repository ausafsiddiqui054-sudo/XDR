namespace SecurePulse.Core.Models;

/// <summary>Normalized severity used across every engine.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>Normalized outcome of a single check.</summary>
public enum FindingStatus
{
    Passed,
    Failed,
    /// <summary>Needs human review (e.g. Maester "Investigate").</summary>
    Investigate,
    /// <summary>Not evaluated (skipped, not licensed, not run, or errored).</summary>
    NotEvaluated
}

/// <summary>
/// The single shape every engine converts its output into.
/// This model is what makes one unified score and report possible.
/// </summary>
public sealed record Finding
{
    public required string Id { get; init; }
    public required Guid TenantId { get; init; }

    /// <summary>Engine that produced it: "Maester", "ScubaGear", "Wazuh", "GoPhish".</summary>
    public required string Source { get; init; }

    /// <summary>Source engine's own check identifier, e.g. a Maester test Id.</summary>
    public string? SourceCheckId { get; init; }

    public required string Title { get; init; }
    public string? Description { get; init; }

    /// <summary>Functional area, e.g. "Identity", "Devices", "Email", "Data".</summary>
    public string Category { get; init; } = "General";

    public required Severity Severity { get; init; }
    public required FindingStatus Status { get; init; }

    /// <summary>What was observed (trimmed engine output).</summary>
    public string? Evidence { get; init; }

    /// <summary>How to fix it, in plain language.</summary>
    public string? Remediation { get; init; }

    public string? HelpUrl { get; init; }

    /// <summary>Compliance mappings, e.g. "UAE IA", "DoH ADHICS", "CIS M365".</summary>
    public IReadOnlyList<string> Frameworks { get; init; } = [];

    public IReadOnlyList<string> Tags { get; init; } = [];

    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
}

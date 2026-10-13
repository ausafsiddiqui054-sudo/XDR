namespace SecurePulse.Core.Models;

/// <summary>Output of one engine run against one tenant.</summary>
public sealed record ScanResult
{
    public required Guid TenantId { get; init; }
    public required string Source { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }

    public bool Succeeded { get; init; } = true;
    public string? Error { get; init; }
}

/// <summary>Computed security posture for a tenant.</summary>
public sealed record RiskScore
{
    /// <summary>0–100, higher is better.</summary>
    public required int Score { get; init; }
    public required string Grade { get; init; }

    public required int Passed { get; init; }
    public required int Failed { get; init; }
    public required int Investigate { get; init; }
    public required int NotEvaluated { get; init; }

    public required IReadOnlyDictionary<Severity, int> FailedBySeverity { get; init; }
}

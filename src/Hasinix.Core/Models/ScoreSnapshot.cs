namespace Hasinix.Core.Models;

/// <summary>
/// A tenant's score right after a successful scan. Findings are replaced by every scan, so these
/// rows are the only record of past scores.
/// </summary>
public sealed record ScoreSnapshot
{
    public required Guid Id { get; init; }
    public required Guid TenantId { get; init; }
    public required DateTimeOffset RecordedAt { get; init; }

    /// <summary>The engine whose scan led to this snapshot. The score itself covers every engine's findings.</summary>
    public required string Engine { get; init; }

    public required RiskScore Score { get; init; }
}

namespace SecurePulse.Core.Models;

public enum ScanTrigger
{
    Scheduled,
    Manual
}

public enum ScanRunStatus
{
    Queued,
    Running,
    Succeeded,
    Failed
}

/// <summary>
/// One engine run against one tenant. Runs form the Worker's queue: the scheduler and the portal
/// enqueue them, the Worker claims and completes them. At most one queued-or-running run exists
/// per tenant and engine.
/// </summary>
public sealed record ScanRun
{
    public required Guid Id { get; init; }
    public required Guid TenantId { get; init; }

    /// <summary><see cref="Abstractions.IScanEngine.Name"/>, e.g. "Maester".</summary>
    public required string Engine { get; init; }

    public required ScanTrigger Trigger { get; init; }
    public required ScanRunStatus Status { get; init; }
    public required DateTimeOffset QueuedAt { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }

    /// <summary>Who asked for a manual run.</summary>
    public string? RequestedBy { get; init; }

    public int? FindingCount { get; init; }
    public string? Error { get; init; }

    public bool IsActive => Status is ScanRunStatus.Queued or ScanRunStatus.Running;
}

/// <summary>Engines the portal can queue runs for. Must match <see cref="Abstractions.IScanEngine.Name"/>.</summary>
public static class ScanEngines
{
    public const string Maester = "Maester";
    public const string ScubaGear = "ScubaGear";

    public static readonly IReadOnlyList<string> All = [Maester, ScubaGear];
}

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
    public const string Wazuh = "Wazuh";
    public const string GoPhish = "GoPhish";

    public static readonly IReadOnlyList<string> All = [Maester, ScubaGear, Wazuh, GoPhish];

    /// <summary>
    /// Whether <paramref name="engine"/> scans <paramref name="tenant"/>: Wazuh only once the tenant has an agent group,
    /// GoPhish only once an Owner turned it on for the tenant.
    /// </summary>
    public static bool AppliesTo(string engine, Tenant tenant) => engine switch
    {
        Wazuh => !string.IsNullOrWhiteSpace(tenant.WazuhAgentGroup),
        GoPhish => tenant.GoPhishEnabled,
        _ => true
    };

    /// <summary>Engines that read the tenant through Microsoft Graph, so the Worker checks the token's roles first.</summary>
    public static bool UsesGraph(string engine) => engine is Maester or ScubaGear;
}

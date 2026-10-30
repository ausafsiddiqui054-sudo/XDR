using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Playbooks;

namespace SecurePulse.Web.Services;

public sealed class DemoOptions
{
    /// <summary>With sample data, stand in for the Worker so the demo runs end to end. Off: requests just wait, as before.</summary>
    public bool Simulate { get; set; } = true;

    public TimeSpan TickInterval { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>How often devices are "synced" (which is when playbooks propose actions).</summary>
    public TimeSpan SyncInterval { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a simulated scan stays running.</summary>
    public TimeSpan ScanDuration { get; set; } = TimeSpan.FromSeconds(5);
}

/// <summary>
/// Sample data only: stands in for the Worker so a demo runs end to end. It finishes queued scans with the sample
/// findings, marks approved device actions and configuration changes as done, and "syncs" devices so playbooks
/// propose. It only changes the in-memory <see cref="SampleDataStore"/>: nothing is ever sent to Microsoft Graph,
/// Intune, Entra or any engine, and every entry it writes to the audit log says it was simulated. Proposals and
/// pre-approvals go through the Worker's own <see cref="PlaybookRunner"/> and <see cref="FindingPlaybookRunner"/>.
/// </summary>
public sealed class DemoSimulator(
    SampleDataStore store,
    PlaybookRunner playbooks,
    FindingPlaybookRunner findingPlaybooks,
    DemoOptions options,
    TimeProvider time,
    ILogger<DemoSimulator> logger) : BackgroundService
{
    public const string Actor = "SecurePulse demo (simulated Worker)";

    private DateTimeOffset _lastSync = DateTimeOffset.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Simulate) return;
        logger.LogInformation("Sample data: the demo simulator stands in for the Worker. Nothing is sent to Microsoft or any engine");
        using var timer = new PeriodicTimer(options.TickInterval);
        do
        {
            try
            {
                await RunOnceAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Demo simulator pass failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task RunOnceAsync(CancellationToken ct = default)
    {
        await FinishScansAsync(ct);
        await SendDeviceActionsAsync(ct);
        await ApplyConfigurationChangesAsync(ct);
        if (time.GetUtcNow() - _lastSync >= options.SyncInterval)
        {
            _lastSync = time.GetUtcNow();
            await SyncDevicesAsync(ct);
        }
    }

    private async Task FinishScansAsync(CancellationToken ct)
    {
        IScanRunRepository runs = store;
        ITenantRepository tenants = store;
        var now = time.GetUtcNow();
        foreach (var run in (await runs.GetLatestAsync(ct)).Where(r => r.Status == ScanRunStatus.Running && r.StartedAt <= now - options.ScanDuration))
        {
            if (await tenants.GetAsync(run.TenantId, ct) is not { } tenant || !ScanRequestService.IsOnboarded(tenant))
            {
                await runs.CompleteAsync(run.Id, false, null, "The tenant isn't onboarded (consent or certificate missing).", now, ct);
                continue;
            }
            var count = store.RecordSimulatedScan(tenant.Id, run.Engine, now);
            await runs.CompleteAsync(run.Id, true, count, null, now, ct);
            // As in the Worker: finding playbooks look at the findings after a successful scan.
            await findingPlaybooks.RunForTenantAsync((await tenants.GetAsync(tenant.Id, ct))!, ct);
        }
        while (await runs.ClaimNextAsync(ScanEngines.All, now, ct) is not null) { }
    }

    private async Task SendDeviceActionsAsync(CancellationToken ct)
    {
        IDeviceActionRepository actions = store;
        while (await actions.ClaimNextApprovedAsync(time.GetUtcNow(), ct) is { } a)
        {
            await RecordAsync(AuditActions.DeviceActionSending, "DeviceAction", a.Id, a.TenantId,
                $"Simulated: sending {a.Action} to {a.DeviceName} (approved by {a.DecidedByName}). Sample data mode sends nothing to Intune",
                new() { ["action"] = a.Action.ToString(), ["deviceId"] = a.DeviceId, ["deviceName"] = a.DeviceName,
                        ["requestedBy"] = a.RequestedByName, ["approvedBy"] = a.DecidedByName ?? "", ["simulated"] = "true" }, ct);
            await actions.CompleteAsync(a.Id, true, null, time.GetUtcNow(), ct);
            await RecordAsync(AuditActions.DeviceActionResult, "DeviceAction", a.Id, a.TenantId,
                $"Simulated: Intune accepted {a.Action} for {a.DeviceName}. Nothing was sent: this is sample data",
                new() { ["action"] = a.Action.ToString(), ["deviceId"] = a.DeviceId, ["deviceName"] = a.DeviceName, ["simulated"] = "true" }, ct);
        }
    }

    private async Task ApplyConfigurationChangesAsync(CancellationToken ct)
    {
        IConfigurationChangeRepository changes = store;
        while (await changes.ClaimNextApprovedAsync(time.GetUtcNow(), ct) is { } c)
        {
            var policy = ConfigurationFixes.Find(c.FixId)?.PolicyDisplayName ?? c.FixId;
            await RecordAsync(AuditActions.ConfigChangeSending, "ConfigurationChange", c.Id, c.TenantId,
                $"Simulated: creating \"{policy}\" (approved by {c.DecidedByName}). Sample data mode sends nothing to Entra",
                new() { ["fix"] = c.FixId, ["checkId"] = c.CheckId ?? "", ["requestedBy"] = c.RequestedByName,
                        ["approvedBy"] = c.DecidedByName ?? "", ["simulated"] = "true" }, ct);
            var policyId = Guid.NewGuid().ToString();
            await changes.CompleteAsync(c.Id, true, null, policyId, time.GetUtcNow(), ct);
            await RecordAsync(AuditActions.ConfigChangeResult, "ConfigurationChange", c.Id, c.TenantId,
                $"Simulated: created \"{policy}\" in report-only mode (sample policy {policyId}). Nothing was sent: this is sample data",
                new() { ["fix"] = c.FixId, ["simulated"] = "true" }, ct);
        }
    }

    private async Task SyncDevicesAsync(CancellationToken ct)
    {
        ITenantRepository tenants = store;
        foreach (var tenant in await tenants.GetAllAsync(ct))
        {
            if (!ScanRequestService.IsOnboarded(tenant)) continue;
            store.RecordSimulatedSync(tenant.Id, time.GetUtcNow());
            // As in the Worker: playbooks run after each successful sync (only tenants with remediation access).
            await playbooks.RunForTenantAsync(tenant, ct);
        }
    }

    private async Task RecordAsync(string action, string targetType, Guid targetId, Guid tenantId, string summary,
        Dictionary<string, string> details, CancellationToken ct)
    {
        IAuditLog audit = store;
        await audit.RecordAsync(new AuditEvent
        {
            Id = Guid.NewGuid(),
            OccurredAt = time.GetUtcNow(),
            Action = action,
            Outcome = AuditOutcome.Success,
            ActorName = Actor,
            TenantId = tenantId,
            TargetType = targetType,
            TargetId = targetId.ToString(),
            Summary = summary,
            Details = details
        }, ct);
    }
}

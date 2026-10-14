using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

/// <summary>
/// The engines this deployment runs (portal setting Scans:Engines, default Maester). It should list
/// the engines of all Workers together; a run queued for an engine no Worker runs would never start.
/// </summary>
public sealed record ScanEngineSelection(IReadOnlyList<string> Engines)
{
    public static ScanEngineSelection From(string[]? configured)
    {
        var engines = configured is { Length: > 0 } ? configured.Distinct(StringComparer.Ordinal).ToList() : [ScanEngines.Maester];
        if (engines.FirstOrDefault(e => !ScanEngines.All.Contains(e, StringComparer.Ordinal)) is { } unknown)
            throw new InvalidOperationException($"Scans:Engines lists '{unknown}'. Known engines: {string.Join(", ", ScanEngines.All)}.");
        return new ScanEngineSelection(engines);
    }
}

/// <summary>
/// Portal side of scanning: shows each tenant's latest run per engine and lets operators queue a
/// scan now. The Worker does the scanning; the portal only adds rows to the queue.
/// </summary>
public sealed class ScanRequestService(
    IScanRunRepository runs,
    ITenantRepository tenants,
    IUserContextAccessor users,
    AuditTrail audit,
    ScanEngineSelection selection,
    TimeProvider time)
{
    public IReadOnlyList<string> Engines => selection.Engines;

    /// <summary>Latest run per tenant and configured engine, for tenants the current user can see.</summary>
    public async Task<IReadOnlyDictionary<(Guid TenantId, string Engine), ScanRun>> GetLatestAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        return (await runs.GetLatestAsync(ct))
            .Where(r => selection.Engines.Contains(r.Engine) && user.CanSee(r.TenantId))
            .ToDictionary(r => (r.TenantId, r.Engine));
    }

    /// <summary>Queues a scan of every onboarded tenant. Returns how many runs were newly queued.</summary>
    public async Task<int> RequestAllAsync(CancellationToken ct = default) =>
        await RequestAsync((await tenants.GetAllAsync(ct)).Where(IsOnboarded).Select(t => t.Id), ct);

    /// <summary>Queues scans for the given tenants (operators only). Already-queued tenants are left as they are.</summary>
    public async Task<int> RequestAsync(IEnumerable<Guid> tenantIds, CancellationToken ct = default)
    {
        var actor = await users.GetAsync();
        if (!actor.IsOperator) throw new UnauthorizedAccessException("Only Owners and MSP admins can start scans.");

        var queued = 0;
        foreach (var id in tenantIds.Distinct())
        {
            if (await tenants.GetAsync(id, ct) is not { } tenant || !IsOnboarded(tenant)) continue;
            foreach (var engine in selection.Engines)
            {
                var (run, created) = await runs.EnqueueAsync(tenant.Id, engine, ScanTrigger.Manual, actor.Name, time.GetUtcNow(), ct);
                if (!created) continue;
                queued++;
                await audit.RecordAsync(AuditActions.ScanRequested, AuditOutcome.Success, $"Requested a {engine} scan of {tenant.DisplayName}",
                    tenant.Id, "ScanRun", run.Id.ToString(), new Dictionary<string, string> { ["engine"] = engine }, actor);
            }
        }
        return queued;
    }

    public static bool IsOnboarded(Tenant t) =>
        t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted
        && !string.IsNullOrWhiteSpace(t.CredentialReference);
}

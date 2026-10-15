using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

public sealed record DeviceRow(Tenant Tenant, ManagedDevice Device)
{
    public bool IsStale(DateTimeOffset now) => Device.LastSyncAt is not { } last || now - last > EndpointService.StaleAfter;
}

/// <summary>Device counts by compliance state, for one platform, tenant or the whole fleet.</summary>
public sealed record ComplianceBreakdown(string Label, int Compliant, int InGracePeriod, int Noncompliant, int Unknown)
{
    public int Total => Compliant + InGracePeriod + Noncompliant + Unknown;
    public int CompliantPercent => Total == 0 ? 0 : (int)Math.Round(100.0 * Compliant / Total);

    public static ComplianceBreakdown Of(string label, IEnumerable<ManagedDevice> devices)
    {
        var list = devices.ToList();
        return new(label,
            list.Count(d => d.ComplianceState == DeviceComplianceState.Compliant),
            list.Count(d => d.ComplianceState == DeviceComplianceState.InGracePeriod),
            list.Count(d => d.ComplianceState == DeviceComplianceState.Noncompliant),
            list.Count(d => d.ComplianceState == DeviceComplianceState.Unknown));
    }
}

/// <param name="AsOf">Reference time for staleness checks.</param>
/// <param name="Syncs">Latest device sync outcome per tenant that has one.</param>
public sealed record EndpointFleet(IReadOnlyList<DeviceRow> Devices, DateTimeOffset AsOf, IReadOnlyList<(Tenant Tenant, DeviceSyncStatus Status)> Syncs)
{
    /// <summary>Most recent successful sync across tenants, i.e. how fresh the newest inventory is.</summary>
    public DateTimeOffset? LastSyncedAt => Syncs.Max(s => s.Status.LastSuccessAt);

    public IEnumerable<(Tenant Tenant, DeviceSyncStatus Status)> FailedSyncs => Syncs.Where(s => !s.Status.Succeeded);

    public ComplianceBreakdown Overall => ComplianceBreakdown.Of("All devices", Devices.Select(r => r.Device));

    /// <summary>Tenants whose last sync succeeded but couldn't read everything (e.g. Defender for Endpoint).</summary>
    public IEnumerable<(Tenant Tenant, DeviceSyncStatus Status)> SyncWarnings =>
        Syncs.Where(s => s.Status.Succeeded && !string.IsNullOrWhiteSpace(s.Status.Warning));

    public int CountDefender(DefenderState state) => Devices.Count(r => r.Device.Defender == state);

    public int DefenderProtectedPercent => Devices.Count == 0 ? 0 : (int)Math.Round(100.0 * CountDefender(DefenderState.Protected) / Devices.Count);

    /// <summary>The most common Defender issues across the fleet, most devices first.</summary>
    public IReadOnlyList<(string Issue, int Devices)> TopDefenderIssues(int take = 5) =>
        Devices.SelectMany(r => (r.Device.DefenderDetails?.Issues ?? []).Distinct())
            .GroupBy(i => i)
            .Select(g => (g.Key, g.Count()))
            .OrderByDescending(x => x.Item2)
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .Take(take)
            .ToList();

    public int NotEncrypted => Devices.Count(r => r.Device.IsEncrypted == false);
    public int Stale => Devices.Count(r => r.IsStale(AsOf));

    public IReadOnlyList<(DevicePlatform Platform, ComplianceBreakdown Breakdown)> ByPlatform =>
        Devices.GroupBy(r => r.Device.Platform)
            .OrderByDescending(g => g.Count())
            .Select(g => (g.Key, ComplianceBreakdown.Of(g.Key.ToString(), g.Select(r => r.Device))))
            .ToList();

    public IReadOnlyList<(Tenant Tenant, ComplianceBreakdown Breakdown)> ByTenant =>
        Devices.GroupBy(r => r.Tenant.Id)
            .Select(g => (g.First().Tenant, ComplianceBreakdown.Of(g.First().Tenant.DisplayName, g.Select(r => r.Device))))
            .OrderBy(x => x.Item2.CompliantPercent)
            .ToList();
}

public sealed record DeviceDetail(Tenant Tenant, ManagedDevice Device, IReadOnlyList<Finding> RelatedFindings);

/// <summary>Assembles Intune device inventory across tenants for the Endpoints screens.</summary>
/// <remarks>Only returns tenants the current user may see (client viewers: their own).</remarks>
public sealed class EndpointService(ITenantRepository tenants, IDeviceRepository devices, IFindingRepository findings, IUserContextAccessor users)
{
    public static readonly TimeSpan StaleAfter = TimeSpan.FromDays(30);

    public async Task<EndpointFleet> GetFleetAsync(CancellationToken ct = default)
    {
        var rows = new List<DeviceRow>();
        var syncs = new List<(Tenant, DeviceSyncStatus)>();
        var user = await users.GetAsync();
        foreach (var tenant in (await tenants.GetAllAsync(ct)).Where(t => user.CanSee(t.Id)))
        {
            rows.AddRange((await devices.GetForTenantAsync(tenant.Id, ct)).Select(d => new DeviceRow(tenant, d)));
            if (await devices.GetSyncStatusAsync(tenant.Id, ct) is { } status)
                syncs.Add((tenant, status));
        }
        return new EndpointFleet(rows, DateTimeOffset.UtcNow, syncs);
    }

    public async Task<DeviceDetail?> GetDeviceAsync(Guid tenantId, string deviceId, CancellationToken ct = default)
    {
        // Not found rather than forbidden, so IDs of other clients' tenants don't leak.
        if (!(await users.GetAsync()).CanSee(tenantId)) return null;
        if (await tenants.GetAsync(tenantId, ct) is not { } tenant) return null;
        if (await devices.GetAsync(tenantId, deviceId, ct) is not { } device) return null;

        // Tenant-wide device policy gaps (from Maester/ScubaGear) that explain why this device fails.
        var related = (await findings.GetForTenantAsync(tenantId, ct))
            .Where(f => f.Category == "Devices" && f.Status is FindingStatus.Failed or FindingStatus.Investigate)
            .OrderByDescending(f => f.Severity)
            .ToList();

        return new DeviceDetail(tenant, device, related);
    }
}

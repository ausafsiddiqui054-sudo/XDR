using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Worker;

public sealed record DeviceSyncSummary(int Tenants, int Synced, int Failed, int Skipped);

/// <summary>
/// One device sync pass: reads every onboarded tenant's inventory and stores the result.
/// A failure in one tenant is recorded against that tenant and never stops the others.
/// </summary>
public sealed class DeviceSyncService(
    ITenantRepository tenants,
    IDeviceRepository devices,
    IDeviceInventorySource source,
    IOptions<DeviceSyncOptions> options,
    ILogger<DeviceSyncService> logger,
    PlaybookRunner? playbooks = null)
{
    public async Task<DeviceSyncSummary> SyncAllAsync(CancellationToken ct = default)
    {
        var all = await tenants.GetAllAsync(ct);
        var eligible = all.Where(IsOnboarded).ToList();
        int synced = 0, failed = 0;

        await Parallel.ForEachAsync(eligible,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Value.MaxParallelTenants), CancellationToken = ct },
            async (tenant, token) =>
            {
                if (await SyncTenantAsync(tenant, token)) Interlocked.Increment(ref synced);
                else Interlocked.Increment(ref failed);
            });

        var summary = new DeviceSyncSummary(all.Count, synced, failed, all.Count - eligible.Count);
        logger.LogInformation("{Source} device sync pass: {Synced} synced, {Failed} failed, {Skipped} not onboarded, of {Tenants} tenants",
            source.Name, summary.Synced, summary.Failed, summary.Skipped, summary.Tenants);
        return summary;
    }

    /// <summary>Syncs one tenant and stores the outcome. Returns true if the inventory was refreshed.</summary>
    public async Task<bool> SyncTenantAsync(Tenant tenant, CancellationToken ct = default)
    {
        DeviceSyncResult result;
        try
        {
            result = await source.GetDevicesAsync(tenant, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogError(ex, "{Source} sync for {Tenant} ({TenantId}) threw", source.Name, tenant.DisplayName, tenant.Id);
            result = Failure(tenant, $"Unexpected error: {ex.Message}");
        }

        try
        {
            await devices.SaveSyncAsync(result, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            logger.LogError(ex, "Saving {Source} sync for {Tenant} ({TenantId}) failed", source.Name, tenant.DisplayName, tenant.Id);
            return false;
        }

        // Playbooks look at the fresh inventory only; a failed sync keeps the old one, which they've already seen.
        if (result.Succeeded && playbooks is not null)
        {
            try
            {
                await playbooks.RunForTenantAsync(tenant, ct);
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                logger.LogError(ex, "Playbooks for {Tenant} ({TenantId}) failed; the sync itself succeeded", tenant.DisplayName, tenant.Id);
            }
        }

        return result.Succeeded;
    }

    /// <summary>Consent granted and a credential configured. Others aren't ready for sync yet.</summary>
    private static bool IsOnboarded(Tenant t) =>
        t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted
        && !string.IsNullOrWhiteSpace(t.CredentialReference);

    private DeviceSyncResult Failure(Tenant tenant, string error) => new()
    {
        TenantId = tenant.Id,
        Source = source.Name,
        StartedAt = DateTimeOffset.UtcNow,
        CompletedAt = DateTimeOffset.UtcNow,
        Devices = [],
        Succeeded = false,
        Error = error
    };
}

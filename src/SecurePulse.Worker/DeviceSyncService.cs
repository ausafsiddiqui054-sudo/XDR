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
    ILogger<DeviceSyncService> logger)
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
                DeviceSyncResult result;
                try
                {
                    result = await source.GetDevicesAsync(tenant, token);
                }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    logger.LogError(ex, "{Source} sync for {Tenant} ({TenantId}) threw", source.Name, tenant.DisplayName, tenant.Id);
                    result = Failure(tenant, $"Unexpected error: {ex.Message}");
                }

                try
                {
                    await devices.SaveSyncAsync(result, token);
                }
                catch (Exception ex) when (!token.IsCancellationRequested)
                {
                    logger.LogError(ex, "Saving {Source} sync for {Tenant} ({TenantId}) failed", source.Name, tenant.DisplayName, tenant.Id);
                    Interlocked.Increment(ref failed);
                    return;
                }

                if (result.Succeeded) Interlocked.Increment(ref synced);
                else Interlocked.Increment(ref failed);
            });

        var summary = new DeviceSyncSummary(all.Count, synced, failed, all.Count - eligible.Count);
        logger.LogInformation("{Source} device sync pass: {Synced} synced, {Failed} failed, {Skipped} not onboarded, of {Tenants} tenants",
            source.Name, summary.Synced, summary.Failed, summary.Skipped, summary.Tenants);
        return summary;
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

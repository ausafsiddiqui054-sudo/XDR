using SecurePulse.Core.Models;

namespace SecurePulse.Core.Abstractions;

/// <summary>
/// Every engine (Maester, ScubaGear, Wazuh, GoPhish) implements this and returns
/// normalized <see cref="Finding"/>s. Engines must run out of process so a hung
/// or crashing scan can never take down the portal.
/// </summary>
public interface IScanEngine
{
    string Name { get; }

    Task<ScanResult> RunAsync(Tenant tenant, CancellationToken cancellationToken = default);
}

public interface ITenantRepository
{
    Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default);
    Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default);
}

public interface IFindingRepository
{
    Task<IReadOnlyList<Finding>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default);
    Task<IReadOnlyList<Finding>> GetAllAsync(CancellationToken ct = default);
    Task SaveScanAsync(ScanResult result, CancellationToken ct = default);
}

/// <summary>
/// Reads a tenant's managed device inventory (e.g. Intune through Microsoft Graph).
/// Implementations use read-only permissions and return normalized <see cref="ManagedDevice"/>s.
/// </summary>
public interface IDeviceInventorySource
{
    string Name { get; }

    Task<DeviceSyncResult> GetDevicesAsync(Tenant tenant, CancellationToken cancellationToken = default);
}

public interface IDeviceRepository
{
    Task<IReadOnlyList<ManagedDevice>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default);
    Task<ManagedDevice?> GetAsync(Guid tenantId, string deviceId, CancellationToken ct = default);

    /// <summary>
    /// Records a sync. On success the tenant's stored devices are replaced with the result's devices;
    /// on failure the previous inventory is kept and only the status changes.
    /// </summary>
    Task SaveSyncAsync(DeviceSyncResult result, CancellationToken ct = default);

    Task<DeviceSyncStatus?> GetSyncStatusAsync(Guid tenantId, CancellationToken ct = default);
}

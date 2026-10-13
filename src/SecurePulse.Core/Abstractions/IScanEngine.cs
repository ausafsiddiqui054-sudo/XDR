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

public interface IOnboardingRepository
{
    /// <param name="stateHash">SHA-256 of the consent link's state value, used to find the request on callback.</param>
    Task AddAsync(OnboardingRequest request, string stateHash, CancellationToken ct = default);

    Task<OnboardingRequest?> GetAsync(Guid id, CancellationToken ct = default);
    Task<OnboardingRequest?> FindByStateHashAsync(string stateHash, CancellationToken ct = default);

    /// <summary>Requests still in progress or failed recently, newest first.</summary>
    Task<IReadOnlyList<OnboardingRequest>> GetOpenAsync(CancellationToken ct = default);

    Task<IReadOnlyList<OnboardingRequest>> GetVerifyingAsync(CancellationToken ct = default);

    /// <summary>
    /// Moves an unexpired request from AwaitingConsent to Verifying. Atomic, so a consent link
    /// can only be used once. Returns false if the request wasn't awaiting consent or had expired.
    /// </summary>
    Task<bool> MarkConsentReceivedAsync(Guid id, DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Records a problem without changing the status (e.g. the admin declined; the link stays usable).</summary>
    Task SetErrorAsync(Guid id, string error, CancellationToken ct = default);

    /// <summary>Counts a failed verification attempt; <paramref name="final"/> marks the request Failed.</summary>
    Task RecordVerificationFailureAsync(Guid id, string error, bool final, CancellationToken ct = default);

    /// <summary>
    /// Completes the request and creates the tenant, or updates the existing tenant with the same
    /// Entra tenant ID (re-consent). Returns the stored tenant.
    /// </summary>
    Task<Tenant> CompleteAsync(Guid id, Tenant tenant, IReadOnlyList<string> grantedPermissions, DateTimeOffset at, CancellationToken ct = default);

    Task CancelAsync(Guid id, CancellationToken ct = default);
}

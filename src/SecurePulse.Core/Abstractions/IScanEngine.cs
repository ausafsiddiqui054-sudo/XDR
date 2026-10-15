using SecurePulse.Core.Models;

namespace SecurePulse.Core.Abstractions;

/// <summary>
/// Every engine (Maester, ScubaGear, Wazuh, GoPhish) implements this and returns
/// normalized <see cref="Finding"/>s. Engines run in the Worker, never the portal: PowerShell
/// engines out of process, API engines (Wazuh) as bounded, read-only HTTP calls.
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

    /// <summary>
    /// Completes a remediation request: the connected tenant with the request's Entra tenant ID gets
    /// remediation access with <paramref name="remediationCredentialReference"/>. Returns the tenant,
    /// or null if no connected tenant matches (the request is then marked failed).
    /// </summary>
    /// <summary>
    /// Sets (or clears, with null) a tenant's Wazuh agent group. Returns false if another tenant already
    /// uses the group; throws <see cref="KeyNotFoundException"/> for an unknown tenant.
    /// </summary>
    Task<bool> SetWazuhAgentGroupAsync(Guid tenantId, string? group, CancellationToken ct = default);

    Task<Tenant?> CompleteRemediationAsync(Guid id, string remediationCredentialReference, IReadOnlyList<string> grantedPermissions,
        DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Turns remediation off for a tenant: back to read-only, remediation credential cleared. False if it wasn't on.</summary>
    Task<bool> DisableRemediationAsync(Guid tenantId, CancellationToken ct = default);

    Task CancelAsync(Guid id, CancellationToken ct = default);
}

public interface IPortalUserRepository
{
    Task<IReadOnlyList<PortalUser>> GetAllAsync(CancellationToken ct = default);
    Task<PortalUser?> GetAsync(Guid id, CancellationToken ct = default);

    /// <summary>The user bound to this Entra identity, or null. Read-only; used on every request.</summary>
    Task<PortalUser?> FindByObjectIdAsync(Guid entraTenantId, Guid objectId, CancellationToken ct = default);

    /// <summary>
    /// Called once per sign-in. Returns the user bound to (tenant, object ID); otherwise binds an
    /// unclaimed invitation for (tenant, sign-in name) to the object ID. Null if neither exists.
    /// </summary>
    Task<PortalUser?> SignInAsync(Guid entraTenantId, Guid objectId, string? userPrincipalName, string? displayName,
        DateTimeOffset at, CancellationToken ct = default);

    /// <exception cref="DuplicatePortalUserException">Same tenant and sign-in name already present.</exception>
    Task AddAsync(PortalUser user, CancellationToken ct = default);

    /// <exception cref="LastOwnerException">The change would remove the last signed-in Owner.</exception>
    Task UpdateRoleAsync(Guid id, PortalRole role, Guid? clientTenantId, CancellationToken ct = default);

    /// <exception cref="LastOwnerException">The change would remove the last signed-in Owner.</exception>
    Task RemoveAsync(Guid id, CancellationToken ct = default);
}

/// <summary>Append-only record of security events. There is deliberately no update or delete.</summary>
public interface IAuditLog
{
    Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default);

    /// <summary>Newest first.</summary>
    Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken ct = default);
}

/// <summary>
/// Deletes old audit events for the retention job. Implementations connect with a separate
/// maintenance role: the application's own database role can never delete audit events.
/// </summary>
public interface IAuditPurger
{
    /// <summary>Events older than <paramref name="cutoff"/> that may be deleted (already exported, if an export is set up).</summary>
    Task<long> CountOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default);

    /// <summary>Events older than <paramref name="cutoff"/> held back because an export hasn't sent them yet.</summary>
    Task<long> CountAwaitingExportAsync(DateTimeOffset cutoff, CancellationToken ct = default);

    /// <summary>
    /// Deletes events older than <paramref name="cutoff"/> in batches, never ones an export hasn't sent yet. Returns how many were deleted, or
    /// null when another Worker is already purging. Throws <see cref="AuditPurgeException"/> if it fails partway.
    /// </summary>
    Task<long?> PurgeOlderThanAsync(DateTimeOffset cutoff, int batchSize, CancellationToken ct = default);
}

/// <summary>
/// The export checkpoint per destination. Events are read in the order the database stored them,
/// and the checkpoint only moves after the destination accepted them: at least once, never lost.
/// </summary>
public interface IAuditExportStore
{
    /// <summary>
    /// Locks <paramref name="destination"/>'s checkpoint and reads up to <paramref name="maxEvents"/>
    /// events after it, leaving out ones stored less than <paramref name="lag"/> ago (so a slow insert
    /// can't commit behind the checkpoint). Null when another Worker holds the checkpoint.
    /// </summary>
    Task<IAuditExportLease?> TryLeaseAsync(string destination, TimeSpan lag, int maxEvents, CancellationToken ct = default);

    /// <summary>Records a failed attempt (the checkpoint doesn't move).</summary>
    Task RecordFailureAsync(string destination, string error, CancellationToken ct = default);

    /// <summary>Null when nothing has ever been exported to <paramref name="destination"/>.</summary>
    Task<AuditExportStatus?> GetStatusAsync(string destination, CancellationToken ct = default);
}

/// <summary>Events read for one export call. Disposing without <see cref="CommitAsync"/> leaves the checkpoint where it was.</summary>
public interface IAuditExportLease : IAsyncDisposable
{
    /// <summary>Oldest first, each with <see cref="AuditEvent.RecordedAt"/>.</summary>
    IReadOnlyList<AuditEvent> Events { get; }

    /// <summary>Moves the checkpoint past the first <paramref name="count"/> events (0: just records the attempt) and releases the lock.</summary>
    Task CommitAsync(int count, CancellationToken ct = default);
}

public sealed class AuditPurgeException(long deleted, Exception inner)
    : Exception($"Audit purge failed after deleting {deleted} events: {inner.Message}", inner)
{
    public long Deleted { get; } = deleted;
}

/// <summary>
/// The remote action queue. State changes are conditional updates, so two people deciding at once,
/// or two Workers sending at once, can't both succeed.
/// </summary>
public interface IDeviceActionRepository
{
    /// <summary>
    /// Adds a pending request, unless the device already has an open one (pending, approved or
    /// sending), which is returned with <c>Created = false</c>.
    /// </summary>
    Task<(DeviceActionRequest Request, bool Created)> AddAsync(DeviceActionRequest request, CancellationToken ct = default);

    Task<DeviceActionRequest?> GetAsync(Guid id, CancellationToken ct = default);

    /// <summary>Newest first.</summary>
    Task<IReadOnlyList<DeviceActionRequest>> QueryAsync(DeviceActionQuery query, CancellationToken ct = default);

    /// <summary>
    /// Approves or rejects a request that is still pending and unexpired at <paramref name="at"/>.
    /// Returns the updated request, or null if it was no longer pending (someone else decided, it was
    /// cancelled, or it expired). Policy checks happen before this call.
    /// </summary>
    Task<DeviceActionRequest?> DecideAsync(Guid id, bool approve, Guid deciderId, string deciderName, PortalRole deciderRole, string? note,
        DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Cancels a request that is pending or approved but not yet claimed for sending.</summary>
    Task<DeviceActionRequest?> CancelAsync(Guid id, string cancelledBy, string? reason, DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Cancels every open-but-unsent request for a tenant (remediation access turned off). Returns them.</summary>
    Task<IReadOnlyList<DeviceActionRequest>> CancelOpenForTenantAsync(Guid tenantId, string cancelledBy, string reason, DateTimeOffset at,
        CancellationToken ct = default);

    /// <summary>Moves the oldest approved request to Sending and returns it; null if none.</summary>
    Task<DeviceActionRequest?> ClaimNextApprovedAsync(DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Records the outcome of a request that is Sending.</summary>
    Task CompleteAsync(Guid id, bool succeeded, string? error, DateTimeOffset at, CancellationToken ct = default);

    /// <summary>
    /// Expires pending requests past their deadline and approved ones not sent within
    /// <paramref name="sendWindow"/>, and fails ones stuck in Sending since before
    /// <paramref name="sendingBefore"/>. Returns the requests changed.
    /// </summary>
    Task<IReadOnlyList<DeviceActionRequest>> ExpireAsync(DateTimeOffset at, TimeSpan sendWindow, DateTimeOffset sendingBefore,
        CancellationToken ct = default);
}

/// <summary>The scan queue. Safe for several Workers: a run is claimed by exactly one of them.</summary>
public interface IScanRunRepository
{
    /// <summary>
    /// Queues a run, unless the tenant already has a queued or running run for that engine, in
    /// which case that one is returned with <c>Created = false</c>.
    /// </summary>
    Task<(ScanRun Run, bool Created)> EnqueueAsync(Guid tenantId, string engine, ScanTrigger trigger, string? requestedBy,
        DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Moves the next queued run (manual first, then oldest) to Running and returns it; null if none.</summary>
    Task<ScanRun?> ClaimNextAsync(IReadOnlyCollection<string> engines, DateTimeOffset at, CancellationToken ct = default);

    Task CompleteAsync(Guid runId, bool succeeded, int? findingCount, string? error, DateTimeOffset at, CancellationToken ct = default);

    /// <summary>Fails runs stuck in Running since before <paramref name="startedBefore"/> (e.g. a Worker crashed).</summary>
    Task<int> FailStaleAsync(DateTimeOffset startedBefore, string error, DateTimeOffset at, CancellationToken ct = default);

    /// <summary>The most recent run per tenant and engine.</summary>
    Task<IReadOnlyList<ScanRun>> GetLatestAsync(CancellationToken ct = default);
}

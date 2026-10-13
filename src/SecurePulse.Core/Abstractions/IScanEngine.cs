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

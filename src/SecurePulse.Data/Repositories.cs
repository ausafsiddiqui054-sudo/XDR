using Microsoft.EntityFrameworkCore;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

// Repositories create a short-lived DbContext per call from the factory. That suits both
// Blazor Server circuits (no shared context across concurrent renders) and the Worker.

public sealed class EfTenantRepository(IDbContextFactory<SecurePulseDbContext> factory) : ITenantRepository
{
    public async Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Tenants.AsNoTracking().OrderBy(t => t.DisplayName).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id, ct))?.ToModel();
    }
}

public sealed class EfFindingRepository(IDbContextFactory<SecurePulseDbContext> factory) : IFindingRepository
{
    public async Task<IReadOnlyList<Finding>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Findings.AsNoTracking().Where(f => f.TenantId == tenantId).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<IReadOnlyList<Finding>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Findings.AsNoTracking().ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    /// <summary>
    /// Replaces the tenant's findings from this result's engine only, so a Maester scan
    /// doesn't wipe ScubaGear findings. Failed scans change nothing.
    /// </summary>
    public async Task SaveScanAsync(ScanResult result, CancellationToken ct = default)
    {
        if (!result.Succeeded) return;

        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        await db.Findings.Where(f => f.TenantId == result.TenantId && f.Source == result.Source).ExecuteDeleteAsync(ct);
        db.Findings.AddRange(result.Findings.Select(f => f.ToEntity()));
        await db.Tenants.Where(t => t.Id == result.TenantId)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.LastScanAt, result.CompletedAt), ct);
        await db.SaveChangesAsync(ct);

        await tx.CommitAsync(ct);
    }
}

public sealed class EfDeviceRepository(IDbContextFactory<SecurePulseDbContext> factory) : IDeviceRepository
{
    private const int MaxErrorLength = 2000;

    public async Task<IReadOnlyList<ManagedDevice>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.Devices.AsNoTracking().Where(d => d.TenantId == tenantId).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<ManagedDevice?> GetAsync(Guid tenantId, string deviceId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.Devices.AsNoTracking().FirstOrDefaultAsync(d => d.TenantId == tenantId && d.Id == deviceId, ct))?.ToModel();
    }

    public async Task SaveSyncAsync(DeviceSyncResult result, CancellationToken ct = default)
    {
        if (result.Succeeded && result.Devices.Any(d => d.TenantId != result.TenantId))
            throw new ArgumentException("Every device in a sync result must belong to the result's tenant.", nameof(result));

        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        if (result.Succeeded)
        {
            // Full replace: devices removed from Intune since the last sync disappear here too.
            await db.Devices.Where(d => d.TenantId == result.TenantId).ExecuteDeleteAsync(ct);
            db.Devices.AddRange(result.Devices.DistinctBy(d => d.Id).Select(d => d.ToEntity()));
        }

        var status = await db.DeviceSyncStatuses.FirstOrDefaultAsync(s => s.TenantId == result.TenantId, ct);
        if (status is null)
        {
            status = new DeviceSyncStatusEntity { TenantId = result.TenantId };
            db.DeviceSyncStatuses.Add(status);
        }

        status.LastAttemptAt = result.CompletedAt;
        status.Succeeded = result.Succeeded;
        status.Error = result.Error is { Length: > MaxErrorLength } e ? e[..MaxErrorLength] : result.Error;
        if (result.Succeeded)
        {
            status.LastSuccessAt = result.CompletedAt;
            status.Warning = result.Warning is { Length: > MaxErrorLength } w ? w[..MaxErrorLength] : result.Warning;
            status.DeviceCount = result.Devices.DistinctBy(d => d.Id).Count();
        }

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<DeviceSyncStatus?> GetSyncStatusAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.DeviceSyncStatuses.AsNoTracking().FirstOrDefaultAsync(s => s.TenantId == tenantId, ct))?.ToModel();
    }
}

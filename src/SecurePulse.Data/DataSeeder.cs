using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Models;

namespace SecurePulse.Data;

/// <summary>Development helper: fills an empty database with demo data so the portal isn't blank.</summary>
public static class DataSeeder
{
    /// <returns>True if data was written; false if the database already had tenants.</returns>
    public static async Task<bool> SeedIfEmptyAsync(
        this IServiceProvider services,
        IEnumerable<Tenant> tenants,
        IEnumerable<Finding> findings,
        IEnumerable<ManagedDevice> devices,
        CancellationToken ct = default)
    {
        var factory = services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct);
        if (await db.Tenants.AnyAsync(ct)) return false;

        var deviceList = devices.ToList();
        var now = DateTimeOffset.UtcNow;

        db.Tenants.AddRange(tenants.Select(t => t.ToEntity()));
        db.Findings.AddRange(findings.Select(f => f.ToEntity()));
        db.Devices.AddRange(deviceList.Select(d => d.ToEntity()));
        db.DeviceSyncStatuses.AddRange(deviceList.GroupBy(d => d.TenantId).Select(g => new Entities.DeviceSyncStatusEntity
        {
            TenantId = g.Key, LastAttemptAt = now, LastSuccessAt = now, Succeeded = true, DeviceCount = g.Count()
        }));

        await db.SaveChangesAsync(ct);
        return true;
    }
}

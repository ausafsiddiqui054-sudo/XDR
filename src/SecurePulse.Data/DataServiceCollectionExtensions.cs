using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;

namespace SecurePulse.Data;

public static class DataServiceCollectionExtensions
{
    /// <summary>Registers the PostgreSQL-backed tenant, finding and device repositories.</summary>
    public static IServiceCollection AddSecurePulseData(this IServiceCollection services, string connectionString)
    {
        services.AddPooledDbContextFactory<SecurePulseDbContext>(o => o.UseNpgsql(connectionString));
        services.AddSingleton<ITenantRepository, EfTenantRepository>();
        services.AddSingleton<IFindingRepository, EfFindingRepository>();
        services.AddSingleton<IDeviceRepository, EfDeviceRepository>();
        return services;
    }

    /// <summary>Applies pending migrations. EF Core takes a database lock, so concurrent callers are safe.</summary>
    public static async Task MigrateSecurePulseDatabaseAsync(this IServiceProvider services, CancellationToken ct = default)
    {
        var factory = services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var db = await factory.CreateDbContextAsync(ct);
        await db.Database.MigrateAsync(ct);
    }
}

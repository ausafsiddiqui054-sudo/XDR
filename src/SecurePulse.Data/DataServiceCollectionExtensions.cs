using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecurePulse.Core.Abstractions;

namespace SecurePulse.Data;

public static class DataServiceCollectionExtensions
{
    /// <summary>Registers the PostgreSQL-backed repositories.</summary>
    public static IServiceCollection AddSecurePulseData(this IServiceCollection services, string connectionString)
    {
        services.AddPooledDbContextFactory<SecurePulseDbContext>(o => o.UseNpgsql(connectionString));
        services.AddSingleton<ITenantRepository, EfTenantRepository>();
        services.AddSingleton<IFindingRepository, EfFindingRepository>();
        services.AddSingleton<IDeviceRepository, EfDeviceRepository>();
        services.AddSingleton<IOnboardingRepository, EfOnboardingRepository>();
        services.AddSingleton<IPortalUserRepository, EfPortalUserRepository>();
        services.AddSingleton<IAuditLog, EfAuditLog>();
        services.AddSingleton<IScanRunRepository, EfScanRunRepository>();
        services.AddSingleton<IDeviceActionRepository, EfDeviceActionRepository>();
        services.AddSingleton<IPlaybookRepository, EfPlaybookRepository>();
        services.AddSingleton<IConfigurationChangeRepository, EfConfigurationChangeRepository>();
        services.AddSingleton<IFindingPlaybookRepository, EfFindingPlaybookRepository>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<IAuditExportStore, EfAuditExportStore>();
        return services;
    }

    /// <summary>
    /// The audit retention purger, on its own maintenance connection (a login that is a member of
    /// <see cref="PostgresAuditPurger.PurgeRole"/>). Only the Worker that runs retention registers it.
    /// </summary>
    public static IServiceCollection AddAuditPurger(this IServiceCollection services, string maintenanceConnectionString)
    {
        services.AddSingleton<IAuditPurger>(new PostgresAuditPurger(Npgsql.NpgsqlDataSource.Create(maintenanceConnectionString)));
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

using Microsoft.EntityFrameworkCore;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class SecurePulseDbContext(DbContextOptions<SecurePulseDbContext> options) : DbContext(options)
{
    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();
    public DbSet<FindingEntity> Findings => Set<FindingEntity>();
    public DbSet<ManagedDeviceEntity> Devices => Set<ManagedDeviceEntity>();
    public DbSet<DeviceSyncStatusEntity> DeviceSyncStatuses => Set<DeviceSyncStatusEntity>();

    protected override void ConfigureConventions(ModelConfigurationBuilder builder)
    {
        // Store enums by name so rows stay readable and reordering an enum can't corrupt data.
        builder.Properties<Enum>().HaveConversion<string>().HaveMaxLength(32);
    }

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<TenantEntity>(e =>
        {
            e.ToTable("tenants");
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.EntraTenantId).IsUnique();
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.PrimaryDomain).HasMaxLength(256);
            e.Property(x => x.PartnerName).HasMaxLength(256);
            e.Property(x => x.Industry).HasMaxLength(128);
            e.Property(x => x.CredentialReference).HasMaxLength(256);
        });

        b.Entity<FindingEntity>(e =>
        {
            e.ToTable("findings");
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(256);
            e.Property(x => x.Source).HasMaxLength(64);
            e.Property(x => x.SourceCheckId).HasMaxLength(128);
            e.Property(x => x.Category).HasMaxLength(128);
            e.HasIndex(x => new { x.TenantId, x.Source });
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ManagedDeviceEntity>(e =>
        {
            e.ToTable("managed_devices");
            // Device IDs come from each tenant's Intune, so key on the pair.
            e.HasKey(x => new { x.TenantId, x.Id });
            e.Property(x => x.Id).HasMaxLength(64);
            e.Property(x => x.DeviceName).HasMaxLength(256);
            e.Property(x => x.UserPrincipalName).HasMaxLength(320);
            e.OwnsMany(x => x.ComplianceSettings, s => s.ToJson());
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<DeviceSyncStatusEntity>(e =>
        {
            e.ToTable("device_sync_status");
            e.HasKey(x => x.TenantId);
            e.Property(x => x.Error).HasMaxLength(2000);
            e.HasOne<TenantEntity>().WithOne().HasForeignKey<DeviceSyncStatusEntity>(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}

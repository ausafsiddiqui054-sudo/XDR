using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class SecurePulseDbContext(DbContextOptions<SecurePulseDbContext> options) : DbContext(options)
{
    public DbSet<TenantEntity> Tenants => Set<TenantEntity>();
    public DbSet<FindingEntity> Findings => Set<FindingEntity>();
    public DbSet<ManagedDeviceEntity> Devices => Set<ManagedDeviceEntity>();
    public DbSet<DeviceSyncStatusEntity> DeviceSyncStatuses => Set<DeviceSyncStatusEntity>();
    public DbSet<OnboardingRequestEntity> OnboardingRequests => Set<OnboardingRequestEntity>();
    public DbSet<PortalUserEntity> PortalUsers => Set<PortalUserEntity>();
    public DbSet<AuditEventEntity> AuditEvents => Set<AuditEventEntity>();
    public DbSet<ScanRunEntity> ScanRuns => Set<ScanRunEntity>();
    public DbSet<DeviceActionEntity> DeviceActions => Set<DeviceActionEntity>();
    public DbSet<DataProtectionKeyEntity> DataProtectionKeys => Set<DataProtectionKeyEntity>();

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
            e.Property(x => x.RemediationCredentialReference).HasMaxLength(256);
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
            e.OwnsOne(x => x.DefenderDetails, h =>
            {
                h.ToJson();
                h.OwnsOne(x => x.Antivirus);
                h.OwnsOne(x => x.Sensor);
            });
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<DeviceSyncStatusEntity>(e =>
        {
            e.ToTable("device_sync_status");
            e.HasKey(x => x.TenantId);
            e.Property(x => x.Error).HasMaxLength(2000);
            e.Property(x => x.Warning).HasMaxLength(2000);
            e.HasOne<TenantEntity>().WithOne().HasForeignKey<DeviceSyncStatusEntity>(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<OnboardingRequestEntity>(e =>
        {
            e.ToTable("onboarding_requests");
            e.HasKey(x => x.Id);
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.PrimaryDomain).HasMaxLength(256);
            e.Property(x => x.PartnerName).HasMaxLength(256);
            e.Property(x => x.Industry).HasMaxLength(128);
            e.Property(x => x.StateHash).HasMaxLength(64);
            e.Property(x => x.ProtectedState).HasMaxLength(1024);
            e.Property(x => x.LastError).HasMaxLength(2000);
            e.Property(x => x.StartedBy).HasMaxLength(512);
            e.HasIndex(x => x.StateHash).IsUnique();
            e.HasIndex(x => new { x.Status, x.CreatedAt });
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.SetNull);
        });
    
        b.Entity<PortalUserEntity>(e =>
        {
            e.ToTable("portal_users");
            e.HasKey(x => x.Id);
            e.Property(x => x.UserPrincipalName).HasMaxLength(320);
            e.Property(x => x.DisplayName).HasMaxLength(256);
            e.Property(x => x.CreatedBy).HasMaxLength(512);
            // One invitation per sign-in name per tenant; one portal user per Entra identity.
            e.HasIndex(x => new { x.EntraTenantId, x.UserPrincipalName }).IsUnique();
            e.HasIndex(x => new { x.EntraTenantId, x.ObjectId }).IsUnique().HasFilter("\"ObjectId\" IS NOT NULL");
            // Removing a client tenant removes its viewers' access with it.
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.ClientTenantId).OnDelete(DeleteBehavior.Cascade);
        });
    
        b.Entity<DataProtectionKeyEntity>(e =>
        {
            e.ToTable("data_protection_keys");
            e.HasKey(x => x.Id);
            e.Property(x => x.FriendlyName).HasMaxLength(256);
            e.HasIndex(x => x.FriendlyName).IsUnique();
        });

        b.Entity<AuditEventEntity>(e =>
        {
            e.ToTable("audit_events");
            e.HasKey(x => x.Id);
            e.Property(x => x.Action).HasMaxLength(64);
            e.Property(x => x.Category).HasMaxLength(32);
            e.Property(x => x.ActorName).HasMaxLength(512);
            e.Property(x => x.TargetType).HasMaxLength(64);
            e.Property(x => x.TargetId).HasMaxLength(128);
            e.Property(x => x.Summary).HasMaxLength(1000);
            e.Property(x => x.IpAddress).HasMaxLength(64);
            e.Property(x => x.Details)
                .HasColumnType("jsonb")
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>(),
                    new ValueComparer<Dictionary<string, string>>(
                        (a, c) => JsonSerializer.Serialize(a, (JsonSerializerOptions?)null) == JsonSerializer.Serialize(c, (JsonSerializerOptions?)null),
                        v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null).GetHashCode(),
                        v => new Dictionary<string, string>(v)));
            // Newest-first listing and keyset paging, plus the page's filters.
            e.HasIndex(x => new { x.OccurredAt, x.Id }).IsDescending();
            e.HasIndex(x => new { x.Category, x.OccurredAt });
            e.HasIndex(x => new { x.TenantId, x.OccurredAt });
            // No foreign keys: the record must survive deleted tenants and users.
        });
    
        b.Entity<DeviceActionEntity>(e =>
        {
            e.ToTable("device_actions");
            e.HasKey(x => x.Id);
            e.Property(x => x.DeviceId).HasMaxLength(64);
            e.Property(x => x.DeviceName).HasMaxLength(256);
            e.Property(x => x.Reason).HasMaxLength(DeviceActionPolicy.MaxReasonLength);
            e.Property(x => x.RequestedByName).HasMaxLength(512);
            e.Property(x => x.DecidedByName).HasMaxLength(512);
            e.Property(x => x.DecisionNote).HasMaxLength(DeviceActionPolicy.MaxNoteLength);
            e.Property(x => x.CancelledBy).HasMaxLength(512);
            e.Property(x => x.Error).HasMaxLength(2000);
            // At most one open (pending, approved or sending) action per device; requests rely on this.
            e.HasIndex(x => new { x.TenantId, x.DeviceId }).IsUnique()
                .HasFilter("\"Status\" IN ('PendingApproval', 'Approved', 'Sending')")
                .HasDatabaseName("IX_device_actions_open");
            e.HasIndex(x => new { x.Status, x.DecidedAt });
            e.HasIndex(x => new { x.TenantId, x.RequestedAt });
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ScanRunEntity>(e =>
        {
            e.ToTable("scan_runs");
            e.HasKey(x => x.Id);
            e.Property(x => x.Engine).HasMaxLength(64);
            e.Property(x => x.RequestedBy).HasMaxLength(512);
            e.Property(x => x.Error).HasMaxLength(2000);
            // At most one queued-or-running run per tenant and engine; enqueue relies on this.
            e.HasIndex(x => new { x.TenantId, x.Engine }).IsUnique()
                .HasFilter("\"Status\" IN ('Queued', 'Running')")
                .HasDatabaseName("IX_scan_runs_active");
            e.HasIndex(x => new { x.Status, x.QueuedAt });
            e.HasIndex(x => new { x.TenantId, x.Engine, x.QueuedAt });
            e.HasOne<TenantEntity>().WithMany().HasForeignKey(x => x.TenantId).OnDelete(DeleteBehavior.Cascade);
        });
    }
}

using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;

namespace SecurePulse.Tests.Data;

public class RepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private ITenantRepository Tenants => db.Services.GetRequiredService<ITenantRepository>();
    private IFindingRepository Findings => db.Services.GetRequiredService<IFindingRepository>();
    private IDeviceRepository Devices => db.Services.GetRequiredService<IDeviceRepository>();

    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 6, 0, 0, TimeSpan.Zero);

    // Tests share one database per class, so each adds its own tenants and only looks at those.
    // ITenantRepository is read-only (onboarding will own writes), so insert through the context.
    private async Task<Tenant> NewTenantAsync(string name = "Contoso Clinic")
    {
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(),
            EntraTenantId = Guid.NewGuid(),
            DisplayName = name,
            PrimaryDomain = "contoso.example",
            PartnerName = "Gulf IT Services",
            Industry = "Healthcare",
            CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
            ConsentState = TenantConsentState.ReadOnlyGranted
        };
        var factory = db.Services.GetRequiredService<Microsoft.EntityFrameworkCore.IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        ctx.Tenants.Add(new SecurePulse.Data.Entities.TenantEntity
        {
            Id = tenant.Id, EntraTenantId = tenant.EntraTenantId, DisplayName = tenant.DisplayName, PrimaryDomain = tenant.PrimaryDomain,
            PartnerName = tenant.PartnerName, Industry = tenant.Industry, CredentialReference = tenant.CredentialReference, ConsentState = tenant.ConsentState
        });
        await ctx.SaveChangesAsync();
        return tenant;
    }

    private static ManagedDevice Device(Tenant t, string id, params DeviceComplianceSetting[] settings) => new()
    {
        Id = id,
        TenantId = t.Id,
        DeviceName = $"PC-{id}",
        UserDisplayName = "Aisha Rahman",
        UserPrincipalName = "aisha@contoso.example",
        Platform = DevicePlatform.Windows,
        OsVersion = "10.0.22631.4317",
        Manufacturer = "Dell",
        Model = "Latitude 5440",
        SerialNumber = "ABC123",
        Ownership = DeviceOwnership.Corporate,
        ComplianceState = settings.Any(s => !s.Compliant) ? DeviceComplianceState.Noncompliant : DeviceComplianceState.Compliant,
        IsEncrypted = true,
        Defender = DefenderState.Unknown,
        EnrolledAt = T0.AddDays(-100),
        LastSyncAt = T0.AddHours(-2),
        ComplianceSettings = settings
    };

    private static DeviceSyncResult Sync(Tenant t, DateTimeOffset at, params ManagedDevice[] devices) => new()
    {
        TenantId = t.Id, Source = "Intune", StartedAt = at, CompletedAt = at, Devices = devices
    };

    [PostgresFact]
    public async Task TenantRoundTrip()
    {
        var t = await NewTenantAsync("Round Trip Dental");

        var loaded = await Tenants.GetAsync(t.Id);

        Assert.Equal(t, loaded);
        Assert.Contains(await Tenants.GetAllAsync(), x => x.Id == t.Id);
        Assert.Null(await Tenants.GetAsync(Guid.NewGuid()));
    }

    [PostgresFact]
    public async Task DeviceSync_StoresDevicesWithSettingsAndStatus()
    {
        var t = await NewTenantAsync();
        var device = Device(t, "d1",
            new DeviceComplianceSetting("Windows baseline", "BitLocker", false, "OS drive is not encrypted."),
            new DeviceComplianceSetting("Windows baseline", "Firewall", true));

        await Devices.SaveSyncAsync(Sync(t, T0, device, Device(t, "d2")));

        var stored = await Devices.GetForTenantAsync(t.Id);
        Assert.Equal(["d1", "d2"], stored.Select(d => d.Id).Order());
        var loaded = await Devices.GetAsync(t.Id, "d1");
        Assert.NotNull(loaded);
        Assert.Equal(device with { ComplianceSettings = [] }, loaded with { ComplianceSettings = [] });
        Assert.Equal(device.ComplianceSettings, loaded.ComplianceSettings);

        var status = await Devices.GetSyncStatusAsync(t.Id);
        Assert.Equal(new DeviceSyncStatus { TenantId = t.Id, LastAttemptAt = T0, LastSuccessAt = T0, Succeeded = true, DeviceCount = 2 }, status);
    }

    [PostgresFact]
    public async Task DeviceSync_StoresDefenderHealth()
    {
        var t = await NewTenantAsync();
        var (state, health) = DefenderHealthEvaluator.Evaluate(DevicePlatform.Windows,
            new DefenderAntivirusStatus
            {
                MalwareProtectionEnabled = true, RealTimeProtectionEnabled = false, TamperProtectionEnabled = true, SignaturesOutOfDate = false,
                QuickScanOverdue = true, RebootRequired = false, ThreatState = DefenderThreatState.RebootPending, SignatureVersion = "1.419.200.0",
                EngineVersion = "1.1.24090.11", LastQuickScanAt = T0.AddHours(-3), LastReportedAt = T0.AddHours(-1)
            },
            new DefenderSensorStatus
            {
                MachineId = "4f1c0de8b5a2e6f4c3d2b1a09f8e7d6c5b4a3f2e", Onboarding = DefenderOnboarding.Onboarded,
                Health = DefenderSensorHealth.ImpairedCommunication, ExposureLevel = "High", LastSeenAt = T0.AddHours(-2)
            },
            sensorDataAvailable: true);
        var device = Device(t, "d1") with { Defender = state, DefenderDetails = health };

        await Devices.SaveSyncAsync(Sync(t, T0, device, Device(t, "d2")));

        var loaded = (await Devices.GetAsync(t.Id, "d1"))!;
        Assert.Equal(DefenderState.Unhealthy, loaded.Defender);
        Assert.Equal(health.Antivirus, loaded.DefenderDetails!.Antivirus);
        Assert.Equal(health.Sensor, loaded.DefenderDetails.Sensor);
        Assert.True(loaded.DefenderDetails.SensorDataAvailable);
        Assert.Equal(health.Issues, loaded.DefenderDetails.Issues);
        Assert.Equal(3, loaded.DefenderDetails.Issues.Count);
        Assert.Null((await Devices.GetAsync(t.Id, "d2"))!.DefenderDetails); // not read: stays null, not an empty record
    }

    [PostgresFact]
    public async Task DeviceSync_KeepsTheLastSuccessfulSyncsWarning()
    {
        var t = await NewTenantAsync();

        await Devices.SaveSyncAsync(Sync(t, T0, Device(t, "d1")) with { Warning = "Defender for Endpoint sensor health wasn't read: 403" });
        Assert.Equal("Defender for Endpoint sensor health wasn't read: 403", (await Devices.GetSyncStatusAsync(t.Id))!.Warning);

        // A failed sync replaces nothing, the warning included (it describes the inventory still shown).
        await Devices.SaveSyncAsync(Sync(t, T0.AddHours(1)) with { Succeeded = false, Error = "timed out" });
        Assert.Equal("Defender for Endpoint sensor health wasn't read: 403", (await Devices.GetSyncStatusAsync(t.Id))!.Warning);

        await Devices.SaveSyncAsync(Sync(t, T0.AddHours(2), Device(t, "d1")));
        Assert.Null((await Devices.GetSyncStatusAsync(t.Id))!.Warning);

        await Devices.SaveSyncAsync(Sync(t, T0.AddHours(3), Device(t, "d1")) with { Warning = new string('w', 2500) });
        Assert.Equal(2000, (await Devices.GetSyncStatusAsync(t.Id))!.Warning!.Length);
    }

    [PostgresFact]
    public async Task DeviceSync_ReplacesInventorySoRemovedDevicesDisappear()
    {
        var t = await NewTenantAsync();
        await Devices.SaveSyncAsync(Sync(t, T0, Device(t, "d1"), Device(t, "d2")));

        await Devices.SaveSyncAsync(Sync(t, T0.AddHours(4), Device(t, "d2"), Device(t, "d3")));

        Assert.Equal(["d2", "d3"], (await Devices.GetForTenantAsync(t.Id)).Select(d => d.Id).Order());
        Assert.Equal(2, (await Devices.GetSyncStatusAsync(t.Id))!.DeviceCount);
    }

    [PostgresFact]
    public async Task FailedSync_KeepsLastGoodInventoryAndRecordsError()
    {
        var t = await NewTenantAsync();
        await Devices.SaveSyncAsync(Sync(t, T0, Device(t, "d1")));

        var error = new string('x', 2500);
        await Devices.SaveSyncAsync(Sync(t, T0.AddHours(4)) with { Succeeded = false, Error = error });

        Assert.Equal(["d1"], (await Devices.GetForTenantAsync(t.Id)).Select(d => d.Id));
        var status = await Devices.GetSyncStatusAsync(t.Id);
        Assert.NotNull(status);
        Assert.False(status.Succeeded);
        Assert.Equal(T0.AddHours(4), status.LastAttemptAt);
        Assert.Equal(T0, status.LastSuccessAt);
        Assert.Equal(1, status.DeviceCount);
        Assert.Equal(2000, status.Error!.Length);
    }

    [PostgresFact]
    public async Task FirstSyncFailing_HasNoLastSuccess()
    {
        var t = await NewTenantAsync();

        await Devices.SaveSyncAsync(Sync(t, T0) with { Succeeded = false, Error = "Graph returned 403" });

        var status = await Devices.GetSyncStatusAsync(t.Id);
        Assert.NotNull(status);
        Assert.Null(status.LastSuccessAt);
        Assert.Equal("Graph returned 403", status.Error);
        Assert.Empty(await Devices.GetForTenantAsync(t.Id));
    }

    [PostgresFact]
    public async Task DeviceSync_IsIsolatedPerTenant()
    {
        var a = await NewTenantAsync("A");
        var b = await NewTenantAsync("B");
        await Devices.SaveSyncAsync(Sync(a, T0, Device(a, "same-id")));
        await Devices.SaveSyncAsync(Sync(b, T0, Device(b, "same-id"), Device(b, "other")));

        await Devices.SaveSyncAsync(Sync(a, T0.AddHours(4)));

        Assert.Empty(await Devices.GetForTenantAsync(a.Id));
        Assert.Equal(2, (await Devices.GetForTenantAsync(b.Id)).Count);
        Assert.Null(await Devices.GetAsync(a.Id, "same-id"));
        Assert.NotNull(await Devices.GetAsync(b.Id, "same-id"));
    }

    [PostgresFact]
    public async Task DeviceSync_RejectsDevicesFromAnotherTenant()
    {
        var a = await NewTenantAsync("A");
        var b = await NewTenantAsync("B");

        await Assert.ThrowsAsync<ArgumentException>(() => Devices.SaveSyncAsync(Sync(a, T0, Device(b, "d1"))));
        Assert.Null(await Devices.GetSyncStatusAsync(a.Id));
    }

    [PostgresFact]
    public async Task DeviceSync_DeduplicatesDeviceIds()
    {
        var t = await NewTenantAsync();

        await Devices.SaveSyncAsync(Sync(t, T0, Device(t, "d1"), Device(t, "d1")));

        Assert.Single(await Devices.GetForTenantAsync(t.Id));
        Assert.Equal(1, (await Devices.GetSyncStatusAsync(t.Id))!.DeviceCount);
    }

    [PostgresFact]
    public async Task ScanSave_ReplacesOnlyThatEngineAndStampsLastScan()
    {
        var t = await NewTenantAsync();
        Finding F(string id, string source) => new()
        {
            Id = $"{source}:{t.Id:N}:{id}", TenantId = t.Id, Source = source, Title = id, Severity = Severity.High,
            Status = FindingStatus.Failed, Frameworks = ["UAE IA", "CIS M365"], Tags = ["Entra"], DetectedAt = T0
        };
        ScanResult Scan(string source, DateTimeOffset at, params Finding[] f) => new()
        {
            TenantId = t.Id, Source = source, StartedAt = at, CompletedAt = at, Findings = f
        };

        await Findings.SaveScanAsync(Scan("Maester", T0, F("m1", "Maester"), F("m2", "Maester")));
        await Findings.SaveScanAsync(Scan("ScubaGear", T0, F("s1", "ScubaGear")));
        await Findings.SaveScanAsync(Scan("Maester", T0.AddDays(1), F("m3", "Maester")));
        await Findings.SaveScanAsync(Scan("Maester", T0.AddDays(2)) with { Succeeded = false, Error = "pwsh missing" });

        var stored = await Findings.GetForTenantAsync(t.Id);
        Assert.Equal(["m3", "s1"], stored.Select(f => f.Title).Order());
        Assert.Equal(["UAE IA", "CIS M365"], stored.Single(f => f.Title == "m3").Frameworks);
        Assert.Equal(T0.AddDays(1), (await Tenants.GetAsync(t.Id))!.LastScanAt);
    }
}

public class SeederTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    [PostgresFact]
    public async Task SeedsAnEmptyDatabaseOnce()
    {
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Seed Clinic", PrimaryDomain = "seed.example",
            ConsentState = TenantConsentState.ReadOnlyGranted, LastScanAt = DateTimeOffset.UtcNow
        };
        var finding = new Finding
        {
            Id = "sample:1", TenantId = tenant.Id, Source = "Maester", Title = "MFA", Severity = Severity.Critical, Status = FindingStatus.Failed
        };
        var device = new ManagedDevice
        {
            Id = "d1", TenantId = tenant.Id, DeviceName = "PC-1", Platform = DevicePlatform.MacOS, ComplianceState = DeviceComplianceState.Compliant
        };

        Assert.True(await db.Services.SeedIfEmptyAsync([tenant], [finding], [device]));
        Assert.False(await db.Services.SeedIfEmptyAsync([tenant with { Id = Guid.NewGuid() }], [], []));

        Assert.Equal([tenant.Id], (await db.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).Select(t => t.Id));
        Assert.Single(await db.Services.GetRequiredService<IFindingRepository>().GetForTenantAsync(tenant.Id));
        var devices = db.Services.GetRequiredService<IDeviceRepository>();
        Assert.Single(await devices.GetForTenantAsync(tenant.Id));
        Assert.True((await devices.GetSyncStatusAsync(tenant.Id))!.Succeeded);
    }
}

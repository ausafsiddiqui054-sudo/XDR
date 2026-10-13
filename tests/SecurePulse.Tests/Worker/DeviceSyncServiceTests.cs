using System.Collections.Concurrent;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Worker;

public class DeviceSyncServiceTests
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";

    private static Tenant T(string name, TenantConsentState consent = TenantConsentState.ReadOnlyGranted, string? credential = Thumbprint) => new()
    {
        Id = Guid.NewGuid(),
        EntraTenantId = Guid.NewGuid(),
        DisplayName = name,
        PrimaryDomain = $"{name.ToLowerInvariant()}.example",
        ConsentState = consent,
        CredentialReference = credential
    };

    private sealed class Tenants(params Tenant[] all) : ITenantRepository
    {
        public Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<Tenant>>(all);
        public Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default) => Task.FromResult(all.FirstOrDefault(t => t.Id == id));
    }

    private sealed class Devices(Func<DeviceSyncResult, bool>? throwOn = null) : IDeviceRepository
    {
        public ConcurrentBag<DeviceSyncResult> Saved { get; } = [];

        public Task SaveSyncAsync(DeviceSyncResult result, CancellationToken ct = default)
        {
            if (throwOn?.Invoke(result) == true) throw new InvalidOperationException("database down");
            Saved.Add(result);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ManagedDevice>> GetForTenantAsync(Guid tenantId, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ManagedDevice?> GetAsync(Guid tenantId, string deviceId, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<DeviceSyncStatus?> GetSyncStatusAsync(Guid tenantId, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private sealed class Source(Func<Tenant, CancellationToken, Task<DeviceSyncResult>> sync) : IDeviceInventorySource
    {
        public ConcurrentBag<Guid> Called { get; } = [];
        public string Name => "Intune";

        public Task<DeviceSyncResult> GetDevicesAsync(Tenant tenant, CancellationToken cancellationToken = default)
        {
            Called.Add(tenant.Id);
            return sync(tenant, cancellationToken);
        }
    }

    private static DeviceSyncResult Ok(Tenant t, int devices = 1) => new()
    {
        TenantId = t.Id,
        Source = "Intune",
        StartedAt = DateTimeOffset.UtcNow,
        CompletedAt = DateTimeOffset.UtcNow,
        Devices = Enumerable.Range(1, devices).Select(i => new ManagedDevice
        {
            Id = $"d{i}", TenantId = t.Id, DeviceName = $"PC-{i}", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Compliant
        }).ToList()
    };

    private static DeviceSyncResult Failed(Tenant t, string error) => Ok(t, 0) with { Succeeded = false, Error = error };

    private static DeviceSyncService Service(ITenantRepository tenants, IDeviceRepository devices, IDeviceInventorySource source, int parallel = 2) =>
        new(tenants, devices, source, Options.Create(new DeviceSyncOptions { MaxParallelTenants = parallel }), NullLogger<DeviceSyncService>.Instance);

    [Fact]
    public async Task OnlyOnboardedTenantsAreSynced()
    {
        var a = T("A");
        var b = T("B", TenantConsentState.RemediationGranted);
        var pending = T("Pending", TenantConsentState.Pending);
        var revoked = T("Revoked", TenantConsentState.Revoked);
        var noCert = T("NoCert", credential: null);
        var source = new Source((t, _) => Task.FromResult(Ok(t)));
        var devices = new Devices();

        var summary = await Service(new Tenants(a, b, pending, revoked, noCert), devices, source).SyncAllAsync();

        Assert.Equal(new DeviceSyncSummary(Tenants: 5, Synced: 2, Failed: 0, Skipped: 3), summary);
        Assert.Equal(new[] { a.Id, b.Id }.Order(), source.Called.Order());
        Assert.Equal(new[] { a.Id, b.Id }.Order(), devices.Saved.Select(r => r.TenantId).Order());
    }

    [Fact]
    public async Task FailedSyncs_AreSavedSoTheStatusIsVisible()
    {
        var a = T("A");
        var b = T("B");
        var devices = new Devices();
        var source = new Source((t, _) => Task.FromResult(t == a ? Ok(t) : Failed(t, "Graph returned 403")));

        var summary = await Service(new Tenants(a, b), devices, source).SyncAllAsync();

        Assert.Equal(1, summary.Synced);
        Assert.Equal(1, summary.Failed);
        var saved = devices.Saved.Single(r => r.TenantId == b.Id);
        Assert.False(saved.Succeeded);
        Assert.Equal("Graph returned 403", saved.Error);
    }

    [Fact]
    public async Task SourceThrowing_IsRecordedAndOtherTenantsContinue()
    {
        var a = T("A");
        var b = T("B");
        var devices = new Devices();
        var source = new Source((t, _) => t == a ? throw new InvalidOperationException("boom") : Task.FromResult(Ok(t)));

        var summary = await Service(new Tenants(a, b), devices, source).SyncAllAsync();

        Assert.Equal(1, summary.Synced);
        Assert.Equal(1, summary.Failed);
        var saved = devices.Saved.Single(r => r.TenantId == a.Id);
        Assert.False(saved.Succeeded);
        Assert.Contains("boom", saved.Error);
        Assert.Empty(saved.Devices);
    }

    [Fact]
    public async Task SaveFailure_CountsAsFailedAndOtherTenantsContinue()
    {
        var a = T("A");
        var b = T("B");
        var devices = new Devices(throwOn: r => r.TenantId == a.Id);
        var source = new Source((t, _) => Task.FromResult(Ok(t)));

        var summary = await Service(new Tenants(a, b), devices, source).SyncAllAsync();

        Assert.Equal(1, summary.Synced);
        Assert.Equal(1, summary.Failed);
        Assert.Equal([b.Id], devices.Saved.Select(r => r.TenantId));
    }

    [Fact]
    public async Task RespectsMaxParallelTenants()
    {
        var running = 0;
        var peak = 0;
        var source = new Source(async (t, ct) =>
        {
            var now = Interlocked.Increment(ref running);
            InterlockedMax(ref peak, now);
            await Task.Delay(50, ct);
            Interlocked.Decrement(ref running);
            return Ok(t);
        });
        var tenants = Enumerable.Range(1, 6).Select(i => T($"T{i}")).ToArray();

        var summary = await Service(new Tenants(tenants), new Devices(), source, parallel: 2).SyncAllAsync();

        Assert.Equal(6, summary.Synced);
        Assert.Equal(2, peak);
    }

    [Fact]
    public async Task Cancellation_StopsThePass()
    {
        using var cts = new CancellationTokenSource();
        var source = new Source(async (t, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, ct);
            return Ok(t);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Service(new Tenants(T("A")), new Devices(), source).SyncAllAsync(cts.Token));
    }

    private static void InterlockedMax(ref int target, int value)
    {
        int current;
        while (value > (current = Volatile.Read(ref target)) && Interlocked.CompareExchange(ref target, value, current) != current) { }
    }
}

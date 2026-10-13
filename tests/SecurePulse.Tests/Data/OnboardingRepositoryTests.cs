using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Tests.Data;

public class OnboardingRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);

    private IOnboardingRepository Repo => db.Services.GetRequiredService<IOnboardingRepository>();
    private ITenantRepository Tenants => db.Services.GetRequiredService<ITenantRepository>();

    private async Task<OnboardingRequest> AddAsync(Guid? entraTenantId = null, DateTimeOffset? createdAt = null, string? hash = null)
    {
        var created = createdAt ?? DateTimeOffset.UtcNow;
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(), DisplayName = "Contoso Clinic", PrimaryDomain = "contoso.com", PartnerName = "Gulf IT Services",
            Industry = "Healthcare", EntraTenantId = entraTenantId ?? Guid.NewGuid(), Status = OnboardingStatus.AwaitingConsent,
            CreatedAt = created, ExpiresAt = created.AddDays(7), ProtectedState = "protected"
        };
        await Repo.AddAsync(request, hash ?? Guid.NewGuid().ToString("N"));
        return request;
    }

    private static Tenant TenantFor(OnboardingRequest r) => new()
    {
        Id = Guid.NewGuid(), EntraTenantId = r.EntraTenantId, DisplayName = r.DisplayName, PrimaryDomain = r.PrimaryDomain,
        PartnerName = r.PartnerName, Industry = r.Industry, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
        ConsentState = TenantConsentState.ReadOnlyGranted
    };

    [PostgresFact]
    public async Task AddFindAndGet()
    {
        var hash = Guid.NewGuid().ToString("N");
        var request = await AddAsync(hash: hash);

        Assert.Equal(request with { CreatedAt = default, ExpiresAt = default },
            (await Repo.FindByStateHashAsync(hash))! with { CreatedAt = default, ExpiresAt = default });
        Assert.Equal(request.Id, (await Repo.GetAsync(request.Id))!.Id);
        Assert.Null(await Repo.FindByStateHashAsync("nope"));
    }

    [PostgresFact]
    public async Task StateHashIsUnique()
    {
        var hash = Guid.NewGuid().ToString("N");
        await AddAsync(hash: hash);

        await Assert.ThrowsAsync<DbUpdateException>(() => AddAsync(hash: hash));
    }

    [PostgresFact]
    public async Task ConsentCanOnlyBeRecordedOnce()
    {
        var request = await AddAsync();
        var at = DateTimeOffset.UtcNow;

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Repo.MarkConsentReceivedAsync(request.Id, at)));

        Assert.Single(results, r => r);
        var stored = await Repo.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.Verifying, stored!.Status);
        Assert.Equal(at.ToUnixTimeMilliseconds(), stored.ConsentReceivedAt!.Value.ToUnixTimeMilliseconds());
    }

    [PostgresFact]
    public async Task ConsentAfterExpiryIsRefused()
    {
        var request = await AddAsync(createdAt: T0);

        Assert.False(await Repo.MarkConsentReceivedAsync(request.Id, T0.AddDays(7)));
        Assert.Equal(OnboardingStatus.AwaitingConsent, (await Repo.GetAsync(request.Id))!.Status);
    }

    [PostgresFact]
    public async Task VerificationFailures_CountUntilFinal()
    {
        var request = await AddAsync();
        await Repo.MarkConsentReceivedAsync(request.Id, DateTimeOffset.UtcNow);

        await Repo.RecordVerificationFailureAsync(request.Id, "not yet", final: false);
        await Repo.RecordVerificationFailureAsync(request.Id, new string('x', 3000), final: true);
        await Repo.RecordVerificationFailureAsync(request.Id, "ignored once failed", final: false);

        var stored = await Repo.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.Failed, stored!.Status);
        Assert.Equal(2, stored.VerificationAttempts);
        Assert.Equal(2000, stored.LastError!.Length);
        Assert.DoesNotContain(await Repo.GetVerifyingAsync(), r => r.Id == request.Id);
    }

    [PostgresFact]
    public async Task Complete_CreatesTenantAndLinksIt()
    {
        var request = await AddAsync();
        await Repo.MarkConsentReceivedAsync(request.Id, DateTimeOffset.UtcNow);
        var tenant = TenantFor(request);

        var stored = await Repo.CompleteAsync(request.Id, tenant, ["DeviceManagementManagedDevices.Read.All"], T0);

        Assert.Equal(tenant, stored);
        Assert.Equal(tenant, await Tenants.GetAsync(tenant.Id));
        var done = await Repo.GetAsync(request.Id);
        Assert.Equal(OnboardingStatus.Completed, done!.Status);
        Assert.Equal(tenant.Id, done.TenantId);
        Assert.Equal(["DeviceManagementManagedDevices.Read.All"], done.GrantedPermissions);
        Assert.Null(done.ProtectedState);
    }

    [PostgresFact]
    public async Task Complete_ReConsentUpdatesExistingTenantOnly()
    {
        var first = await AddAsync();
        await Repo.MarkConsentReceivedAsync(first.Id, DateTimeOffset.UtcNow);
        var original = await Repo.CompleteAsync(first.Id, TenantFor(first) with { ConsentState = TenantConsentState.RemediationGranted }, [], T0);

        // Renamed in the portal, then re-consented with a new certificate.
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using (var ctx = await factory.CreateDbContextAsync())
        {
            await ctx.Tenants.Where(t => t.Id == original.Id).ExecuteUpdateAsync(s => s.SetProperty(t => t.DisplayName, "Contoso (renamed)"));
        }
        var second = await AddAsync(first.EntraTenantId);
        await Repo.MarkConsentReceivedAsync(second.Id, DateTimeOffset.UtcNow);

        var updated = await Repo.CompleteAsync(second.Id, TenantFor(second) with { CredentialReference = "FEDCBA9876543210FEDCBA9876543210FEDCBA98" }, [], T0);

        Assert.Equal(original.Id, updated.Id);
        Assert.Equal("Contoso (renamed)", updated.DisplayName);
        Assert.Equal("FEDCBA9876543210FEDCBA9876543210FEDCBA98", updated.CredentialReference);
        Assert.Equal(TenantConsentState.RemediationGranted, updated.ConsentState);
        Assert.Single(await Tenants.GetAllAsync(), t => t.EntraTenantId == first.EntraTenantId);
    }

    [PostgresFact]
    public async Task Complete_RequiresVerifyingAndMatchingTenant()
    {
        var awaiting = await AddAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => Repo.CompleteAsync(awaiting.Id, TenantFor(awaiting), [], T0));

        await Repo.MarkConsentReceivedAsync(awaiting.Id, DateTimeOffset.UtcNow);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Repo.CompleteAsync(awaiting.Id, TenantFor(awaiting) with { EntraTenantId = Guid.NewGuid() }, [], T0));
        Assert.Equal(OnboardingStatus.Verifying, (await Repo.GetAsync(awaiting.Id))!.Status);
    }

    [PostgresFact]
    public async Task Cancel_OnlyAffectsOpenRequests()
    {
        var awaiting = await AddAsync();
        var verifying = await AddAsync();
        await Repo.MarkConsentReceivedAsync(verifying.Id, DateTimeOffset.UtcNow);

        await Repo.CancelAsync(awaiting.Id);
        await Repo.CancelAsync(verifying.Id);

        var cancelled = await Repo.GetAsync(awaiting.Id);
        Assert.Equal(OnboardingStatus.Cancelled, cancelled!.Status);
        Assert.Null(cancelled.ProtectedState);
        Assert.Equal(OnboardingStatus.Verifying, (await Repo.GetAsync(verifying.Id))!.Status);
    }

    [PostgresFact]
    public async Task GetOpen_ListsInProgressAndFailedNewestFirst()
    {
        var old = await AddAsync(createdAt: DateTimeOffset.UtcNow.AddDays(-40));
        var a = await AddAsync(createdAt: DateTimeOffset.UtcNow.AddMinutes(-2));
        var b = await AddAsync(createdAt: DateTimeOffset.UtcNow.AddMinutes(-1));
        var cancelled = await AddAsync();
        await Repo.CancelAsync(cancelled.Id);

        var open = (await Repo.GetOpenAsync()).Select(r => r.Id).ToList();

        Assert.True(open.IndexOf(b.Id) < open.IndexOf(a.Id));
        Assert.DoesNotContain(old.Id, open);
        Assert.DoesNotContain(cancelled.Id, open);
    }
}

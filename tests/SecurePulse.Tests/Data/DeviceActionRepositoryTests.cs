using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Tests.Data;

/// <summary>The device action queue and remediation consent against real PostgreSQL. Each test uses its own tenant.</summary>
public class DeviceActionRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 14, 9, 0, 0, TimeSpan.Zero);

    private IDeviceActionRepository Actions => db.Services.GetRequiredService<IDeviceActionRepository>();
    private IOnboardingRepository Onboarding => db.Services.GetRequiredService<IOnboardingRepository>();
    private ITenantRepository Tenants => db.Services.GetRequiredService<ITenantRepository>();

    private async Task<TenantEntity> AddTenantAsync(TenantConsentState consent = TenantConsentState.RemediationGranted)
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        var tenant = new TenantEntity
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Creek Physio", PrimaryDomain = "creek.example", ConsentState = consent,
            CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
            RemediationCredentialReference = consent == TenantConsentState.RemediationGranted ? "FEDCBA9876543210FEDCBA9876543210FEDCBA98" : null
        };
        ctx.Tenants.Add(tenant);
        await ctx.SaveChangesAsync();
        return tenant;
    }

    private static DeviceActionRequest New(Guid tenantId, string? deviceId = null, DeviceAction action = DeviceAction.Sync, DateTimeOffset? at = null) => new()
    {
        Id = Guid.NewGuid(), TenantId = tenantId, DeviceId = deviceId ?? Guid.NewGuid().ToString(), DeviceName = "PC-1", Action = action,
        Reason = "test", Status = DeviceActionStatus.PendingApproval, RequestedAt = at ?? T0, RequestedByUserId = Guid.NewGuid(), RequestedByName = "Req",
        ExpiresAt = (at ?? T0) + DeviceActionPolicy.ApprovalWindow
    };

    [PostgresFact]
    public async Task RoundTripsAndKeepsOneOpenActionPerDevice()
    {
        var tenant = await AddTenantAsync();
        var first = New(tenant.Id);

        var (stored, created) = await Actions.AddAsync(first);
        var (again, createdAgain) = await Actions.AddAsync(New(tenant.Id, first.DeviceId, DeviceAction.Wipe));

        Assert.True(created);
        Assert.False(createdAgain);
        Assert.Equal(first.Id, again.Id);
        Assert.Equal(first, (await Actions.GetAsync(first.Id))!);

        // Once it's finished, the device can have a new one.
        await Actions.CancelAsync(first.Id, "Req", "no longer needed", T0);
        Assert.True((await Actions.AddAsync(New(tenant.Id, first.DeviceId))).Created);
    }

    [PostgresFact]
    public async Task ConcurrentRequestsForOneDeviceCreateExactlyOne()
    {
        var tenant = await AddTenantAsync();
        var device = Guid.NewGuid().ToString();

        var results = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Task.Run(() => Actions.AddAsync(New(tenant.Id, device)))));

        Assert.Single(results, r => r.Created);
        Assert.Single(results.Select(r => r.Request.Id).Distinct());
    }

    [PostgresFact]
    public async Task OnlyOneConcurrentDecisionWins()
    {
        var tenant = await AddTenantAsync();
        var (a, _) = await Actions.AddAsync(New(tenant.Id));

        var decisions = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => Task.Run(() =>
            Actions.DecideAsync(a.Id, approve: i % 2 == 0, Guid.NewGuid(), $"Admin {i}", PortalRole.Owner, null, T0.AddMinutes(1)))));

        var winner = Assert.Single(decisions, d => d is not null)!;
        Assert.Equal(winner.Status, (await Actions.GetAsync(a.Id))!.Status);
        Assert.Equal(PortalRole.Owner, winner.DecidedByRole);
    }

    [PostgresFact]
    public async Task ExpiredOrDecidedRequestsCantBeDecidedAgain()
    {
        var tenant = await AddTenantAsync();
        var (a, _) = await Actions.AddAsync(New(tenant.Id));

        Assert.Null(await Actions.DecideAsync(a.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, a.ExpiresAt));
        Assert.NotNull(await Actions.DecideAsync(a.Id, false, Guid.NewGuid(), "A", PortalRole.Owner, "no", T0));
        Assert.Null(await Actions.DecideAsync(a.Id, true, Guid.NewGuid(), "B", PortalRole.Owner, null, T0));
        Assert.Null(await Actions.CancelAsync(a.Id, "Req", null, T0));
        Assert.Equal(DeviceActionStatus.Rejected, (await Actions.GetAsync(a.Id))!.Status);
    }

    [PostgresFact]
    public async Task ConcurrentClaimersEachGetADifferentApprovedAction()
    {
        var tenant = await AddTenantAsync();
        var approved = new List<Guid>();
        for (var i = 0; i < 5; i++)
        {
            var (a, _) = await Actions.AddAsync(New(tenant.Id));
            await Actions.DecideAsync(a.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, T0.AddSeconds(i));
            approved.Add(a.Id);
        }

        var claims = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => Actions.ClaimNextApprovedAsync(T0.AddMinutes(1)))));

        var claimed = claims.Where(c => c is not null && c.TenantId == tenant.Id).Select(c => c!.Id).ToList();
        Assert.Equal(approved.Order(), claimed.Order());
        Assert.All(claims.Where(c => c is not null), c => Assert.Equal(DeviceActionStatus.Sending, c!.Status));

        // Completion only applies to a Sending action, once.
        await Actions.CompleteAsync(approved[0], true, null, T0.AddMinutes(2));
        await Actions.CompleteAsync(approved[0], false, "late", T0.AddMinutes(3));
        Assert.Equal(DeviceActionStatus.Sent, (await Actions.GetAsync(approved[0]))!.Status);
        Assert.Null(await Actions.CancelAsync(approved[1], "Req", null, T0)); // already sending
    }

    [PostgresFact]
    public async Task ExpiryCoversUnapprovedLateAndStuckActions()
    {
        var tenant = await AddTenantAsync();
        var (pending, _) = await Actions.AddAsync(New(tenant.Id));
        var (late, _) = await Actions.AddAsync(New(tenant.Id));
        await Actions.DecideAsync(late.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, T0);
        var (fresh, _) = await Actions.AddAsync(New(tenant.Id, at: T0.AddHours(23)));

        var now = T0 + DeviceActionPolicy.ApprovalWindow + TimeSpan.FromMinutes(1);
        var changed = await Actions.ExpireAsync(now, DeviceActionPolicy.SendWindow, now - TimeSpan.FromMinutes(10));

        Assert.Equal(new[] { pending.Id, late.Id }.Order(), changed.Where(c => c.TenantId == tenant.Id).Select(c => c.Id).Order());
        Assert.All(changed.Where(c => c.TenantId == tenant.Id), c => Assert.Equal(DeviceActionStatus.Expired, c.Status));
        Assert.Equal(EfDeviceActionRepository.ExpiredPendingMessage, (await Actions.GetAsync(pending.Id))!.Error);
        Assert.Equal(EfDeviceActionRepository.ExpiredApprovedMessage, (await Actions.GetAsync(late.Id))!.Error);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await Actions.GetAsync(fresh.Id))!.Status);

        // A send that started long ago and never finished: failed as unknown, not retried.
        await Actions.DecideAsync(fresh.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, now);
        var claimed = await Actions.ClaimNextApprovedAsync(now);
        Assert.NotNull(claimed);
        var stuck = await Actions.ExpireAsync(now.AddMinutes(30), DeviceActionPolicy.SendWindow, now.AddMinutes(20));
        var failed = Assert.Single(stuck, c => c.Id == claimed!.Id);
        Assert.Equal(DeviceActionStatus.Failed, failed.Status);
        Assert.Equal(EfDeviceActionRepository.StuckSendingMessage, failed.Error);
    }

    [PostgresFact]
    public async Task CancelOpenForTenantLeavesOtherTenantsAndSendingActions()
    {
        var tenant = await AddTenantAsync();
        var other = await AddTenantAsync();
        var (pending, _) = await Actions.AddAsync(New(tenant.Id));
        var (sending, _) = await Actions.AddAsync(New(tenant.Id));
        await Actions.DecideAsync(sending.Id, true, Guid.NewGuid(), "A", PortalRole.Owner, null, T0);
        // Claim only this tenant's: approve-then-claim until we get it.
        while (await Actions.ClaimNextApprovedAsync(T0) is { } c && c.Id != sending.Id) { }
        var (elsewhere, _) = await Actions.AddAsync(New(other.Id));

        var cancelled = await Actions.CancelOpenForTenantAsync(tenant.Id, "Olivia", "Remediation access was turned off.", T0);

        Assert.Equal([pending.Id], cancelled.Select(c => c.Id));
        Assert.Equal("Remediation access was turned off.", (await Actions.GetAsync(pending.Id))!.Error);
        Assert.Equal(DeviceActionStatus.Sending, (await Actions.GetAsync(sending.Id))!.Status);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await Actions.GetAsync(elsewhere.Id))!.Status);
        Assert.Single(await Actions.QueryAsync(new DeviceActionQuery { TenantId = tenant.Id, OpenOnly = true }));
    }

    [PostgresFact]
    public async Task RemediationConsentCompletesOnlyForAConnectedTenantAndCanBeTurnedOff()
    {
        var tenant = await AddTenantAsync(TenantConsentState.ReadOnlyGranted);
        async Task<OnboardingRequest> RequestAsync(Guid entraTenantId)
        {
            var r = new OnboardingRequest
            {
                Id = Guid.NewGuid(), Kind = OnboardingKind.Remediation, DisplayName = "Creek Physio", PrimaryDomain = "creek.example",
                EntraTenantId = entraTenantId, Status = OnboardingStatus.AwaitingConsent, CreatedAt = T0, ExpiresAt = T0.AddDays(7)
            };
            await Onboarding.AddAsync(r, Guid.NewGuid().ToString("N"));
            await Onboarding.MarkConsentReceivedAsync(r.Id, T0);
            return r;
        }

        var request = await RequestAsync(tenant.EntraTenantId);
        Assert.Equal(OnboardingKind.Remediation, (await Onboarding.GetAsync(request.Id))!.Kind);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Onboarding.CompleteAsync(request.Id, new Tenant
        {
            Id = Guid.NewGuid(), EntraTenantId = tenant.EntraTenantId, DisplayName = "x", PrimaryDomain = "x", ConsentState = TenantConsentState.ReadOnlyGranted
        }, [], T0)); // a remediation request can't connect a tenant

        var updated = await Onboarding.CompleteRemediationAsync(request.Id, "FEDCBA9876543210FEDCBA9876543210FEDCBA98",
            [RemediationPermissions.PrivilegedOperations], T0);
        Assert.NotNull(updated);
        Assert.True(updated!.CanRemediate);
        Assert.Equal("0123456789ABCDEF0123456789ABCDEF01234567", updated.CredentialReference);
        Assert.True((await Tenants.GetAsync(tenant.Id))!.CanRemediate);

        Assert.Null(await Onboarding.CompleteRemediationAsync((await RequestAsync(Guid.NewGuid())).Id, "FEDCBA9876543210FEDCBA9876543210FEDCBA98", [], T0));

        Assert.True(await Onboarding.DisableRemediationAsync(tenant.Id));
        Assert.False(await Onboarding.DisableRemediationAsync(tenant.Id));
        var off = (await Tenants.GetAsync(tenant.Id))!;
        Assert.Equal((TenantConsentState.ReadOnlyGranted, (string?)null), (off.ConsentState, off.RemediationCredentialReference));
    }
}

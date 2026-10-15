using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Tests.Data;

/// <summary>The configuration change queue, finding playbooks and configuration consent against real PostgreSQL.</summary>
public class ConfigurationChangeRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 9, 0, 0, TimeSpan.Zero);

    private IConfigurationChangeRepository Changes => db.Services.GetRequiredService<IConfigurationChangeRepository>();
    private IFindingPlaybookRepository Playbooks => db.Services.GetRequiredService<IFindingPlaybookRepository>();
    private IOnboardingRepository Onboarding => db.Services.GetRequiredService<IOnboardingRepository>();
    private ITenantRepository Tenants => db.Services.GetRequiredService<ITenantRepository>();

    private async Task<TenantEntity> AddTenantAsync(string? configuration = "ABCDEF0123456789ABCDEF0123456789ABCDEF01")
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        var tenant = new TenantEntity
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Creek Physio", PrimaryDomain = "creek.example",
            ConsentState = TenantConsentState.ReadOnlyGranted, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
            ConfigurationCredentialReference = configuration
        };
        ctx.Tenants.Add(tenant);
        await ctx.SaveChangesAsync();
        return tenant;
    }

    private static ConfigurationChangeRequest New(Guid tenantId, string fixId = "block-legacy-auth", Guid? playbook = null, DateTimeOffset? at = null) => new()
    {
        Id = Guid.NewGuid(), TenantId = tenantId, FixId = fixId, CheckId = "MS.AAD.1.1v1", Reason = "failed", Status = DeviceActionStatus.PendingApproval,
        RequestedAt = at ?? T0, RequestedByUserId = Guid.NewGuid(), RequestedByName = "Adam", ExpiresAt = (at ?? T0).AddDays(3), PlaybookId = playbook
    };

    [PostgresFact]
    public async Task OneOpenChangePerTenantAndFix_ThroughTheWholeLifecycle()
    {
        var tenant = await AddTenantAsync();
        var first = New(tenant.Id);
        Assert.True((await Changes.AddAsync(first)).Created);
        var (same, created) = await Changes.AddAsync(New(tenant.Id));
        Assert.False(created);
        Assert.Equal(first.Id, same.Id);
        Assert.True((await Changes.AddAsync(New(tenant.Id, "mfa-all-users"))).Created); // another fix is fine
        Assert.Equal(first, await Changes.GetAsync(first.Id));

        var owner = Guid.NewGuid();
        var approved = (await Changes.DecideAsync(first.Id, true, owner, "Omar", PortalRole.Owner, "ok", T0.AddMinutes(1)))!;
        Assert.Equal((DeviceActionStatus.Approved, owner), (approved.Status, approved.DecidedByUserId!.Value));
        Assert.Null(await Changes.DecideAsync(first.Id, false, owner, "Omar", PortalRole.Owner, null, T0.AddMinutes(2))); // decided once

        // Claims are one at a time; only Approved ones.
        ConfigurationChangeRequest? claimed;
        while ((claimed = await Changes.ClaimNextApprovedAsync(T0.AddMinutes(3))) is not null && claimed.Id != first.Id)
            await Changes.CompleteAsync(claimed.Id, false, "other test", null, T0.AddMinutes(3));
        Assert.NotNull(claimed);
        Assert.Equal(DeviceActionStatus.Sending, claimed!.Status);
        await Changes.CompleteAsync(first.Id, true, null, "policy-42", T0.AddMinutes(4));
        var done = (await Changes.GetAsync(first.Id))!;
        Assert.Equal((DeviceActionStatus.Sent, "policy-42"), (done.Status, done.PolicyId));

        Assert.True((await Changes.AddAsync(New(tenant.Id))).Created); // finished, so a new one may open
    }

    [PostgresFact]
    public async Task ExpiryCancellationAndCooldownLookup()
    {
        var tenant = await AddTenantAsync();
        var playbook = Guid.NewGuid();
        var old = New(tenant.Id, playbook: playbook, at: T0.AddDays(-10));
        await Changes.AddAsync(old);
        var expired = await Changes.ExpireAsync(T0, TimeSpan.FromHours(1), T0.AddMinutes(-10));
        Assert.Contains(expired, c => c.Id == old.Id && c.Status == DeviceActionStatus.Expired);

        Assert.False(await Changes.HasPlaybookProposalSinceAsync(playbook, tenant.Id, T0.AddDays(-7)));
        Assert.True(await Changes.HasPlaybookProposalSinceAsync(playbook, tenant.Id, T0.AddDays(-11)));
        Assert.False(await Changes.HasPlaybookProposalSinceAsync(playbook, Guid.NewGuid(), T0.AddDays(-11)));

        var open = New(tenant.Id, "mfa-all-users");
        await Changes.AddAsync(open);
        var cancelled = await Changes.CancelOpenForTenantAsync(tenant.Id, "Olivia", "turned off", T0);
        Assert.Equal([open.Id], cancelled.Select(c => c.Id));
        Assert.Equal(DeviceActionStatus.Cancelled, (await Changes.GetAsync(open.Id))!.Status);
    }

    [PostgresFact]
    public async Task FindingPlaybooksRoundTrip_WithVersionedUpdates()
    {
        var tenant = await AddTenantAsync();
        var p = new FindingPlaybook
        {
            Id = Guid.NewGuid(), FixId = "block-legacy-auth", Enabled = true, TenantId = tenant.Id, CreatedAt = T0, UpdatedAt = T0,
            UpdatedByUserId = Guid.NewGuid(), UpdatedByName = "Olivia"
        };
        await Playbooks.AddAsync(p);
        Assert.Equal(p, await Playbooks.GetAsync(p.Id));
        Assert.True(await Playbooks.UpdateAsync(p with { Enabled = false, UpdatedAt = T0.AddMinutes(1) }, p.UpdatedAt));
        Assert.False(await Playbooks.UpdateAsync(p with { Enabled = true, UpdatedAt = T0.AddMinutes(2) }, p.UpdatedAt));
        Assert.False((await Playbooks.GetAsync(p.Id))!.Enabled);
        await Playbooks.RecordRunAsync(p.Id, T0.AddHours(1));
        Assert.Equal(T0.AddHours(1), (await Playbooks.GetAsync(p.Id))!.LastRunAt);
        Assert.True(await Playbooks.DeleteAsync(p.Id));
        Assert.Null(await Playbooks.GetAsync(p.Id));
    }

    [PostgresFact]
    public async Task ConfigurationConsentSetsOnlyTheConfigurationReference_AndReConsentKeepsIt()
    {
        var tenant = await AddTenantAsync(configuration: null);
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(), Kind = OnboardingKind.Configuration, DisplayName = tenant.DisplayName, PrimaryDomain = tenant.PrimaryDomain,
            EntraTenantId = tenant.EntraTenantId, Status = OnboardingStatus.AwaitingConsent, CreatedAt = T0, ExpiresAt = T0.AddDays(7)
        };
        await Onboarding.AddAsync(request, Guid.NewGuid().ToString("N"));
        await Onboarding.MarkConsentReceivedAsync(request.Id, T0);
        var stored = (await Onboarding.CompleteConfigurationAsync(request.Id, "ABCDEF0123456789ABCDEF0123456789ABCDEF01", [.. ConfigurationPermissions.Required], T0))!;
        Assert.True(stored.CanConfigure);
        Assert.Equal(TenantConsentState.ReadOnlyGranted, stored.ConsentState);
        Assert.Null(stored.RemediationCredentialReference);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Onboarding.CompleteRemediationAsync(request.Id, "x", [], T0)); // wrong kind / spent

        // Assessment re-consent keeps configuration access.
        var again = new OnboardingRequest
        {
            Id = Guid.NewGuid(), DisplayName = tenant.DisplayName, PrimaryDomain = tenant.PrimaryDomain, EntraTenantId = tenant.EntraTenantId,
            Status = OnboardingStatus.AwaitingConsent, CreatedAt = T0, ExpiresAt = T0.AddDays(7)
        };
        await Onboarding.AddAsync(again, Guid.NewGuid().ToString("N"));
        await Onboarding.MarkConsentReceivedAsync(again.Id, T0);
        var reconsented = await Onboarding.CompleteAsync(again.Id, stored with { Id = Guid.NewGuid(), ConfigurationCredentialReference = null }, [], T0);
        Assert.True(reconsented.CanConfigure);

        Assert.True(await Onboarding.DisableConfigurationAsync(tenant.Id));
        Assert.False(await Onboarding.DisableConfigurationAsync(tenant.Id));
        Assert.False((await Tenants.GetAsync(tenant.Id))!.CanConfigure);
    }
}

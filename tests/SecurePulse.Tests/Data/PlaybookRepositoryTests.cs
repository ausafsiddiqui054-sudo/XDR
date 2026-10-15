using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Tests.Data;

/// <summary>Playbooks and their proposals against real PostgreSQL.</summary>
public class PlaybookRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 15, 9, 0, 0, TimeSpan.Zero);

    private IPlaybookRepository Playbooks => db.Services.GetRequiredService<IPlaybookRepository>();
    private IDeviceActionRepository Actions => db.Services.GetRequiredService<IDeviceActionRepository>();

    private async Task<Guid> AddTenantAsync()
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        var tenant = new TenantEntity
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Creek Physio", PrimaryDomain = "creek.example",
            ConsentState = TenantConsentState.RemediationGranted, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
            RemediationCredentialReference = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
        };
        ctx.Tenants.Add(tenant);
        await ctx.SaveChangesAsync();
        return tenant.Id;
    }

    private static RemediationPlaybook New(Guid? tenantId = null) => new()
    {
        Id = Guid.NewGuid(), Name = "Signatures", Enabled = true, Trigger = PlaybookTrigger.DefenderSignaturesOutOfDate,
        Action = DeviceAction.DefenderUpdateSignatures, TenantId = tenantId, MaxPerRun = 15, Cooldown = TimeSpan.FromHours(12),
        CreatedAt = T0, UpdatedAt = T0, UpdatedByUserId = Guid.NewGuid(), UpdatedByName = "Olivia"
    };

    [PostgresFact]
    public async Task RoundTrips_UpdatesOnlyTheVersionSeen_AndDeletes()
    {
        var p = New(await AddTenantAsync());
        await Playbooks.AddAsync(p);
        Assert.Equal(p, await Playbooks.GetAsync(p.Id));
        Assert.Contains(await Playbooks.GetAllAsync(), x => x.Id == p.Id);

        var changed = p with { Enabled = false, MaxPerRun = 5, UpdatedAt = T0.AddMinutes(1), UpdatedByName = "Omar" };
        Assert.True(await Playbooks.UpdateAsync(changed, p.UpdatedAt));
        Assert.False(await Playbooks.UpdateAsync(p with { UpdatedAt = T0.AddMinutes(2) }, p.UpdatedAt)); // stale version
        Assert.Equal(changed, await Playbooks.GetAsync(p.Id));

        await Playbooks.RecordRunAsync(p.Id, T0.AddHours(1));
        var run = (await Playbooks.GetAsync(p.Id))!;
        Assert.Equal(T0.AddHours(1), run.LastRunAt);
        // The Worker's run time survives an edit.
        Assert.True(await Playbooks.UpdateAsync(run with { Name = "Renamed", UpdatedAt = T0.AddMinutes(3), LastRunAt = null }, run.UpdatedAt));
        Assert.Equal(T0.AddHours(1), (await Playbooks.GetAsync(p.Id))!.LastRunAt);

        Assert.True(await Playbooks.DeleteAsync(p.Id));
        Assert.False(await Playbooks.DeleteAsync(p.Id));
        Assert.Null(await Playbooks.GetAsync(p.Id));
    }

    [PostgresFact]
    public async Task ProposalsKeepThePlaybook_AndTheCooldownQueryFindsThem()
    {
        var tenantId = await AddTenantAsync();
        var p = New(tenantId);
        await Playbooks.AddAsync(p);
        var device = Guid.NewGuid().ToString();
        DeviceActionRequest Proposal(string deviceId, DateTimeOffset at, Guid? playbook) => new()
        {
            Id = Guid.NewGuid(), TenantId = tenantId, DeviceId = deviceId, DeviceName = "PC", Action = DeviceAction.DefenderUpdateSignatures,
            Reason = "Playbook", Status = DeviceActionStatus.PendingApproval, RequestedAt = at, RequestedByUserId = p.UpdatedByUserId,
            RequestedByName = "Olivia (playbook)", ExpiresAt = at.AddDays(1), PlaybookId = playbook
        };

        var recent = Proposal(device, T0, p.Id);
        await Actions.AddAsync(recent);
        Assert.Equal(p.Id, (await Actions.GetAsync(recent.Id))!.PlaybookId);
        await Actions.CancelAsync(recent.Id, "x", "y", T0);
        await Actions.AddAsync(Proposal(Guid.NewGuid().ToString(), T0.AddDays(-3), p.Id)); // too old
        await Actions.AddAsync(Proposal(Guid.NewGuid().ToString(), T0, null));             // manual

        Assert.Equal([device], await Actions.GetPlaybookDevicesSinceAsync(p.Id, tenantId, T0.AddHours(-12)));
        Assert.Empty(await Actions.GetPlaybookDevicesSinceAsync(p.Id, Guid.NewGuid(), T0.AddHours(-12)));
        Assert.Empty(await Actions.GetPlaybookDevicesSinceAsync(Guid.NewGuid(), tenantId, T0.AddHours(-12)));

        // Deleting the playbook keeps its history.
        await Playbooks.DeleteAsync(p.Id);
        Assert.Equal(p.Id, (await Actions.GetAsync(recent.Id))!.PlaybookId);
    }

    [PostgresFact]
    public async Task PreApprovalIsGrantedOnlyForTheVersionSeen_ByAnotherPerson_AndAnEditClearsIt()
    {
        var p = New(await AddTenantAsync());
        await Playbooks.AddAsync(p);
        var owner = Guid.NewGuid();

        Assert.False(await Playbooks.GrantPreApprovalAsync(p.Id, p.UpdatedAt.AddSeconds(1), owner, "Omar", T0, T0.AddDays(90))); // stale version
        Assert.False(await Playbooks.GrantPreApprovalAsync(p.Id, p.UpdatedAt, p.UpdatedByUserId, "Self", T0, T0.AddDays(90)));  // the editor
        Assert.True(await Playbooks.GrantPreApprovalAsync(p.Id, p.UpdatedAt, owner, "Omar", T0, T0.AddDays(90)));
        var granted = (await Playbooks.GetAsync(p.Id))!;
        Assert.Equal((owner, "Omar", T0, T0.AddDays(90)), (granted.PreApprovedByUserId!.Value, granted.PreApprovedByName, granted.PreApprovedAt!.Value, granted.PreApprovalExpiresAt!.Value));
        Assert.Equal(p.UpdatedAt, granted.UpdatedAt);
        Assert.Equal(25, granted.DailyAutoLimit);

        // An edit saves the cleared fields.
        Assert.True(await Playbooks.UpdateAsync(granted with
        {
            UpdatedAt = T0.AddMinutes(1), DailyAutoLimit = 5, PreApprovedByUserId = null, PreApprovedByName = null, PreApprovedAt = null, PreApprovalExpiresAt = null
        }, granted.UpdatedAt));
        var edited = (await Playbooks.GetAsync(p.Id))!;
        Assert.Null(edited.PreApprovedByUserId);
        Assert.Null(edited.PreApprovalExpiresAt);
        Assert.Equal(5, edited.DailyAutoLimit);

        Assert.True(await Playbooks.GrantPreApprovalAsync(p.Id, edited.UpdatedAt, owner, "Omar", T0, T0.AddDays(90)));
        Assert.True(await Playbooks.WithdrawPreApprovalAsync(p.Id));
        Assert.False(await Playbooks.WithdrawPreApprovalAsync(p.Id));
        Assert.Null((await Playbooks.GetAsync(p.Id))!.PreApprovedByName);
    }

    [PostgresFact]
    public async Task AutoApprovalOnlyAppliesToPendingPlaybookRequests_AndIsCounted()
    {
        var tenantId = await AddTenantAsync();
        var p = New(tenantId);
        await Playbooks.AddAsync(p);
        DeviceActionRequest Request(Guid? playbook) => new()
        {
            Id = Guid.NewGuid(), TenantId = tenantId, DeviceId = Guid.NewGuid().ToString(), DeviceName = "PC", Action = DeviceAction.Sync, Reason = "r",
            Status = DeviceActionStatus.PendingApproval, RequestedAt = T0, RequestedByUserId = p.UpdatedByUserId, RequestedByName = "Olivia",
            ExpiresAt = T0.AddDays(1), PlaybookId = playbook
        };
        var fromPlaybook = Request(p.Id);
        var manual = Request(null);
        await Actions.AddAsync(fromPlaybook);
        await Actions.AddAsync(manual);
        var owner = Guid.NewGuid();

        Assert.Null(await Actions.AutoApproveAsync(manual.Id, owner, "Omar", "note", T0)); // never a manual request
        Assert.Null(await Actions.AutoApproveAsync(fromPlaybook.Id, owner, "Omar", "note", T0.AddDays(2))); // expired
        var approved = (await Actions.AutoApproveAsync(fromPlaybook.Id, owner, "Omar (pre-approved playbook)", "note", T0))!;
        Assert.Equal((DeviceActionStatus.Approved, true, owner, PortalRole.Owner, "note"),
            (approved.Status, approved.AutoApproved, approved.DecidedByUserId!.Value, approved.DecidedByRole!.Value, approved.DecisionNote));
        Assert.Null(await Actions.AutoApproveAsync(fromPlaybook.Id, owner, "Omar", "note", T0)); // only once
        await Actions.AddAsync(Request(p.Id)); // a proposal of the same playbook waiting for a person doesn't count

        Assert.Equal(1, await Actions.CountAutoApprovedSinceAsync(p.Id, tenantId, T0.AddHours(-24)));
        Assert.Equal(0, await Actions.CountAutoApprovedSinceAsync(p.Id, tenantId, T0.AddMinutes(1)));
        Assert.Equal(0, await Actions.CountAutoApprovedSinceAsync(p.Id, Guid.NewGuid(), T0.AddHours(-24)));
        Assert.False((await Actions.GetAsync(manual.Id))!.AutoApproved);
    }
}

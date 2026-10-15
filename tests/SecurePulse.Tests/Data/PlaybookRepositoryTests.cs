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
}

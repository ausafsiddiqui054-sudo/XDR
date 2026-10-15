using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Tests.Data;

public class PortalUserRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private IPortalUserRepository Users => db.Services.GetRequiredService<IPortalUserRepository>();

    private async Task<PortalUser> InviteAsync(PortalRole role, Guid? tenant = null, string? upn = null)
    {
        var user = new PortalUser
        {
            Id = Guid.NewGuid(), Role = role, EntraTenantId = tenant ?? Guid.NewGuid(),
            UserPrincipalName = upn ?? $"{Guid.NewGuid():N}@msp.example", CreatedAt = DateTimeOffset.UtcNow, CreatedBy = "test"
        };
        await Users.AddAsync(user);
        return user;
    }

    [PostgresFact]
    public async Task InviteIsStoredLowercaseAndBindsOnFirstSignIn()
    {
        var tid = Guid.NewGuid();
        var invite = await InviteAsync(PortalRole.MspAdmin, tid, "Pat.Smith@MSP.example");
        var oid = Guid.NewGuid();

        var user = await Users.SignInAsync(tid, oid, "pat.smith@msp.example", "Pat Smith", DateTimeOffset.UtcNow);

        Assert.Equal(invite.Id, user!.Id);
        Assert.Equal("pat.smith@msp.example", user.UserPrincipalName);
        Assert.Equal(oid, user.ObjectId);
        Assert.Equal("Pat Smith", user.DisplayName);
        Assert.NotNull(user.LastSignInAt);
        Assert.Equal(invite.Id, (await Users.FindByObjectIdAsync(tid, oid))!.Id);
    }

    [PostgresFact]
    public async Task OtherTenantOrOtherAccountDoesNotBind()
    {
        var tid = Guid.NewGuid();
        await InviteAsync(PortalRole.Owner, tid, "pat@msp.example");

        Assert.Null(await Users.SignInAsync(Guid.NewGuid(), Guid.NewGuid(), "pat@msp.example", null, DateTimeOffset.UtcNow));

        var oid = Guid.NewGuid();
        Assert.NotNull(await Users.SignInAsync(tid, oid, "pat@msp.example", null, DateTimeOffset.UtcNow));
        Assert.Null(await Users.SignInAsync(tid, Guid.NewGuid(), "pat@msp.example", null, DateTimeOffset.UtcNow));
        Assert.NotNull(await Users.SignInAsync(tid, oid, "renamed@msp.example", null, DateTimeOffset.UtcNow));
    }

    [PostgresFact]
    public async Task ConcurrentFirstSignInsBindOnce()
    {
        var tid = Guid.NewGuid();
        var invite = await InviteAsync(PortalRole.MspAdmin, tid, "race@msp.example");
        var oid = Guid.NewGuid();

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Users.SignInAsync(tid, oid, "race@msp.example", null, DateTimeOffset.UtcNow)));

        Assert.All(results, r => Assert.Equal(invite.Id, r?.Id));
    }

    [PostgresFact]
    public async Task RacingFirstSignInsFromDifferentAccountsBindOnlyOne()
    {
        var tid = Guid.NewGuid();
        var invite = await InviteAsync(PortalRole.MspAdmin, tid, "reused@msp.example");
        var accounts = Enumerable.Range(0, 6).Select(_ => Guid.NewGuid()).ToList();

        var results = await Task.WhenAll(accounts.Select(oid => Task.Run(() => Users.SignInAsync(tid, oid, "reused@msp.example", null, DateTimeOffset.UtcNow))));

        var winner = Assert.Single(results, r => r is not null);
        Assert.Equal(invite.Id, winner!.Id);
        // The invitation stays bound to the account that won; later sign-ins by the others are refused.
        Assert.Equal(winner.ObjectId, (await Users.GetAsync(invite.Id))!.ObjectId);
        foreach (var other in accounts.Where(a => a != winner.ObjectId))
            Assert.Null(await Users.SignInAsync(tid, other, "reused@msp.example", null, DateTimeOffset.UtcNow));
    }

    [PostgresFact]
    public async Task DuplicateInvitationThrows()
    {
        var tid = Guid.NewGuid();
        await InviteAsync(PortalRole.MspAdmin, tid, "dup@msp.example");

        await Assert.ThrowsAsync<DuplicatePortalUserException>(() => InviteAsync(PortalRole.Owner, tid, "DUP@msp.example"));
        await InviteAsync(PortalRole.ClientViewer, Guid.NewGuid(), "dup@msp.example"); // same name, other tenant: fine
    }

    [PostgresFact]
    public async Task LastSignedInOwnerIsProtected()
    {
        // Other test classes use their own database, so this class controls every owner here.
        var tid = Guid.NewGuid();
        await InviteAsync(PortalRole.Owner, tid, "owner1@msp.example");
        var first = await Users.SignInAsync(tid, Guid.NewGuid(), "owner1@msp.example", null, DateTimeOffset.UtcNow);
        var pending = await InviteAsync(PortalRole.Owner, tid, "owner2@msp.example");

        foreach (var other in (await Users.GetAllAsync()).Where(u => u.Role == PortalRole.Owner && u.Id != first!.Id && !u.IsInvitationPending))
            await Users.RemoveAsync(other.Id);

        await Assert.ThrowsAsync<LastOwnerException>(() => Users.UpdateRoleAsync(first!.Id, PortalRole.MspAdmin, null));
        await Assert.ThrowsAsync<LastOwnerException>(() => Users.RemoveAsync(first!.Id));
        Assert.Equal(PortalRole.Owner, (await Users.GetAsync(first!.Id))!.Role);

        await Users.RemoveAsync(pending.Id); // a pending invite doesn't count, so removing it is fine
        Assert.Null(await Users.GetAsync(pending.Id));
    }

    [PostgresFact]
    public async Task RoleChangeClearsClientScopeForOperators()
    {
        var tid = Guid.NewGuid();
        await InviteAsync(PortalRole.Owner, tid, "keeper@msp.example");
        await Users.SignInAsync(tid, Guid.NewGuid(), "keeper@msp.example", null, DateTimeOffset.UtcNow);
        var admin = await InviteAsync(PortalRole.MspAdmin, tid);

        await Users.UpdateRoleAsync(admin.Id, PortalRole.Owner, Guid.NewGuid());

        var updated = await Users.GetAsync(admin.Id);
        Assert.Equal(PortalRole.Owner, updated!.Role);
        Assert.Null(updated.ClientTenantId);
    }
}

using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Security;

public class PortalUserServiceTests
{
    private static readonly Guid OperatorTenant = Guid.Parse("0e0e0e0e-1111-2222-3333-444444444444");

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public AuthOptions Auth { get; } = new() { OperatorTenantId = OperatorTenant };
        public FixedUser Actor { get; set; } = FixedUser.Owner();
        public PortalUserService Service => new(Store, Store, Auth, Actor, new FakeTime(DateTimeOffset.UtcNow));
        public IPortalUserRepository Users => Store;

        public async Task<Tenant> ConnectedTenantAsync() =>
            (await Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);

        /// <summary>An Owner who has signed in, so last-owner rules have someone to protect.</summary>
        public async Task<PortalUser> SignedInAsync(PortalRole role, string upn)
        {
            var user = new PortalUser { Id = Guid.NewGuid(), Role = role, EntraTenantId = OperatorTenant, UserPrincipalName = upn, CreatedAt = DateTimeOffset.UtcNow };
            await Users.AddAsync(user);
            return (await Users.SignInAsync(OperatorTenant, Guid.NewGuid(), upn, null, DateTimeOffset.UtcNow))!;
        }
    }

    [Fact]
    public async Task OwnerInvitesOperatorsFromTheOperatorTenant()
    {
        var h = new Harness();

        var result = await h.Service.InviteAsync(new InviteForm { SignInName = "  New.Admin@MSP.example ", Role = PortalRole.MspAdmin });

        Assert.Null(result.Error);
        Assert.Equal(OperatorTenant, result.User!.EntraTenantId);
        Assert.Equal("new.admin@msp.example", result.User.UserPrincipalName);
        Assert.Null(result.User.ClientTenantId);
        Assert.True(result.User.IsInvitationPending);
        Assert.Equal(h.Actor.User.Name, result.User.CreatedBy);
    }

    [Fact]
    public async Task ClientViewersSignInFromTheirClientsTenant()
    {
        var h = new Harness();
        var tenant = await h.ConnectedTenantAsync();

        var result = await h.Service.InviteAsync(new InviteForm { SignInName = "vera@client.example", Role = PortalRole.ClientViewer, ClientTenantId = tenant.Id });

        Assert.Null(result.Error);
        Assert.Equal(tenant.EntraTenantId, result.User!.EntraTenantId);
        Assert.Equal(tenant.Id, result.User.ClientTenantId);
    }

    [Fact]
    public async Task ViewerNeedsAConnectedTenant()
    {
        var h = new Harness();
        var pending = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.Pending);

        Assert.NotNull((await h.Service.InviteAsync(new InviteForm { SignInName = "a@b.example", Role = PortalRole.ClientViewer })).Error);
        Assert.Contains("isn't connected", (await h.Service.InviteAsync(new InviteForm
        {
            SignInName = "a@b.example", Role = PortalRole.ClientViewer, ClientTenantId = pending.Id
        })).Error);
        Assert.NotNull((await h.Service.InviteAsync(new InviteForm
        {
            SignInName = "a@b.example", Role = PortalRole.ClientViewer, ClientTenantId = Guid.NewGuid()
        })).Error);
    }

    [Fact]
    public async Task OperatorInvitesNeedTheOperatorTenantConfigured()
    {
        var h = new Harness();
        h.Auth.OperatorTenantId = Guid.Empty;

        Assert.Contains("OperatorTenantId", (await h.Service.InviteAsync(new InviteForm { SignInName = "a@msp.example", Role = PortalRole.Owner })).Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("no-at-sign")]
    [InlineData("two@@msp.example")]
    [InlineData("a@b@c.example")]
    [InlineData("@msp.example")]
    [InlineData("name@")]
    [InlineData("has space@msp.example")]
    public async Task RejectsInvalidSignInNames(string upn)
    {
        var h = new Harness();

        Assert.Contains("sign-in name", (await h.Service.InviteAsync(new InviteForm { SignInName = upn, Role = PortalRole.MspAdmin })).Error);
        Assert.Empty(await h.Users.GetAllAsync());
    }

    [Fact]
    public async Task DuplicateInvitationIsRejected()
    {
        var h = new Harness();
        await h.Service.InviteAsync(new InviteForm { SignInName = "pat@msp.example", Role = PortalRole.MspAdmin });

        var again = await h.Service.InviteAsync(new InviteForm { SignInName = "PAT@msp.example", Role = PortalRole.Owner });

        Assert.Contains("already", again.Error);
    }

    [Fact]
    public async Task MspAdminsManageOnlyClientViewers()
    {
        var h = new Harness { Actor = FixedUser.MspAdmin() };
        var tenant = await h.ConnectedTenantAsync();

        Assert.Contains("Only Owners", (await h.Service.InviteAsync(new InviteForm { SignInName = "x@msp.example", Role = PortalRole.Owner })).Error);
        Assert.Contains("Only Owners", (await h.Service.InviteAsync(new InviteForm { SignInName = "x@msp.example", Role = PortalRole.MspAdmin })).Error);
        var viewer = await h.Service.InviteAsync(new InviteForm { SignInName = "v@client.example", Role = PortalRole.ClientViewer, ClientTenantId = tenant.Id });
        Assert.Null(viewer.Error);

        var owner = await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        Assert.NotNull(await h.Service.RemoveAsync(owner.Id));
        Assert.Null(await h.Service.RemoveAsync(viewer.User!.Id));
        Assert.Contains("Only Owners", await h.Service.ChangeRoleAsync(owner.Id, PortalRole.MspAdmin));
    }

    [Fact]
    public async Task ClientViewersAndOutsidersManageNobody()
    {
        var h = new Harness();
        var tenant = await h.ConnectedTenantAsync();
        h.Actor = FixedUser.Viewer(tenant.Id);

        Assert.NotNull((await h.Service.InviteAsync(new InviteForm { SignInName = "v@client.example", Role = PortalRole.ClientViewer, ClientTenantId = tenant.Id })).Error);
        Assert.Empty(await h.Service.GetAllAsync());

        h.Actor = FixedUser.Anonymous();
        Assert.Empty(await h.Service.GetAllAsync());
    }

    [Fact]
    public async Task OwnerSwitchesOperatorsBetweenOwnerAndMspAdmin()
    {
        var h = new Harness();
        await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        var admin = await h.SignedInAsync(PortalRole.MspAdmin, "adam@msp.example");

        Assert.Null(await h.Service.ChangeRoleAsync(admin.Id, PortalRole.Owner));
        Assert.Equal(PortalRole.Owner, (await h.Users.GetAsync(admin.Id))!.Role);
    }

    [Fact]
    public async Task ViewersCantBecomeOperatorsOrViceVersa()
    {
        var h = new Harness();
        var tenant = await h.ConnectedTenantAsync();
        await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        var admin = await h.SignedInAsync(PortalRole.MspAdmin, "adam@msp.example");
        var viewer = (await h.Service.InviteAsync(new InviteForm { SignInName = "v@client.example", Role = PortalRole.ClientViewer, ClientTenantId = tenant.Id })).User!;

        Assert.Contains("remove and invite", await h.Service.ChangeRoleAsync(viewer.Id, PortalRole.Owner));
        Assert.Contains("remove and invite", await h.Service.ChangeRoleAsync(admin.Id, PortalRole.ClientViewer));
    }

    [Fact]
    public async Task TheLastSignedInOwnerCantBeRemovedOrDemoted()
    {
        var h = new Harness();
        var owner = await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        await h.Service.InviteAsync(new InviteForm { SignInName = "pending.owner@msp.example", Role = PortalRole.Owner });

        Assert.Contains("At least one Owner", await h.Service.ChangeRoleAsync(owner.Id, PortalRole.MspAdmin));
        Assert.Contains("At least one Owner", await h.Service.RemoveAsync(owner.Id));
        Assert.Equal(PortalRole.Owner, (await h.Users.GetAsync(owner.Id))!.Role);

        var second = await h.SignedInAsync(PortalRole.Owner, "second@msp.example");
        Assert.Null(await h.Service.RemoveAsync(owner.Id));
        Assert.Contains("At least one Owner", await h.Service.RemoveAsync(second.Id));
    }
}

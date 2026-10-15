using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Security;

public class ClaimsTransformationTests
{
    private static readonly Guid Tid = Guid.NewGuid();
    private static readonly Guid Oid = Guid.NewGuid();

    private static ClaimsPrincipal EntraUser(params Claim[] extra) => new(new ClaimsIdentity(
        [new Claim("tid", Tid.ToString()), new Claim("oid", Oid.ToString()), new Claim("preferred_username", "pat@msp.example"), .. extra],
        "AuthenticationTypes.Federation"));

    private static async Task<(SampleDataStore Store, PortalUser User)> StoreWithUserAsync(PortalRole role, Guid? clientTenant = null)
    {
        var store = new SampleDataStore();
        IPortalUserRepository users = store;
        await users.AddAsync(new PortalUser
        {
            Id = Guid.NewGuid(), Role = role, EntraTenantId = Tid, UserPrincipalName = "pat@msp.example",
            ClientTenantId = clientTenant, CreatedAt = DateTimeOffset.UtcNow
        });
        var bound = await users.SignInAsync(Tid, Oid, "pat@msp.example", "Pat", DateTimeOffset.UtcNow);
        return (store, bound!);
    }

    private static PortalClaimsTransformation Transformation(IPortalUserRepository users) => new(users, new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public async Task AddsRoleAndScopeFromTheDatabase()
    {
        var tenant = Guid.NewGuid();
        var (store, user) = await StoreWithUserAsync(PortalRole.ClientViewer, tenant);

        var principal = await Transformation(store).TransformAsync(EntraUser());

        Assert.Equal(PortalRole.ClientViewer, principal.PortalRole());
        Assert.Equal(tenant, principal.ClientTenantId());
        Assert.Equal(user.Id, principal.PortalUserId());
    }

    [Fact]
    public async Task UnknownUserGetsNoRole()
    {
        var principal = await Transformation(new SampleDataStore()).TransformAsync(EntraUser());

        Assert.Null(principal.PortalRole());
        Assert.False(principal.HasPortalRole(PortalRole.Owner, PortalRole.MspAdmin, PortalRole.ClientViewer));
    }

    [Fact]
    public async Task EntraAppRolesFromTheTokenGrantNothing()
    {
        // A client tenant's admin can assign our app's roles in their own tenant; those arrive as claims.
        var principal = await Transformation(new SampleDataStore()).TransformAsync(EntraUser(
            new Claim("roles", "Owner"), new Claim(ClaimTypes.Role, "Owner"), new Claim("role", "MspAdmin")));

        Assert.Null(principal.PortalRole());
        Assert.False(principal.IsInRole("Owner"));
        Assert.DoesNotContain(principal.Claims, c => c.Type is "roles" or "role" or ClaimTypes.Role);
    }

    [Fact]
    public async Task ForgedSecurePulseClaimsOnTheInboundIdentityAreStripped()
    {
        var (store, _) = await StoreWithUserAsync(PortalRole.ClientViewer, Guid.NewGuid());

        var principal = await Transformation(store).TransformAsync(EntraUser(
            new Claim(PortalClaims.Role, "Owner", ClaimValueTypes.String, PortalClaims.Issuer)));

        Assert.Equal(PortalRole.ClientViewer, principal.PortalRole());
        Assert.Single(principal.Claims, c => c.Type == PortalClaims.Role);
    }

    [Fact]
    public void RoleClaimsFromAnyOtherIssuerAreIgnored()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PortalClaims.Role, "Owner", ClaimValueTypes.String, "https://login.microsoftonline.com/x/v2.0")], "test"));

        Assert.Null(principal.PortalRole());
    }

    [Fact]
    public async Task RunningTwiceDoesNotDuplicateClaims()
    {
        var (store, _) = await StoreWithUserAsync(PortalRole.Owner);
        var transformation = Transformation(store);

        var once = await transformation.TransformAsync(EntraUser());
        var twice = await transformation.TransformAsync(once);

        Assert.Single(twice.Claims, c => c.Type == PortalClaims.Role);
    }

    [Fact]
    public async Task AnonymousIsLeftAlone()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Same(anonymous, await Transformation(new SampleDataStore()).TransformAsync(anonymous));
    }

    // --- Session revalidation ------------------------------------------------------------

    [Fact]
    public async Task Revalidation_PassesWhileAccessIsUnchanged()
    {
        var (store, user) = await StoreWithUserAsync(PortalRole.MspAdmin);
        var principal = await Transformation(store).TransformAsync(EntraUser());

        Assert.True(PortalAuthenticationStateProvider.IsStillValid(user, principal));
    }

    [Fact]
    public async Task Revalidation_FailsWhenRemovedOrChanged()
    {
        var (store, user) = await StoreWithUserAsync(PortalRole.MspAdmin);
        var principal = await Transformation(store).TransformAsync(EntraUser());

        Assert.False(PortalAuthenticationStateProvider.IsStillValid(null, principal));
        Assert.False(PortalAuthenticationStateProvider.IsStillValid(user with { Role = PortalRole.ClientViewer, ClientTenantId = Guid.NewGuid() }, principal));
        Assert.False(PortalAuthenticationStateProvider.IsStillValid(user with { Id = Guid.NewGuid() }, principal));
    }

    // --- Return URLs ---------------------------------------------------------------------

    [Theory]
    [InlineData("/endpoints?tenant=1", "/endpoints?tenant=1")]
    [InlineData("/", "/")]
    [InlineData(null, "/")]
    [InlineData("", "/")]
    [InlineData("//evil.example/x", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("https://evil.example", "/")]
    [InlineData("evil", "/")]
    public void ReturnUrlsStayOnSite(string? input, string expected) =>
        Assert.Equal(expected, AuthEndpoints.LocalOrRoot(input));
}

public class SignInBindingTests
{
    private static readonly Guid OperatorTenant = Guid.NewGuid();

    private static async Task<IPortalUserRepository> WithInviteAsync(string upn = "Pat@MSP.example")
    {
        IPortalUserRepository users = new SampleDataStore();
        await users.AddAsync(new PortalUser
        {
            Id = Guid.NewGuid(), Role = PortalRole.MspAdmin, EntraTenantId = OperatorTenant, UserPrincipalName = upn, CreatedAt = DateTimeOffset.UtcNow
        });
        return users;
    }

    [Fact]
    public async Task InvitationBindsOnFirstSignInFromTheRightTenant()
    {
        var users = await WithInviteAsync();
        var oid = Guid.NewGuid();

        var user = await users.SignInAsync(OperatorTenant, oid, "pat@msp.example", "Pat", DateTimeOffset.UtcNow);

        Assert.NotNull(user);
        Assert.Equal(oid, user.ObjectId);
        Assert.Equal("Pat", user.DisplayName);
        Assert.Equal(user.Id, (await users.FindByObjectIdAsync(OperatorTenant, oid))?.Id);
    }

    [Fact]
    public async Task SameSignInNameFromAnotherTenantDoesNotBind()
    {
        var users = await WithInviteAsync();

        Assert.Null(await users.SignInAsync(Guid.NewGuid(), Guid.NewGuid(), "pat@msp.example", "Pat", DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task AfterBindingTheObjectIdDecides()
    {
        var users = await WithInviteAsync();
        var oid = Guid.NewGuid();
        await users.SignInAsync(OperatorTenant, oid, "pat@msp.example", null, DateTimeOffset.UtcNow);

        // Renamed account still gets in; a new account reusing the old name does not.
        Assert.NotNull(await users.SignInAsync(OperatorTenant, oid, "patricia@msp.example", null, DateTimeOffset.UtcNow));
        Assert.Null(await users.SignInAsync(OperatorTenant, Guid.NewGuid(), "pat@msp.example", null, DateTimeOffset.UtcNow));
    }
}

public class TenantScopingTests
{
    private static async Task<(SampleDataStore Store, Tenant Mine, Tenant Other)> StoreAsync()
    {
        var store = new SampleDataStore();
        var connected = (await store.GetAllAsync()).Where(t => t.LastScanAt is not null).ToList();
        return (store, connected[0], connected[1]);
    }

    [Fact]
    public async Task ClientViewerSeesOnlyTheirTenantEverywhere()
    {
        var (store, mine, other) = await StoreAsync();
        var viewer = FixedUser.Viewer(mine.Id);

        var portfolio = await new PostureService(store, store, viewer).GetPortfolioAsync();
        var endpoints = new EndpointService(store, store, store, viewer);
        var fleet = await endpoints.GetFleetAsync();

        Assert.Equal([mine.Id], portfolio.Tenants.Select(t => t.Tenant.Id));
        Assert.All(fleet.Devices, d => Assert.Equal(mine.Id, d.Tenant.Id));
        Assert.NotEmpty(fleet.Devices);
        Assert.All(fleet.Syncs, s => Assert.Equal(mine.Id, s.Tenant.Id));

        var theirDevice = (await ((IDeviceRepository)store).GetForTenantAsync(other.Id))[0];
        Assert.Null(await endpoints.GetDeviceAsync(other.Id, theirDevice.Id));
        var myDevice = (await ((IDeviceRepository)store).GetForTenantAsync(mine.Id))[0];
        Assert.NotNull(await endpoints.GetDeviceAsync(mine.Id, myDevice.Id));
    }

    [Fact]
    public async Task OperatorsSeeEveryTenant()
    {
        var (store, _, _) = await StoreAsync();
        var all = await store.GetAllAsync();

        foreach (var user in new[] { FixedUser.Owner(), FixedUser.MspAdmin() })
            Assert.Equal(all.Count, (await new PostureService(store, store, user).GetPortfolioAsync()).Tenants.Count);
    }

    [Fact]
    public async Task NoRoleSeesNothing()
    {
        var (store, mine, _) = await StoreAsync();
        var anonymous = FixedUser.Anonymous();

        Assert.Empty((await new PostureService(store, store, anonymous).GetPortfolioAsync()).Tenants);
        Assert.Empty((await new EndpointService(store, store, store, anonymous).GetFleetAsync()).Devices);
        var device = (await ((IDeviceRepository)store).GetForTenantAsync(mine.Id))[0];
        Assert.Null(await new EndpointService(store, store, store, anonymous).GetDeviceAsync(mine.Id, device.Id));
    }

    [Fact]
    public void CanSee()
    {
        var mine = Guid.NewGuid();

        Assert.True(FixedUser.Owner().User.CanSee(mine));
        Assert.True(FixedUser.MspAdmin().User.CanSee(mine));
        Assert.True(FixedUser.Viewer(mine).User.CanSee(mine));
        Assert.False(FixedUser.Viewer(mine).User.CanSee(Guid.NewGuid()));
        Assert.False(new UserContext(null, PortalRole.ClientViewer, null, "x").CanSee(mine));
        Assert.False(UserContext.Anonymous.CanSee(mine));
    }
}

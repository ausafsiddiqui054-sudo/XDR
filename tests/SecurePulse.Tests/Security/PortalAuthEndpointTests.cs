using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;

namespace SecurePulse.Tests.Security;

/// <summary>
/// Runs the real portal pipeline (sample data, development sign-in) to check that every page
/// needs a role, public pages stay public, and each persona sees what it should.
/// </summary>
public sealed partial class PortalAuthEndpointTests : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    public sealed class PortalFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:SecurePulse", "");
            builder.UseSetting("AzureAd:ClientId", "");
            builder.UseSetting("Onboarding:AppClientId", "");
        }
    }

    private readonly PortalFactory _factory;

    public PortalAuthEndpointTests(PortalFactory factory) => _factory = factory;

    private HttpClient Client() => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    private async Task<IReadOnlyList<Tenant>> ConnectedTenantsAsync() =>
        (await _factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync())
        .Where(t => t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted).ToList();

    private static async Task<string> TokenAsync(HttpClient client, string page = "/dev/sign-in")
    {
        var html = await client.GetStringAsync(page);
        return AntiforgeryToken().Match(html).Groups[1].Value;
    }

    private async Task<HttpClient> SignInAsync(string persona)
    {
        var client = Client();
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = persona,
            ["returnUrl"] = "/",
            ["__RequestVerificationToken"] = await TokenAsync(client)
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/findings")]
    [InlineData("/endpoints")]
    [InlineData("/tenants")]
    [InlineData("/tenants/connect")]
    [InlineData("/settings/users")]
    public async Task AnonymousVisitorsAreSentToSignIn(string path)
    {
        var response = await Client().GetAsync(path);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/dev/sign-in", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task InteractiveConnectionsNeedSignIn()
    {
        var response = await Client().PostAsync("/_blazor/negotiate?negotiateVersion=1", null);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ConsentPagesArePublic()
    {
        var client = Client();

        var result = await client.GetAsync("/onboarding/consent-result?outcome=Received");
        Assert.Equal(HttpStatusCode.OK, result.StatusCode);
        Assert.Contains("Access granted", await result.Content.ReadAsStringAsync());

        var callback = await client.GetAsync("/onboarding/consent-callback?state=forged&tenant=x&admin_consent=True");
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.EndsWith("/onboarding/consent-result?outcome=Invalid", callback.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("/_content/MudBlazor/MudBlazor.min.css")]
    [InlineData("/_framework/blazor.web.js")]
    public async Task StaticAssetsArePublic(string path) =>
        Assert.Equal(HttpStatusCode.OK, (await Client().GetAsync(path)).StatusCode);

    [Fact]
    public async Task SignInNeedsAnAntiforgeryToken()
    {
        var response = await Client().PostAsync("/authentication/dev-login",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["persona"] = "owner" }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SignOutIsPostOnly()
    {
        var client = await SignInAsync("owner");

        // Neither a GET (e.g. an <img> on another site) nor a token-less POST signs anyone out.
        Assert.False((await client.GetAsync("/authentication/logout")).IsSuccessStatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/authentication/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task OwnerSeesEverything()
    {
        var client = await SignInAsync("owner");

        var home = await client.GetStringAsync("/");
        Assert.Contains("Security posture", home);
        foreach (var t in await ConnectedTenantsAsync())
            Assert.Contains(t.DisplayName, home);
        Assert.Contains("People", await client.GetStringAsync("/settings/users"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/tenants/connect")).StatusCode);
    }

    [Fact]
    public async Task MspAdminCanOnboardAndManagePeople()
    {
        var client = await SignInAsync("msp-admin");

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/tenants/connect")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/settings/users")).StatusCode);
    }

    [Fact]
    public async Task ClientViewerSeesOnlyTheirTenant()
    {
        var tenants = await ConnectedTenantsAsync();
        var mine = tenants[0];
        var client = await SignInAsync($"viewer:{mine.Id}");

        var home = await client.GetStringAsync("/");
        Assert.Contains(mine.DisplayName, home);
        foreach (var notMine in tenants.Skip(1))
            Assert.DoesNotContain(notMine.DisplayName, home);

        foreach (var path in new[] { "/tenants/connect", "/settings/users" })
        {
            var response = await client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Contains("/access-pending", response.Headers.Location!.ToString());
        }

        // A device in someone else's tenant reads as not found, not forbidden.
        var other = tenants[1];
        var theirDevice = (await _factory.Services.GetRequiredService<IDeviceRepository>().GetForTenantAsync(other.Id))[0];
        var detail = await client.GetStringAsync($"/endpoints/{other.Id}/{theirDevice.Id}");
        Assert.Contains("Device not found", detail);
        Assert.DoesNotContain(theirDevice.DeviceName, detail);
    }

    [Fact]
    public async Task PeopleWithoutAccessLandOnAccessPending()
    {
        var client = await SignInAsync("unassigned");

        var response = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/access-pending", response.Headers.Location!.ToString());
        var pending = await client.GetStringAsync("/access-pending");
        Assert.Contains("have access yet", pending);
        Assert.Contains("Organization (tenant) ID", pending);
    }

    [Fact]
    public async Task SigningOutEndsTheSession()
    {
        var client = await SignInAsync("owner");
        var token = await TokenAsync(client, "/access-pending");

        var response = await client.PostAsync("/authentication/logout",
            new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/dev/sign-in", (await client.GetAsync("/")).Headers.Location!.ToString());
    }

    [Fact]
    public void ProductionRefusesToStartWithoutEntra()
    {
        using var production = new PortalFactory().WithWebHostBuilder(b => b.UseEnvironment("Production"));

        var ex = Assert.ThrowsAny<Exception>(() => production.CreateClient());
        Assert.Contains("AzureAd:ClientId", ex.ToString());
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

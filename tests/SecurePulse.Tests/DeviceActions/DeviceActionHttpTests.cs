using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;

namespace SecurePulse.Tests.DeviceActions;

/// <summary>The approvals page through the real pipeline (sample data, development sign-in).</summary>
public sealed partial class DeviceActionHttpTests(PortalAuthEndpointTests.PortalFactory factory) : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    private async Task<HttpClient> SignInAsync(string persona)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var token = AntiforgeryToken().Match(await client.GetStringAsync("/dev/sign-in")).Groups[1].Value;
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = persona, ["returnUrl"] = "/", ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    [Fact]
    public async Task OperatorsSeeTheApprovalsPage()
    {
        var html = await (await SignInAsync("msp-admin")).GetStringAsync("/devices/actions");

        Assert.Contains("Device actions", html);
        Assert.Contains("Waiting for approval", html);
    }

    [Fact]
    public async Task ClientViewersCantOpenTheApprovalsPage()
    {
        var tenant = (await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).First(t => t.CanRemediate);
        var response = await (await SignInAsync($"viewer:{tenant.Id}")).GetAsync("/devices/actions");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/access-pending", response.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("owner", true)]
    [InlineData("msp-admin", false)]
    public async Task OperatorsSeePlaybooks_OnlyOwnersCanCreateThem(string persona, bool canCreate)
    {
        var html = await (await SignInAsync(persona)).GetStringAsync("/devices/playbooks");

        Assert.Contains("Remediation playbooks", html);
        Assert.Contains("Retire and wipe are never automated", html);
        Assert.Equal(canCreate, html.Contains("data-testid=\"new-playbook\""));
    }

    [Fact]
    public async Task OperatorsSeeConfigurationChanges_ViewersDont()
    {
        var html = await (await SignInAsync("msp-admin")).GetStringAsync("/configuration/changes");
        Assert.Contains("Configuration changes", html);
        Assert.Contains("report-only Conditional Access policies", html);

        var tenant = (await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).First();
        var response = await (await SignInAsync($"viewer:{tenant.Id}")).GetAsync("/configuration/changes");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/access-pending", response.Headers.Location!.ToString());

        var playbooks = await (await SignInAsync("owner")).GetStringAsync("/devices/playbooks");
        Assert.Contains("When a check fails", playbooks);
        Assert.Contains("Block legacy authentication", playbooks);
    }

    [Fact]
    public async Task ClientViewersCantOpenPlaybooks()
    {
        var tenant = (await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).First(t => t.CanRemediate);
        var response = await (await SignInAsync($"viewer:{tenant.Id}")).GetAsync("/devices/playbooks");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/access-pending", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task DevicePagesOfARemediationTenantOfferActionsToOperatorsOnly()
    {
        var tenant = (await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).First(t => t.CanRemediate);
        var device = (await factory.Services.GetRequiredService<IDeviceRepository>().GetForTenantAsync(tenant.Id))[0];
        var path = $"/endpoints/{tenant.Id}/{device.Id}";

        var asOperator = await (await SignInAsync("owner")).GetStringAsync(path);
        var asViewer = await (await SignInAsync($"viewer:{tenant.Id}")).GetStringAsync(path);

        Assert.Contains("More actions", asOperator);
        Assert.Contains("Remote actions", asOperator);
        Assert.DoesNotContain("More actions", asViewer);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

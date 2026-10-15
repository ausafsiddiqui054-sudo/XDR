using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Audit;

/// <summary>The Audit log page's Sentinel export line.</summary>
public sealed partial class AuditExportPageTests(PortalAuthEndpointTests.PortalFactory factory) : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    private async Task<string> PageAsync()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var token = AntiforgeryToken().Match(await client.GetStringAsync("/dev/sign-in")).Groups[1].Value;
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = "msp-admin", ["returnUrl"] = "/", ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return WebUtility.HtmlDecode(await client.GetStringAsync("/settings/audit"));
    }

    [Fact]
    public async Task ShowsTheExportOnlyOnceSetUp_AndWarnsWhenItFails()
    {
        var store = factory.Services.GetRequiredService<SampleDataStore>();

        Assert.DoesNotContain("data-testid=\"sentinel-export\"", await PageAsync());

        store.ExportStatus = new AuditExportStatus
        {
            Destination = AuditExportDestinations.Sentinel, ExportedCount = 12_345, Pending = 0,
            LastExportedAt = DateTimeOffset.UtcNow.AddMinutes(-2), LastAttemptAt = DateTimeOffset.UtcNow.AddMinutes(-1)
        };
        var ok = await PageAsync();
        Assert.Contains("Microsoft Sentinel: 12,345 events sent", ok);
        Assert.Contains("Up to date.", ok);

        store.ExportStatus = store.ExportStatus with { Pending = 87, LastError = "Sentinel returned 403 Forbidden. Give the Worker's identity the Monitoring Metrics Publisher role" };
        var failing = await PageAsync();
        Assert.Contains("Sending audit events to Microsoft Sentinel is failing.", failing);
        Assert.Contains("87 events are waiting and are", failing);
        Assert.Contains("Monitoring Metrics Publisher", failing);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

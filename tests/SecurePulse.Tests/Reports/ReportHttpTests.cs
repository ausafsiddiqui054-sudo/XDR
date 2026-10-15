using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Reports;

/// <summary>The download endpoint through the real pipeline (sample data, development sign-in).</summary>
[Collection(QuestPdfCollection.Name)]
public sealed partial class ReportHttpTests(ReportHttpTests.ReportsFactory factory) : IClassFixture<ReportHttpTests.ReportsFactory>
{
    /// <summary>The portal with reports turned on (as a deployment that has chosen its QuestPDF tier would be).</summary>
    public sealed class ReportsFactory : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("ConnectionStrings:SecurePulse", "");
            builder.UseSetting("AzureAd:ClientId", "");
            builder.UseSetting("Onboarding:AppClientId", "");
            builder.UseSetting("Reports:QuestPdfLicense", "Community");
            builder.UseSetting("Reports:TimeZone", "Asia/Dubai");
        }
    }

    private HttpClient Client(WebApplicationFactory<Program>? app = null) =>
        (app ?? factory).CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    private async Task<HttpClient> SignInAsync(string persona, WebApplicationFactory<Program>? app = null)
    {
        var client = Client(app);
        var token = AntiforgeryToken().Match(await client.GetStringAsync("/dev/sign-in")).Groups[1].Value;
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = persona, ["returnUrl"] = "/", ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    private async Task<(Tenant Scanned, Tenant Other, Tenant Unscanned)> TenantsAsync()
    {
        var all = await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync();
        var scanned = all.Where(t => t.LastScanAt is not null).ToList();
        return (scanned[0], scanned[1], all.First(t => t.LastScanAt is null));
    }

    private async Task<int> DownloadsAsync(Guid tenantId) =>
        (await factory.Services.GetRequiredService<IAuditLog>().QueryAsync(new AuditQuery { TenantId = tenantId, Limit = 1000 }))
        .Count(e => e.Action == AuditActions.ReportDownloaded);

    [Fact]
    public async Task OperatorsDownloadABrandedPdfAndItIsAudited()
    {
        var (tenant, _, _) = await TenantsAsync();
        var before = await DownloadsAsync(tenant.Id);
        var client = await SignInAsync("msp-admin");

        var response = await client.GetAsync($"/reports/{tenant.Id}/posture.pdf");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Matches(@"^Security-posture-[a-z0-9-]+-\d{4}-\d{2}-\d{2}\.pdf$", response.Content.Headers.ContentDisposition?.FileName?.Trim('"'));
        var text = ReportPdf.Text(await response.Content.ReadAsByteArrayAsync());
        Assert.Contains(tenant.DisplayName, text);
        Assert.Contains("Fix these first", text);

        Assert.Equal(before + 1, await DownloadsAsync(tenant.Id));
        var e = (await factory.Services.GetRequiredService<IAuditLog>().QueryAsync(new AuditQuery { TenantId = tenant.Id, Limit = 1000 }))
            .First(x => x.Action == AuditActions.ReportDownloaded);
        Assert.Contains("admin@securepulse.dev", e.ActorName);
        Assert.Equal("report", e.Category);
    }

    [Fact]
    public async Task ClientViewersGetTheirOwnReportAndNotFoundForOthers()
    {
        var (own, other, _) = await TenantsAsync();
        var otherBefore = await DownloadsAsync(other.Id);
        var viewer = await SignInAsync($"viewer:{own.Id}");

        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync($"/reports/{own.Id}/posture.pdf")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/reports/{other.Id}/posture.pdf")).StatusCode);
        Assert.Equal(otherBefore, await DownloadsAsync(other.Id));
    }

    [Fact]
    public async Task AnonymousAndPeopleWithoutAccessAreSentToSignIn()
    {
        var (tenant, _, _) = await TenantsAsync();

        var anonymous = await Client().GetAsync($"/reports/{tenant.Id}/posture.pdf");
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        Assert.Contains("/dev/sign-in", anonymous.Headers.Location!.ToString());

        var noAccess = await (await SignInAsync("unassigned")).GetAsync($"/reports/{tenant.Id}/posture.pdf");
        Assert.Equal(HttpStatusCode.Redirect, noAccess.StatusCode);
        Assert.Contains("/access-pending", noAccess.Headers.Location!.ToString());
    }

    [Fact]
    public async Task UnknownAndUnscannedTenants()
    {
        var (_, _, unscanned) = await TenantsAsync();
        var owner = await SignInAsync("owner");

        Assert.Equal(HttpStatusCode.NotFound, (await owner.GetAsync($"/reports/{Guid.NewGuid()}/posture.pdf")).StatusCode);
        var none = await owner.GetAsync($"/reports/{unscanned.Id}/posture.pdf");
        Assert.Equal(HttpStatusCode.Conflict, none.StatusCode);
        Assert.Contains("no scan results", await none.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task WithoutALicenseTierReportsAreOff()
    {
        await using var unlicensed = new PortalAuthEndpointTests.PortalFactory();
        var tenant = (await unlicensed.Services.GetRequiredService<ITenantRepository>().GetAllAsync()).First(t => t.LastScanAt is not null);
        var owner = await SignInAsync("owner", unlicensed);

        var response = await owner.GetAsync($"/reports/{tenant.Id}/posture.pdf");

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("Reports:QuestPdfLicense", await response.Content.ReadAsStringAsync());
        Assert.False(unlicensed.Services.GetRequiredService<ReportSettings>().Enabled);
    }

    [Fact]
    public async Task TenantsPageLinksToTheReport()
    {
        var (tenant, _, _) = await TenantsAsync();
        var html = await (await SignInAsync("owner")).GetStringAsync("/tenants");

        Assert.Contains($"href=\"reports/{tenant.Id}/posture.pdf\"", html);
    }

    [Theory]
    [InlineData("Al Noor Family Clinic", "Security-posture-al-noor-family-clinic-2026-10-14.pdf")]
    [InlineData("Café Zürich / Branch #2", "Security-posture-cafe-zurich-branch-2-2026-10-14.pdf")]
    [InlineData("عيادة النور", "Security-posture-tenant-2026-10-14.pdf")]
    [InlineData("../../etc/passwd", "Security-posture-etc-passwd-2026-10-14.pdf")]
    public void FileNamesAreSafe(string name, string expected) =>
        Assert.Equal(expected, ReportService.FileName(new Tenant
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = name, PrimaryDomain = "x.example", ConsentState = TenantConsentState.ReadOnlyGranted
        }, new DateTimeOffset(2026, 10, 14, 1, 0, 0, TimeSpan.Zero)));

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

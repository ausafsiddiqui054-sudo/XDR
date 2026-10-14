using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Endpoints;

/// <summary>Defender health in the endpoint manager: fleet aggregates, sample data and the pages.</summary>
public sealed partial class DefenderEndpointTests(PortalAuthEndpointTests.PortalFactory factory) : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 14, 8, 0, 0, TimeSpan.Zero);

    private static readonly Tenant Contoso = new()
    {
        Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Contoso Clinic", PrimaryDomain = "contoso.example",
        ConsentState = TenantConsentState.ReadOnlyGranted
    };

    private static DeviceRow Row(string name, DevicePlatform platform, DefenderAntivirusStatus? av, DefenderSensorStatus? sensor)
    {
        var (state, health) = DefenderHealthEvaluator.Evaluate(platform, av, sensor, sensorDataAvailable: true);
        return new DeviceRow(Contoso, new ManagedDevice
        {
            Id = name, TenantId = Contoso.Id, DeviceName = name, Platform = platform, ComplianceState = DeviceComplianceState.Compliant,
            Defender = state, DefenderDetails = health
        });
    }

    [Fact]
    public void FleetCountsStatesAndRanksIssues()
    {
        var av = new DefenderAntivirusStatus { MalwareProtectionEnabled = true, RealTimeProtectionEnabled = true };
        var active = new DefenderSensorStatus { Onboarding = DefenderOnboarding.Onboarded, Health = DefenderSensorHealth.Active };
        var fleet = new EndpointFleet(
        [
            Row("PC-1", DevicePlatform.Windows, av, active),
            Row("PC-2", DevicePlatform.Windows, av with { TamperProtectionEnabled = false }, active),
            Row("PC-3", DevicePlatform.Windows, av with { TamperProtectionEnabled = false, SignaturesOutOfDate = true }, active),
            Row("MAC-1", DevicePlatform.MacOS, null, null),
            new DeviceRow(Contoso, new ManagedDevice { Id = "OLD", TenantId = Contoso.Id, DeviceName = "OLD", Platform = DevicePlatform.Windows, ComplianceState = DeviceComplianceState.Unknown })
        ], T0, []);

        Assert.Equal((1, 2, 1, 1), (fleet.CountDefender(DefenderState.Protected), fleet.CountDefender(DefenderState.Unhealthy),
            fleet.CountDefender(DefenderState.NotOnboarded), fleet.CountDefender(DefenderState.Unknown)));
        Assert.Equal(20, fleet.DefenderProtectedPercent);
        Assert.Equal(
            [("Tamper protection is off.", 2), ("Not onboarded to Defender for Endpoint.", 1), ("Security intelligence (signatures) is out of date.", 1)],
            fleet.TopDefenderIssues());
        Assert.Single(fleet.TopDefenderIssues(take: 1));
        Assert.Equal(0, new EndpointFleet([], T0, []).DefenderProtectedPercent);
    }

    [Fact]
    public void OnlySuccessfulSyncsWithAWarningAreShownAsWarnings()
    {
        var other = Contoso with { Id = Guid.NewGuid(), DisplayName = "Other" };
        var third = Contoso with { Id = Guid.NewGuid(), DisplayName = "Third" };
        var fleet = new EndpointFleet([], T0,
        [
            (Contoso, new DeviceSyncStatus { TenantId = Contoso.Id, LastAttemptAt = T0, Succeeded = true, Warning = "Defender data unavailable" }),
            (other, new DeviceSyncStatus { TenantId = other.Id, LastAttemptAt = T0, Succeeded = false, Error = "403", Warning = "old warning" }),
            (third, new DeviceSyncStatus { TenantId = third.Id, LastAttemptAt = T0, Succeeded = true, Warning = " " })
        ]);

        Assert.Equal([Contoso.Id], fleet.SyncWarnings.Select(w => w.Tenant.Id));
    }

    [Fact]
    public async Task SampleDevicesFollowTheEvaluatorAndShowEveryState()
    {
        var store = new SampleDataStore();
        var devices = new List<ManagedDevice>();
        foreach (var t in await ((ITenantRepository)store).GetAllAsync())
            devices.AddRange(await ((IDeviceRepository)store).GetForTenantAsync(t.Id));

        Assert.All(devices, d =>
        {
            var details = Assert.IsType<DefenderHealth>(d.DefenderDetails);
            var (state, health) = DefenderHealthEvaluator.Evaluate(d.Platform, details.Antivirus, details.Sensor, details.SensorDataAvailable);
            Assert.Equal(state, d.Defender);
            Assert.Equal(health.Issues, details.Issues);
            Assert.Equal(d.Platform == DevicePlatform.Windows, details.Antivirus is not null);
        });
        Assert.All(Enum.GetValues<DefenderState>(), s => Assert.Contains(devices, d => d.Defender == s));
    }

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
    public async Task EndpointsPageShowsTheDefenderOverview()
    {
        var html = await (await SignInAsync("msp-admin")).GetStringAsync("/endpoints");

        Assert.Contains("data-testid=\"defender-overview\"", html);
        Assert.Contains("Most common issues", html);
        Assert.Contains("data-testid=\"defender-tile-NotOnboarded\"", html);
    }

    [Fact]
    public async Task DevicePageShowsDefenderDetailsToClientViewersToo()
    {
        var devices = factory.Services.GetRequiredService<IDeviceRepository>();
        Tenant tenant = null!;
        ManagedDevice device = null!;
        foreach (var t in await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync())
        {
            if ((await devices.GetForTenantAsync(t.Id)).FirstOrDefault(d => d.Defender == DefenderState.Unhealthy) is { } found)
            {
                (tenant, device) = (t, found);
                break;
            }
        }
        Assert.NotNull(device);

        var html = await (await SignInAsync($"viewer:{tenant.Id}")).GetStringAsync($"/endpoints/{tenant.Id}/{device.Id}");

        Assert.Contains("data-testid=\"defender-card\"", html);
        Assert.Contains("Real-time protection", html);
        Assert.Contains("Endpoint detection and response", html);
        Assert.Contains(WebUtility.HtmlEncode(device.DefenderDetails!.Issues[0]), html);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

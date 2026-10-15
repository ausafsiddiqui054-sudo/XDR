using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;

namespace SecurePulse.Tests.Audit;

/// <summary>The Audit log page's retention notice, from the last <see cref="AuditActions.AuditPurged"/> entry.</summary>
public sealed partial class AuditRetentionPageTests(PortalAuthEndpointTests.PortalFactory factory) : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    private async Task<string> PageAsync()
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var token = AntiforgeryToken().Match(await client.GetStringAsync("/dev/sign-in")).Groups[1].Value;
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = "owner", ["returnUrl"] = "/", ["__RequestVerificationToken"] = token
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var html = await client.GetStringAsync("/settings/audit");
        return WebUtility.HtmlDecode(Regex.Replace(Regex.Match(html, "data-testid=\"retention\".*?</div>\\s*</div>", RegexOptions.Singleline).Value, "<[^>]+>", " "));
    }

    private Task RecordAsync(AuditOutcome outcome, string summary, DateTimeOffset at, string deleted) =>
        factory.Services.GetRequiredService<IAuditLog>().RecordAsync(new AuditEvent
        {
            Id = Guid.NewGuid(), OccurredAt = at, Action = AuditActions.AuditPurged, Outcome = outcome, ActorName = "SecurePulse Worker",
            TargetType = "AuditLog", Summary = summary,
            Details = new Dictionary<string, string>
            {
                ["cutoff"] = "2025-10-15T03:00:00.0000000+00:00", ["retainForDays"] = "365", ["due"] = "1234", ["deleted"] = deleted
            }
        });

    [Fact]
    public async Task ShowsWhetherAndHowOldEventsAreRemoved()
    {
        Assert.Contains("No audit events have been removed", await PageAsync());

        await RecordAsync(AuditOutcome.Success, "Removed 1,234 audit events older than 2025-10-15", DateTimeOffset.UtcNow.AddHours(-3), "1234");
        var success = await PageAsync();
        Assert.Contains("events older than 365 days are removed", success);
        Assert.Contains("removed 1,234 events from before", success);
        Assert.Contains("Oct 2025", success);

        await RecordAsync(AuditOutcome.Failure, "Removed 10 of 1,234 audit events older than 2025-10-15, then failed: connection reset",
            DateTimeOffset.UtcNow.AddHours(-1), "10");
        var failed = await PageAsync();
        Assert.Contains("The last retention run didn't finish", failed);
        Assert.Contains("connection reset", failed);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

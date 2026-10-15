using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Security;

namespace SecurePulse.Tests.Audit;

/// <summary>Sign-in, sign-out and export events through the real pipeline (sample data, development sign-in).</summary>
public sealed partial class AuditHttpTests(PortalAuthEndpointTests.PortalFactory factory) : IClassFixture<PortalAuthEndpointTests.PortalFactory>
{
    private IAuditLog Log => factory.Services.GetRequiredService<IAuditLog>();

    private HttpClient Client() => factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });

    private static async Task<string> TokenAsync(HttpClient client, string page) =>
        AntiforgeryToken().Match(await client.GetStringAsync(page)).Groups[1].Value;

    private async Task<HttpClient> SignInAsync(string persona)
    {
        var client = Client();
        var response = await client.PostAsync("/authentication/dev-login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["persona"] = persona, ["returnUrl"] = "/", ["__RequestVerificationToken"] = await TokenAsync(client, "/dev/sign-in")
        }));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    private async Task<List<AuditEvent>> EventsAsync(string action, string actorContains) =>
        (await Log.QueryAsync(new AuditQuery { Limit = 1000 })).Where(e => e.Action == action && e.ActorName.Contains(actorContains)).ToList();

    [Fact]
    public async Task SignInsAreAudited()
    {
        await SignInAsync("msp-admin");
        await SignInAsync("msp-admin");

        var signIns = await EventsAsync(AuditActions.SignIn, "admin@securepulse.dev");
        Assert.True(signIns.Count >= 2);
        Assert.All(signIns, e =>
        {
            Assert.Equal(AuditOutcome.Success, e.Outcome);
            Assert.Equal("MspAdmin", e.Details["role"]);
            Assert.NotNull(e.ActorUserId);
            // No IP assertion: the in-memory test server has no remote address (checked against Kestrel instead).
        });
        // The invitation is accepted only once, on the first sign-in.
        Assert.Single(await EventsAsync(AuditActions.InvitationAccepted, "admin@securepulse.dev"));
    }

    [Fact]
    public async Task SignInWithoutAccessIsAuditedAsDenied()
    {
        await SignInAsync("unassigned");

        var e = (await EventsAsync(AuditActions.SignIn, "nobody@elsewhere.dev")).First();
        Assert.Equal(AuditOutcome.Denied, e.Outcome);
        Assert.Null(e.ActorUserId);
        Assert.True(e.Details.ContainsKey("entraTenantId"));
        Assert.True(e.Details.ContainsKey("objectId"));
    }

    [Fact]
    public async Task SignOutIsAudited()
    {
        var client = await SignInAsync("owner");
        var before = (await EventsAsync(AuditActions.SignOut, "owner@securepulse.dev")).Count;

        await client.PostAsync("/authentication/logout", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = await TokenAsync(client, "/access-pending")
        }));

        Assert.Equal(before + 1, (await EventsAsync(AuditActions.SignOut, "owner@securepulse.dev")).Count);
    }

    [Fact]
    public async Task OperatorsCanExportCsvAndTheExportIsAudited()
    {
        var client = await SignInAsync("owner");

        var response = await client.GetAsync("/settings/audit/export.csv?period=all&category=auth");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/csv", response.Content.Headers.ContentType?.MediaType);
        var bytes = await response.Content.ReadAsByteArrayAsync();
        Assert.Equal(Encoding.UTF8.GetPreamble(), bytes.Take(3));
        var text = Encoding.UTF8.GetString(bytes[3..]);
        Assert.EndsWith("\r\n", text);
        var lines = text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("\"OccurredAtUtc\",\"Action\"", lines[0]);
        Assert.Contains(lines.Skip(1), l => l.Contains("\"auth.sign-in\""));
        Assert.DoesNotContain(lines.Skip(1), l => l.Contains("\"people."));

        var exported = (await EventsAsync(AuditActions.AuditExported, "owner@securepulse.dev")).First();
        Assert.Contains("category=auth", exported.Details["filter"]);
    }

    [Fact]
    public async Task ClientViewersAndAnonymousCantSeeTheAuditLog()
    {
        var tenant = (await factory.Services.GetRequiredService<ITenantRepository>().GetAllAsync())
            .First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);
        var viewer = await SignInAsync($"viewer:{tenant.Id}");

        foreach (var path in new[] { "/settings/audit", "/settings/audit/export.csv" })
        {
            var asViewer = await viewer.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, asViewer.StatusCode);
            Assert.Contains("/access-pending", asViewer.Headers.Location!.ToString());

            var anonymous = await Client().GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
            Assert.Contains("/dev/sign-in", anonymous.Headers.Location!.ToString());
        }
    }

    [Fact]
    public async Task AuditPageRendersForOperators()
    {
        var client = await SignInAsync("msp-admin");

        var html = await client.GetStringAsync("/settings/audit");

        Assert.Contains("Audit log", html);
        Assert.Contains("Sign-in", html);
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Engines.GoPhish;
using SecurePulse.Engines.Http;
using SecurePulse.Tests.Onboarding;

namespace SecurePulse.Tests.Scans;

public class GoPhishOptionsTests
{
    private static GoPhishOptions Valid() => new() { Url = "https://gophish.msp.example:3333" };

    [Fact]
    public void TheDefaults_WithAnHttpsUrl_AreFine() => Assert.Empty(Valid().Problems());

    [Theory]
    [InlineData("")]
    [InlineData("http://gophish.msp.example:3333")]
    [InlineData("https://gophish.msp.example:3333/api/")]
    [InlineData("https://user:pw@gophish.msp.example:3333")]
    [InlineData("gophish.msp.example")]
    public void TheUrlMustBeAnHttpsServerAddress(string url)
    {
        var o = Valid();
        o.Url = url;
        Assert.Contains(o.Problems(), p => p.StartsWith("GoPhish:Url"));
    }

    [Fact]
    public void OtherSettingsAreChecked()
    {
        var o = Valid();
        o.CertificateSha256 = "abc";
        o.Timeout = TimeSpan.FromSeconds(30);
        o.Lookback = TimeSpan.FromDays(1);
        o.MaxRetries = -1;
        o.FindingSeverity = (Severity)42;

        var problems = o.Problems();
        Assert.Contains(problems, p => p.StartsWith("GoPhish:CertificateSha256"));
        Assert.Contains(problems, p => p.StartsWith("GoPhish:Timeout"));
        Assert.Contains(problems, p => p.StartsWith("GoPhish:Lookback"));
        Assert.Contains(problems, p => p.StartsWith("GoPhish:MaxRetries"));
        Assert.Contains(problems, p => p.StartsWith("GoPhish:FindingSeverity"));
    }

    [Fact]
    public void GoPhishOnlyAppliesToTenantsWhereItWasTurnedOn_AndIsntAGraphEngine()
    {
        var tenant = GoPhishEngineTests.Tenant(enabled: false);
        Assert.False(ScanEngines.AppliesTo(ScanEngines.GoPhish, tenant));
        Assert.True(ScanEngines.AppliesTo(ScanEngines.GoPhish, tenant with { GoPhishEnabled = true }));
        Assert.False(ScanEngines.AppliesTo(ScanEngines.Wazuh, tenant with { GoPhishEnabled = true }));
        Assert.True(ScanEngines.AppliesTo(ScanEngines.Maester, tenant));
        Assert.False(ScanEngines.UsesGraph(ScanEngines.GoPhish));
        Assert.Contains(ScanEngines.GoPhish, ScanEngines.All);
    }

    [Fact]
    public void EachTenantsKeyHasItsOwnSecretName()
    {
        var id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e");
        Assert.Equal("gophish-api-key-0f8fad5bd9cb469fa16570867728950e", GoPhishSecrets.ApiKeySecretName(id));
        Assert.NotEqual(GoPhishSecrets.ApiKeySecretName(id), GoPhishSecrets.ApiKeySecretName(Guid.NewGuid()));
    }
}

public class ReadOnlyHttpHandlerTests
{
    private sealed class Ok : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public async Task WritesNeverLeaveTheProcess(string method)
    {
        var inner = new Ok();
        using var http = new HttpClient(new ReadOnlyHttpHandler(inner));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            http.SendAsync(new HttpRequestMessage(new HttpMethod(method), "https://gophish.example/api/campaigns/")));
        Assert.Contains("only reads", ex.Message);
        Assert.Equal(0, inner.Calls);
    }

    [Fact]
    public async Task ReadsGoThrough()
    {
        var inner = new Ok();
        using var http = new HttpClient(new ReadOnlyHttpHandler(inner));

        await http.GetAsync("https://gophish.example/api/campaigns/summary");
        await http.SendAsync(new HttpRequestMessage(HttpMethod.Head, "https://gophish.example/api/users/"));
        Assert.Equal(2, inner.Calls);
    }

    [Fact]
    public void TheGoPhishHandlerIsReadOnly() =>
        Assert.IsType<ReadOnlyHttpHandler>(new GoPhishOptions { Url = "https://gophish.example" }.CreateHandler());
}

public class GoPhishEngineTests
{
    private const string Server = "https://gophish.msp.example:3333";
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 9, 0, 0, TimeSpan.Zero);

    public static Tenant Tenant(bool enabled = true) => new()
    {
        Id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), EntraTenantId = Guid.NewGuid(), DisplayName = "Al Noor Family Clinic",
        PrimaryDomain = "alnoor.example", ConsentState = TenantConsentState.ReadOnlyGranted, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
        GoPhishEnabled = enabled
    };

    private sealed class Keys(string key = "tenant-user-key") : IGoPhishApiKeyProvider
    {
        public readonly ConcurrentQueue<Guid> Asked = new();

        public Task<string> GetApiKeyAsync(Guid tenantId, CancellationToken ct)
        {
            Asked.Enqueue(tenantId);
            return Task.FromResult(key);
        }
    }

    public static object Campaign(long id, string name, string status, DateTimeOffset launched, long total, long sent, long opened, long clicked,
        long submitted, long reported, long error = 0, DateTimeOffset? completed = null) => new
    {
        id, name, status, created_date = launched.AddDays(-1), launch_date = launched, send_by_date = DateTimeOffset.MinValue,
        completed_date = completed ?? DateTimeOffset.MinValue,
        stats = new { total, sent, opened, clicked, submitted_data = submitted, email_reported = reported, error }
    };

    /// <summary>A stand-in GoPhish API: one standard user, a few campaigns.</summary>
    private sealed class FakeGoPhish : HttpMessageHandler
    {
        public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();
        public HttpStatusCode UsersStatus { get; set; } = HttpStatusCode.Forbidden;
        public string ValidKey { get; set; } = "tenant-user-key";

        public List<object> Campaigns { get; set; } =
        [
            Campaign(7, "Q3 invoice lure", "Completed", Now.AddDays(-40), total: 80, sent: 78, opened: 50, clicked: 12, submitted: 3, reported: 9, error: 2,
                completed: Now.AddDays(-26)),
            Campaign(5, "Payroll update", "Completed", Now.AddDays(-120), total: 60, sent: 60, opened: 20, clicked: 4, submitted: 0, reported: 25,
                completed: Now.AddDays(-110)),
            Campaign(9, "Shared document", "In progress", Now.AddDays(-2), total: 40, sent: 40, opened: 10, clicked: 2, submitted: 0, reported: 3),
            Campaign(10, "MFA reset", "In progress", Now.AddDays(-1), total: 30, sent: 30, opened: 5, clicked: 2, submitted: 1, reported: 0),
            Campaign(11, "Next month", "Queued", Now.AddDays(10), total: 40, sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0),
            Campaign(12, "Draft", "Created", Now.AddDays(-3), total: 40, sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0),
            Campaign(2, "Last year", "Completed", Now.AddDays(-400), total: 50, sent: 50, opened: 30, clicked: 10, submitted: 5, reported: 1)
        ];

        public Func<HttpRequestMessage, HttpResponseMessage?>? Override { get; set; }

        private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
            new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Enqueue(request);
            if (Override?.Invoke(request) is { } overridden) return Task.FromResult(overridden);
            if (request.Headers.Authorization is not { Scheme: "Bearer" } auth || auth.Parameter != ValidKey)
                return Task.FromResult(Json(new { success = false, message = "Invalid API Key" }, HttpStatusCode.Unauthorized));

            var path = request.RequestUri!.AbsolutePath;
            return Task.FromResult((request.Method.Method, path) switch
            {
                ("HEAD", "/api/users/") => new HttpResponseMessage(UsersStatus),
                ("GET", "/api/campaigns/summary") => Json(new { total = Campaigns.Count, campaigns = Campaigns }),
                _ => Json(new { success = false, message = "Not found" }, HttpStatusCode.NotFound)
            });
        }
    }

    private static (GoPhishEngine Engine, FakeGoPhish Api, Keys Keys) Create(Action<GoPhishOptions>? configure = null, FakeGoPhish? api = null)
    {
        var options = new GoPhishOptions { Url = Server, MaxRetries = 1 };
        configure?.Invoke(options);
        api ??= new FakeGoPhish();
        var keys = new Keys();
        // The real handler chain minus the network: GET/HEAD only.
        var http = new HttpClient(new ReadOnlyHttpHandler(api));
        return (new GoPhishEngine(http, options, keys, new FakeTime(Now), NullLogger<GoPhishEngine>.Instance), api, keys);
    }

    [Fact]
    public async Task ImportsOneFindingPerLaunchedCampaign_FromTheTenantsOwnKey()
    {
        var (engine, api, keys) = Create();

        var result = await engine.RunAsync(Tenant());

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(ScanEngines.GoPhish, result.Source);
        Assert.Equal([Tenant().Id], keys.Asked);
        // Newest first; queued, draft and older-than-a-year campaigns left out.
        Assert.Equal(["campaign:10", "campaign:9", "campaign:7", "campaign:5"], result.Findings.Select(f => f.SourceCheckId));
        Assert.All(result.Findings, f =>
        {
            Assert.Equal(Tenant().Id, f.TenantId);
            Assert.StartsWith("gophish:0f8fad5bd9cb469fa16570867728950e:", f.Id);
            Assert.Equal("Security awareness", f.Category);
            Assert.Equal(Severity.Medium, f.Severity);
            Assert.Equal(Now, f.DetectedAt);
        });

        var q3 = result.Findings.Single(f => f.SourceCheckId == "campaign:7");
        Assert.Equal("Phishing simulation: Q3 invoice lure", q3.Title);
        Assert.Equal(FindingStatus.Failed, q3.Status);
        Assert.Equal("3 of 78 recipients entered data on the landing page (4%). 12 clicked the link (15%), 50 opened the email (64%) " +
                     "and 9 reported it (12%). 2 emails couldn't be sent.", q3.Evidence);
        Assert.Contains("launched 2026-09-05 and completed 2026-09-19", q3.Description);

        Assert.Equal(FindingStatus.Passed, result.Findings.Single(f => f.SourceCheckId == "campaign:5").Status);
        var running = result.Findings.Single(f => f.SourceCheckId == "campaign:9");
        Assert.Equal(FindingStatus.NotEvaluated, running.Status);
        Assert.EndsWith("still running; these are the results so far.", running.Evidence);
        // Someone already entered data: that fails even while the campaign runs.
        Assert.Equal(FindingStatus.Failed, result.Findings.Single(f => f.SourceCheckId == "campaign:10").Status);
    }

    [Fact]
    public async Task OnlyReads_AndNeverAsksForPerRecipientResults()
    {
        var (engine, api, _) = Create();

        await engine.RunAsync(Tenant());

        Assert.Equal(["HEAD /api/users/", "GET /api/campaigns/summary"], api.Requests.Select(r => $"{r.Method} {r.RequestUri!.AbsolutePath}"));
        Assert.All(api.Requests, r =>
        {
            Assert.Equal(Server, r.RequestUri!.GetLeftPart(UriPartial.Authority));
            Assert.Equal("", r.RequestUri.Query); // the key goes in a header, never the URL
            Assert.Equal("Bearer", r.Headers.Authorization?.Scheme);
        });
    }

    [Fact]
    public async Task AnAdminsKey_IsRefusedBeforeAnyCampaignIsRead()
    {
        var api = new FakeGoPhish { UsersStatus = HttpStatusCode.OK };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("belongs to a GoPhish admin", result.Error);
        Assert.Contains("gophish-api-key-0f8fad5bd9cb469fa16570867728950e", result.Error);
        Assert.Empty(result.Findings);
        Assert.DoesNotContain(api.Requests, r => r.RequestUri!.AbsolutePath.Contains("campaigns"));
    }

    [Fact]
    public async Task AWrongKey_SaysWhichSecretToFix()
    {
        var api = new FakeGoPhish { ValidKey = "someone-else" };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("rejected the API key in Key Vault secret 'gophish-api-key-0f8fad5bd9cb469fa16570867728950e' (401)", result.Error);
    }

    [Fact]
    public async Task AServerWithoutUserRoles_IsRefused()
    {
        var api = new FakeGoPhish { UsersStatus = HttpStatusCode.NotFound };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("no user roles", result.Error);
    }

    [Fact]
    public async Task NoRecentCampaigns_IsAFailure_NotAnEmptySuccess()
    {
        var api = new FakeGoPhish { Campaigns = [Campaign(2, "Last year", "Completed", Now.AddDays(-400), 50, 50, 30, 10, 5, 1)] };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("No GoPhish campaigns launched in the last 365 days", result.Error);
    }

    [Fact]
    public async Task OnlyRunningCampaignsWithoutSubmissions_IsAFailure()
    {
        var api = new FakeGoPhish { Campaigns = [Campaign(9, "Shared document", "In progress", Now.AddDays(-2), 40, 40, 10, 2, 0, 3)] };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("has finished yet", result.Error);
    }

    [Fact]
    public async Task TheLookbackAndSeverityComeFromSettings()
    {
        var (engine, _, _) = Create(o => { o.Lookback = TimeSpan.FromDays(500); o.FindingSeverity = Severity.High; });

        var result = await engine.RunAsync(Tenant());

        Assert.Contains(result.Findings, f => f.SourceCheckId == "campaign:2");
        Assert.All(result.Findings, f => Assert.Equal(Severity.High, f.Severity));
    }

    [Fact]
    public async Task ATenantWithoutGoPhish_IsNotImported()
    {
        var (engine, api, keys) = Create();

        var result = await engine.RunAsync(Tenant(enabled: false));

        Assert.False(result.Succeeded);
        Assert.Empty(keys.Asked);
        Assert.Empty(api.Requests);
    }

    [Fact]
    public async Task BusyServer_IsRetried_ThenReportedOnce()
    {
        var api = new FakeGoPhish();
        var busy = 0;
        api.Override = r => r.RequestUri!.AbsolutePath == "/api/campaigns/summary" && busy++ < 1
            ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Headers = { RetryAfter = new(TimeSpan.Zero) } }
            : null;
        var (engine, _, _) = Create(api: api);
        Assert.True((await engine.RunAsync(Tenant())).Succeeded);

        api.Override = r => r.RequestUri!.AbsolutePath == "/api/campaigns/summary"
            ? new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("""{"success":false,"message":"database is locked"}""") }
            : null;
        var failed = await engine.RunAsync(Tenant());
        Assert.False(failed.Succeeded);
        Assert.Equal("GoPhish returned 500 Internal Server Error (database is locked).", failed.Error);
    }

    [Fact]
    public async Task AnUnreachableServer_IsAReadableFailure()
    {
        var api = new FakeGoPhish { Override = _ => throw new HttpRequestException("Connection refused") };
        var (engine, _, _) = Create(api: api);

        var result = await engine.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Equal("Couldn't reach the GoPhish server at gophish.msp.example: Connection refused", result.Error);
    }

    [Fact]
    public async Task AHungServer_TimesOut()
    {
        // A server that never answers: the engine's own timeout ends it.
        var hung = new GoPhishEngine(new HttpClient(new Hung()), new GoPhishOptions { Url = Server, Timeout = TimeSpan.FromMilliseconds(200) },
            new Keys(), new FakeTime(Now), NullLogger<GoPhishEngine>.Instance);

        var result = await hung.RunAsync(Tenant());

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Error);
    }

    private sealed class Hung : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    [Fact]
    public void CampaignNamesAreTidied_AndEmptyDeliveriesArentPasses()
    {
        var campaigns = JsonSerializer.Deserialize<List<GoPhishCampaignSummary>>(JsonSerializer.Serialize(new[]
        {
            Campaign(3, "  Two\n lines  ", "Completed", Now.AddDays(-5), 10, 0, 0, 0, 0, 0, error: 10),
            Campaign(4, new string('x', 400), "Completed", Now.AddDays(-5), 10, 10, 0, 0, 0, 0),
            Campaign(0, "No id", "Completed", Now.AddDays(-5), 10, 10, 0, 0, 0, 0),
            Campaign(6, "No recipients", "Completed", Now.AddDays(-5), 0, 0, 0, 0, 0, 0)
        }), JsonSerializerOptions.Web)!;

        var findings = GoPhishMapper.ToFindings(Guid.NewGuid(), campaigns, Severity.Low, Now.AddDays(-30), Now);

        Assert.Equal(["campaign:3", "campaign:4"], findings.Select(f => f.SourceCheckId));
        Assert.Equal("Phishing simulation: Two lines", findings[0].Title);
        Assert.Equal(FindingStatus.NotEvaluated, findings[0].Status);
        Assert.Equal("No email was delivered (10 of 10 couldn't be sent).", findings[0].Evidence);
        Assert.EndsWith("…", findings[1].Title);
        Assert.True(findings[1].Title.Length < 330);
    }
}

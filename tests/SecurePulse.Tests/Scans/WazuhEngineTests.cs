using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Engines.Wazuh;

namespace SecurePulse.Tests.Scans;

public class WazuhAgentGroupTests
{
    [Theory]
    [InlineData("clinic-a")]
    [InlineData("Creek_Physio.2026")]
    public void ValidGroups(string group) => Assert.Null(WazuhAgentGroups.Problem(group));

    [Theory]
    [InlineData(null, "Enter")]
    [InlineData("  ", "Enter")]
    [InlineData("default", "every unassigned agent")]
    [InlineData("DEFAULT", "every unassigned agent")]
    [InlineData("clinic a", "letters, digits")]
    [InlineData("../etc", "letters, digits")]
    [InlineData(".", "letters, digits")]
    [InlineData("..", "letters, digits")]
    [InlineData("grüppe", "letters, digits")]
    public void InvalidGroups(string? group, string message) => Assert.Contains(message, WazuhAgentGroups.Problem(group));

    [Fact]
    public void TooLong() => Assert.Contains("at most 128", WazuhAgentGroups.Problem(new string('a', 129)));

    [Fact]
    public void WazuhOnlyAppliesToMappedTenants_AndIsntAGraphEngine()
    {
        var tenant = WazuhEngineTests.Tenant(null);

        Assert.False(ScanEngines.AppliesTo(ScanEngines.Wazuh, tenant));
        Assert.True(ScanEngines.AppliesTo(ScanEngines.Wazuh, tenant with { WazuhAgentGroup = "clinic-a" }));
        Assert.True(ScanEngines.AppliesTo(ScanEngines.Maester, tenant));
        Assert.False(ScanEngines.UsesGraph(ScanEngines.Wazuh));
        Assert.True(ScanEngines.UsesGraph(ScanEngines.Maester));
        Assert.True(ScanEngines.UsesGraph(ScanEngines.ScubaGear));
        Assert.Contains(ScanEngines.Wazuh, ScanEngines.All);
    }
}

public class WazuhRbacTests
{
    private static JsonElement Policies(string json) => JsonDocument.Parse(json).RootElement;

    private const string ReadOnly = """
        { "agent:read": { "agent:group:clinic-a": "allow" }, "sca:read": { "agent:id:*": "allow" }, "group:read": { "group:id:*": "allow" },
          "agent:restart": { "agent:id:*": "deny" }, "rbac_mode": "white" }
        """;

    [Fact]
    public void AReadOnlyRoleInWhiteMode_IsAccepted() => Assert.Null(WazuhRbac.Problem(Policies(ReadOnly)));

    [Fact]
    public void BlackMode_IsRefused()
    {
        var problem = WazuhRbac.Problem(Policies(ReadOnly.Replace("\"white\"", "\"black\"")));

        Assert.Contains("'black' mode", problem);
    }

    [Theory]
    [InlineData("agent:restart")]
    [InlineData("active-response:command")]
    [InlineData("agent:delete")]
    public void AnyAllowedNonReadAction_IsRefused(string action)
    {
        var problem = WazuhRbac.Problem(Policies(ReadOnly.Replace("\"rbac_mode\"", $"\"{action}\": {{ \"agent:id:001\": \"allow\" }}, \"rbac_mode\"")
            .Replace("\"agent:restart\": { \"agent:id:*\": \"deny\" },", "")));

        Assert.Contains("can do more than read", problem);
        Assert.Contains(action, problem);
    }

    [Fact]
    public void MissingScaRead_IsNamed()
    {
        var problem = WazuhRbac.Problem(Policies("""{ "agent:read": { "agent:id:*": "allow" }, "sca:read": { "agent:id:*": "deny" }, "rbac_mode": "white" }"""));

        Assert.Equal("The Wazuh user's role doesn't allow sca:read.", problem);
    }

    [Fact]
    public void NotAnObject_IsRefused() => Assert.NotNull(WazuhRbac.Problem(Policies("[]")));
}

public class WazuhOptionsTests
{
    private static WazuhOptions Valid() => new() { Url = "https://wazuh.msp.example:55000", Username = "securepulse-readonly" };

    [Fact]
    public void ValidOptions_HaveNoProblems() => Assert.Empty(Valid().Problems());

    [Theory]
    [InlineData("http://wazuh.msp.example:55000")]
    [InlineData("https://wazuh.msp.example:55000/security")]
    [InlineData("https://user:pw@wazuh.msp.example:55000")]
    [InlineData("")]
    public void TheApiMustBeHttpsWithNoPath(string url)
    {
        var o = Valid();
        o.Url = url;

        Assert.Contains(o.Problems(), p => p.StartsWith("Wazuh:Url"));
    }

    [Theory]
    [InlineData("AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    [InlineData("abcdef", null)]
    [InlineData("zz", null)]
    public void PinsAreNormalized(string pin, string? expected) => Assert.Equal(expected, WazuhOptions.NormalizePin(pin));

    [Fact]
    public void ABadPin_IsAProblem()
    {
        var o = Valid();
        o.CertificateSha256 = "1234";

        Assert.Contains(o.Problems(), p => p.StartsWith("Wazuh:CertificateSha256"));
    }

    [Fact]
    public void ThePinMatchesTheCertificatesSha256()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        using var cert = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=wazuh", rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var pin = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(cert.RawData));

        Assert.True(WazuhOptions.MatchesPin(cert, pin));
        Assert.False(WazuhOptions.MatchesPin(cert, new string('0', 64)));
    }
}

public class WazuhEngineTests
{
    private const string Api = "https://wazuh.msp.example:55000";

    public static Tenant Tenant(string? group) => new()
    {
        Id = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"), EntraTenantId = Guid.NewGuid(), DisplayName = "Al Noor Family Clinic",
        PrimaryDomain = "alnoor.example", ConsentState = TenantConsentState.ReadOnlyGranted, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
        WazuhAgentGroup = group
    };

    private static readonly Tenant Other = Tenant("creek-physio") with { Id = Guid.NewGuid(), DisplayName = "Creek Physio" };

    private sealed class Tenants(params Tenant[] all) : ITenantRepository
    {
        public Task<IReadOnlyList<Tenant>> GetAllAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<Tenant>>(all);
        public Task<Tenant?> GetAsync(Guid id, CancellationToken ct = default) => Task.FromResult(all.FirstOrDefault(t => t.Id == id));
    }

    private sealed class Passwords(Func<string>? get = null) : IWazuhPasswordProvider
    {
        public int Calls;

        public Task<string> GetPasswordAsync(CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult((get ?? (() => "s3cret!"))());
        }
    }

    /// <summary>A stand-in Wazuh server API with agents, SCA policies and checks.</summary>
    private sealed class FakeWazuh : HttpMessageHandler
    {
        public ConcurrentQueue<HttpRequestMessage> Requests { get; } = new();
        public string Rbac { get; set; } = """{ "agent:read": { "agent:group:clinic-a": "allow" }, "sca:read": { "agent:id:*": "allow" }, "rbac_mode": "white" }""";
        public List<object> Agents { get; set; } =
        [
            new { id = "001", name = "ALN-RECEPTION-01", status = "active", group = new[] { "clinic-a" }, os = new { name = "Microsoft Windows 11 Pro", platform = "windows" } },
            new { id = "002", name = "ALN-DOCTOR-02", status = "disconnected", group = new[] { "clinic-a" }, os = new { name = "Microsoft Windows 11 Pro", platform = "windows" } },
            new { id = "003", name = "SHARED-PC", status = "active", group = new[] { "clinic-a", "creek-physio" }, os = new { name = "Ubuntu", platform = "ubuntu" } }
        ];
        public Dictionary<string, List<object>> Checks { get; } = new()
        {
            ["001"] = [Check(26000, "failed"), Check(26001, "passed"), Check(26002, "not applicable")],
            ["002"] = [Check(26000, "passed"), Check(26001, "passed"), Check(26002, "not applicable")],
            ["003"] = [Check(26000, "failed")]
        };
        public Func<HttpRequestMessage, HttpResponseMessage?>? Override { get; set; }
        public int SignIns;

        public static object Check(long id, string result) => new
        {
            id, policy_id = "cis_win11_enterprise", title = $"Ensure setting {id} is configured", description = $"Description {id}.",
            rationale = "Reduces the attack surface.", remediation = $"Set {id} to Enabled.", result,
            references = "http://insecure.example/x, https://www.cisecurity.org/benchmark/microsoft_windows_desktop",
            compliance = new object[]
            {
                new { key = "cis", value = "1.1.1" }, new { key = "pci_dss", value = "8.2.5" }, new { key = "mitre_techniques", value = "T1110" },
                new { key = "iso_27001-2013", value = "A.9.4.3" }
            }
        };

        private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
            new(status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };

        private static object Page(IReadOnlyList<object> all, HttpRequestMessage r)
        {
            var q = System.Web.HttpUtility.ParseQueryString(r.RequestUri!.Query);
            var offset = int.Parse(q["offset"] ?? "0");
            var limit = int.Parse(q["limit"] ?? "500");
            return new { data = new { affected_items = all.Skip(offset).Take(limit), total_affected_items = all.Count, total_failed_items = 0, failed_items = Array.Empty<object>() }, error = 0 };
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            Requests.Enqueue(r);
            if (Override?.Invoke(r) is { } overridden) return Task.FromResult(overridden);
            var path = r.RequestUri!.AbsolutePath;

            if (path == "/security/user/authenticate")
            {
                Interlocked.Increment(ref SignIns);
                return Task.FromResult(r.Method == HttpMethod.Post && r.Headers.Authorization?.Parameter == Convert.ToBase64String(Encoding.UTF8.GetBytes("securepulse-readonly:s3cret!"))
                    ? Json(new { data = new { token = $"jwt-{SignIns}" }, error = 0 })
                    : Json(new { title = "Unauthorized", detail = "Invalid credentials" }, HttpStatusCode.Unauthorized));
            }
            if (r.Headers.Authorization?.Scheme != "Bearer" || !r.Headers.Authorization.Parameter!.StartsWith("jwt-"))
                return Task.FromResult(Json(new { title = "Unauthorized" }, HttpStatusCode.Unauthorized));
            if (r.Method != HttpMethod.Get)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.MethodNotAllowed));

            if (path == "/security/users/me/policies")
                return Task.FromResult(Json(new { data = JsonDocument.Parse(Rbac).RootElement, error = 0 }));
            if (path == "/agents")
                return Task.FromResult(Json(Page(Agents, r)));
            if (path.StartsWith("/sca/") && path.Split('/') is [_, _, var agent])
                return Task.FromResult(Json(Page(Checks.ContainsKey(agent)
                    ? [new { policy_id = "cis_win11_enterprise", name = "CIS Microsoft Windows 11 Enterprise Benchmark", end_scan = "2026-10-14T03:00:00+00:00" }]
                    : [], r)));
            if (path.StartsWith("/sca/") && path.Split('/') is [_, _, var a, "checks", "cis_win11_enterprise"])
                return Task.FromResult(Json(Page(Checks.GetValueOrDefault(a) ?? [], r)));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    private static (WazuhEngine Engine, FakeWazuh Api, Passwords Passwords) Create(FakeWazuh? api = null, Action<WazuhOptions>? configure = null,
        Passwords? passwords = null, params Tenant[] tenants)
    {
        api ??= new FakeWazuh();
        passwords ??= new Passwords();
        var options = new WazuhOptions { Url = Api, Username = "securepulse-readonly", FindingSeverity = Severity.Medium };
        configure?.Invoke(options);
        var engine = new WazuhEngine(new HttpClient(api), options, passwords, new Tenants([Tenant("clinic-a"), Other, .. tenants]), TimeProvider.System,
            NullLogger<WazuhEngine>.Instance);
        return (engine, api, passwords);
    }

    [Fact]
    public async Task ReadsScaForTheTenantsGroup_AndAggregatesPerCheck()
    {
        var (engine, api, _) = Create();

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("Wazuh", result.Source);
        Assert.Equal(3, result.Findings.Count);

        var failed = result.Findings.Single(f => f.SourceCheckId == "cis_win11_enterprise:26000");
        Assert.Equal(FindingStatus.Failed, failed.Status);
        Assert.Equal("wazuh:0f8fad5bd9cb469fa16570867728950e:cis_win11_enterprise:26000", failed.Id);
        Assert.Equal("Failed on 1 of 2 agents: ALN-RECEPTION-01.", failed.Evidence); // SHARED-PC is left out
        Assert.Equal("Ensure setting 26000 is configured", failed.Title);
        Assert.Equal("Description 26000.\n\nWhy it matters: Reduces the attack surface.", failed.Description);
        Assert.Equal("Set 26000 to Enabled.", failed.Remediation);
        Assert.Equal("https://www.cisecurity.org/benchmark/microsoft_windows_desktop", failed.HelpUrl); // the http link is dropped
        Assert.Equal(["CIS 1.1.1", "PCI DSS 8.2.5", "ISO 27001:2013 A.9.4.3"], failed.Frameworks);
        Assert.Equal(Severity.Medium, failed.Severity);
        Assert.Equal("Endpoint hardening", failed.Category);
        Assert.Equal(Tenant("clinic-a").Id, failed.TenantId);

        Assert.Equal(FindingStatus.Passed, result.Findings.Single(f => f.SourceCheckId!.EndsWith(":26001")).Status);
        var notApplicable = result.Findings.Single(f => f.SourceCheckId!.EndsWith(":26002"));
        Assert.Equal(FindingStatus.NotEvaluated, notApplicable.Status);
        Assert.Equal("Not applicable or not checked on 2 agents.", notApplicable.Evidence);

        // Read-only: one sign-in POST, everything else GET, and never the shared agent's results.
        Assert.Single(api.Requests, r => r.Method == HttpMethod.Post);
        Assert.All(api.Requests.Where(r => r.Method != HttpMethod.Post), r => Assert.Equal(HttpMethod.Get, r.Method));
        Assert.DoesNotContain(api.Requests, r => r.RequestUri!.AbsolutePath.StartsWith("/sca/003"));
        Assert.Contains(api.Requests, r => r.RequestUri!.AbsolutePath == "/agents" && r.RequestUri.Query.Contains("group=clinic-a"));
    }

    [Fact]
    public async Task ManyFailingAgents_AreSummarised()
    {
        var api = new FakeWazuh
        {
            Agents = Enumerable.Range(1, 14).Select(i => (object)new { id = $"{i:000}", name = $"PC-{i:00}", status = "active", group = new[] { "clinic-a" } }).ToList()
        };
        api.Checks.Clear();
        for (var i = 1; i <= 14; i++) api.Checks[$"{i:000}"] = [FakeWazuh.Check(1, "failed")];
        var (engine, _, _) = Create(api, o => o.PageSize = 10);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("Failed on 14 of 14 agents: PC-01, PC-02, PC-03, PC-04, PC-05, PC-06, PC-07, PC-08, PC-09, PC-10 and 4 more.",
            Assert.Single(result.Findings).Evidence);
    }

    [Fact]
    public async Task PagesThroughLongCheckLists()
    {
        var api = new FakeWazuh();
        api.Checks["001"] = Enumerable.Range(0, 25).Select(i => FakeWazuh.Check(30000 + i, "passed")).ToList();
        var (engine, _, _) = Create(api, o => o.PageSize = 10);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(25, result.Findings.Count(f => f.SourceCheckId!.Contains(":300")));
        Assert.Equal(3, api.Requests.Count(r => r.RequestUri!.AbsolutePath == "/sca/001/checks/cis_win11_enterprise"));
    }

    [Fact]
    public async Task ARoleThatCanWrite_StopsTheScanBeforeReadingAgents()
    {
        var api = new FakeWazuh { Rbac = """{ "agent:read": { "agent:id:*": "allow" }, "sca:read": { "agent:id:*": "allow" }, "agent:restart": { "agent:id:*": "allow" }, "rbac_mode": "white" }""" };
        var (engine, _, _) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("agent:restart", result.Error);
        Assert.DoesNotContain(api.Requests, r => r.RequestUri!.AbsolutePath == "/agents");
    }

    [Fact]
    public async Task WrongPassword_IsReportedWithWhereToLook()
    {
        var (engine, _, _) = Create(passwords: new Passwords(() => "wrong"));

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("rejected the user 'securepulse-readonly' (401)", result.Error);
        Assert.Contains("Key Vault", result.Error);
    }

    [Fact]
    public async Task AnExpiredToken_SignsInOnceMore()
    {
        var api = new FakeWazuh();
        var expired = 0;
        api.Override = r => r.RequestUri!.AbsolutePath == "/agents" && Interlocked.Increment(ref expired) == 1
            ? new HttpResponseMessage(HttpStatusCode.Unauthorized) : null;
        var (engine, _, passwords) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(2, api.SignIns);
        Assert.Equal(2, passwords.Calls);
    }

    [Fact]
    public async Task ThrottlingIsRetried()
    {
        var api = new FakeWazuh();
        var calls = 0;
        api.Override = r => r.RequestUri!.AbsolutePath == "/sca/001" && Interlocked.Increment(ref calls) == 1
            ? new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero) } }
            : null;
        var (engine, _, _) = Create(api);

        Assert.True((await engine.RunAsync(Tenant("clinic-a"))).Succeeded);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task AnAgentsScaFailing_FailsTheScan_SoStoredFindingsStay()
    {
        var api = new FakeWazuh();
        api.Override = r => r.RequestUri!.AbsolutePath == "/sca/002"
            ? new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("""{"title":"Internal error","detail":"wazuh-db timeout"}""") }
            : null;
        var (engine, _, _) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("Wazuh returned 500", result.Error);
        Assert.Contains("wazuh-db timeout", result.Error);
    }

    [Fact]
    public async Task NoAgentsInTheGroup_IsAFailure()
    {
        var (engine, _, _) = Create(new FakeWazuh { Agents = [] });

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("No agents found in Wazuh group 'clinic-a'", result.Error);
    }

    [Fact]
    public async Task AgentsAlsoInAnotherTenantsGroup_AreNeverRead()
    {
        var api = new FakeWazuh { Agents = [new { id = "003", name = "SHARED-PC", status = "active", group = new[] { "clinic-a", "creek-physio" } }] };
        var (engine, _, _) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("also in another tenant's group", result.Error);
        Assert.DoesNotContain(api.Requests, r => r.RequestUri!.AbsolutePath.StartsWith("/sca/"));
    }

    [Fact]
    public async Task AgentsTheApiReturnsOutsideTheGroup_AreIgnored()
    {
        // Defence in depth: only agents whose own group list names the tenant's group are read.
        var api = new FakeWazuh();
        api.Agents.Add(new { id = "009", name = "OTHER-CLIENT-PC", status = "active", group = new[] { "someone-else" } });
        api.Checks["009"] = [FakeWazuh.Check(26000, "failed")];
        var (engine, _, _) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.DoesNotContain(api.Requests, r => r.RequestUri!.AbsolutePath.StartsWith("/sca/009"));
        Assert.Equal("Failed on 1 of 2 agents: ALN-RECEPTION-01.", result.Findings.Single(f => f.SourceCheckId!.EndsWith(":26000")).Evidence);
    }

    [Fact]
    public async Task NoScaResultsAtAll_IsAFailure()
    {
        var api = new FakeWazuh();
        api.Checks.Clear();
        var (engine, _, _) = Create(api);

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("has SCA results yet", result.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("default")]
    public async Task WithoutAUsableGroup_NothingIsCalled(string? group)
    {
        var (engine, api, passwords) = Create();

        var result = await engine.RunAsync(Tenant(group));

        Assert.False(result.Succeeded);
        Assert.Empty(api.Requests);
        Assert.Equal(0, passwords.Calls);
    }

    [Fact]
    public async Task KeyVaultFailures_AreReported()
    {
        var (engine, api, _) = Create(passwords: new Passwords(() => throw new WazuhException("Couldn't read the Wazuh password from Key Vault (403).")));

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("Key Vault (403)", result.Error);
        Assert.Empty(api.Requests);
    }

    [Fact]
    public async Task ASlowApi_TimesOut()
    {
        var (engine, _, _) = Create(new SlowHandler(), o => o.Timeout = TimeSpan.FromMilliseconds(200));

        var result = await engine.RunAsync(Tenant("clinic-a"));

        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Error);
    }

    private sealed class SlowHandler : FakeWazuhBase;

    private class FakeWazuhBase : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            await Task.Delay(Timeout.Infinite, ct);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private static (WazuhEngine, HttpMessageHandler, Passwords) Create(HttpMessageHandler handler, Action<WazuhOptions> configure)
    {
        var options = new WazuhOptions { Url = Api, Username = "securepulse-readonly" };
        configure(options);
        var passwords = new Passwords();
        return (new WazuhEngine(new HttpClient(handler), options, passwords, new Tenants(Tenant("clinic-a")), TimeProvider.System,
            NullLogger<WazuhEngine>.Instance), handler, passwords);
    }
}

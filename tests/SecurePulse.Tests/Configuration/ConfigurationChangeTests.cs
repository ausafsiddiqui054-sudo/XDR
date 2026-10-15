using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;
using SecurePulse.Tests.DeviceActions;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Configuration;

internal static class ConfigData
{
    public static readonly DateTimeOffset T0 = new(2026, 10, 15, 9, 0, 0, TimeSpan.Zero);
    public const string Thumbprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01";

    /// <summary>Gives a sample tenant configuration access through the real consent-completion path.</summary>
    public static async Task<Tenant> ConfigurableTenantAsync(SampleDataStore store)
    {
        var tenant = (await store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);
        IOnboardingRepository repo = store;
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(), Kind = OnboardingKind.Configuration, DisplayName = tenant.DisplayName, PrimaryDomain = tenant.PrimaryDomain,
            EntraTenantId = tenant.EntraTenantId, Status = OnboardingStatus.AwaitingConsent, CreatedAt = T0, ExpiresAt = T0.AddDays(7)
        };
        await repo.AddAsync(request, Guid.NewGuid().ToString("N"));
        await repo.MarkConsentReceivedAsync(request.Id, T0);
        return (await repo.CompleteConfigurationAsync(request.Id, Thumbprint, [.. ConfigurationPermissions.Required], T0))!;
    }

    public static Finding Failed(Guid tenantId, string checkId, string source = "ScubaGear", FindingStatus status = FindingStatus.Failed) => new()
    {
        Id = $"{source}:{checkId}:{tenantId:N}", TenantId = tenantId, Source = source, SourceCheckId = checkId, Title = $"Check {checkId}",
        Severity = Severity.High, Status = status, DetectedAt = T0
    };

    public static Task SaveFindingsAsync(SampleDataStore store, Guid tenantId, params Finding[] findings) =>
        ((IFindingRepository)store).SaveScanAsync(new ScanResult
        {
            TenantId = tenantId, Source = "ScubaGear", StartedAt = T0, CompletedAt = T0, Findings = findings
        });
}

public class ConfigurationCatalogTests
{
    [Fact]
    public void EveryFixIsAReportOnlyPolicyWithItsOwnName()
    {
        Assert.NotEmpty(ConfigurationFixes.All);
        Assert.Equal(ConfigurationFixes.All.Count, ConfigurationFixes.All.Select(f => f.Id).Distinct().Count());
        Assert.Equal(ConfigurationFixes.All.Sum(f => f.CheckIds.Count), ConfigurationFixes.All.SelectMany(f => f.CheckIds).Distinct().Count());
        foreach (var fix in ConfigurationFixes.All)
        {
            using var doc = JsonDocument.Parse(fix.PolicyJson);
            Assert.Equal("enabledForReportingButNotEnforced", doc.RootElement.GetProperty("state").GetString());
            Assert.Equal(fix.PolicyDisplayName, doc.RootElement.GetProperty("displayName").GetString());
            Assert.StartsWith(ConfigurationFixes.PolicyNamePrefix, fix.PolicyDisplayName);
            Assert.EndsWith("(report-only)", fix.PolicyDisplayName);
            Assert.Null(GraphConditionalAccessWriter.ReportOnlyProblem(fix));
            Assert.NotEmpty(fix.CheckIds);
        }
    }

    [Fact]
    public void ThePoliciesSayWhatTheyClaim()
    {
        using var legacy = JsonDocument.Parse(ConfigurationFixes.BlockLegacyAuth.PolicyJson);
        Assert.Equal(["exchangeActiveSync", "other"], legacy.RootElement.GetProperty("conditions").GetProperty("clientAppTypes").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(["block"], legacy.RootElement.GetProperty("grantControls").GetProperty("builtInControls").EnumerateArray().Select(e => e.GetString()));

        using var admins = JsonDocument.Parse(ConfigurationFixes.PhishingResistantMfaForAdmins.PolicyJson);
        var roles = admins.RootElement.GetProperty("conditions").GetProperty("users").GetProperty("includeRoles").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Equal(8, roles.Count);
        Assert.Contains("62e90394-69f5-4237-9190-012177145e10", roles); // Global Administrator
        Assert.Equal("00000000-0000-0000-0000-000000000004",
            admins.RootElement.GetProperty("grantControls").GetProperty("authenticationStrength").GetProperty("id").GetString());
    }

    [Fact]
    public void FixesAreFoundByCheckId()
    {
        Assert.Same(ConfigurationFixes.BlockLegacyAuth, ConfigurationFixes.ForCheck("ms.aad.1.1v1"));
        Assert.Same(ConfigurationFixes.PhishingResistantMfaForAdmins, ConfigurationFixes.ForCheck("MS.AAD.3.6v1"));
        Assert.Null(ConfigurationFixes.ForCheck("MS.AAD.9.9v9"));
        Assert.Null(ConfigurationFixes.ForCheck(null));
        Assert.Null(ConfigurationFixes.Find("nope"));
    }

    [Fact]
    public void TheConfigurationAppMayHoldOnlyTheConditionalAccessPermissions()
    {
        Assert.Equal(["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess"], ConfigurationPermissions.Required);
        Assert.Empty(ConfigurationPermissions.Unexpected(["policy.read.all", "Policy.ReadWrite.ConditionalAccess"]));
        Assert.Equal(["Policy.ReadWrite.Authorization"], ConfigurationPermissions.Unexpected([.. ConfigurationPermissions.Required, "Policy.ReadWrite.Authorization"]));
        Assert.Equal(["Policy.ReadWrite.ConditionalAccess"], ConfigurationPermissions.MissingFrom(["Policy.Read.All"]));
    }

    [Fact]
    public void OnlyAnotherOwnerApproves()
    {
        var requester = Guid.NewGuid();
        var c = new ConfigurationChangeRequest
        {
            Id = Guid.NewGuid(), TenantId = Guid.NewGuid(), FixId = "block-legacy-auth", Reason = "r", Status = DeviceActionStatus.PendingApproval,
            RequestedAt = ConfigData.T0, RequestedByUserId = requester, RequestedByName = "Req", ExpiresAt = ConfigData.T0.AddDays(3)
        };
        Assert.Null(ConfigurationChangePolicy.WhyCannotApprove(c, Guid.NewGuid(), PortalRole.Owner));
        Assert.Contains("Owner's approval", ConfigurationChangePolicy.WhyCannotApprove(c, Guid.NewGuid(), PortalRole.MspAdmin));
        Assert.Contains("own request", ConfigurationChangePolicy.WhyCannotApprove(c, requester, PortalRole.Owner));
        Assert.NotNull(ConfigurationChangePolicy.WhyCannotApprove(c, null, PortalRole.Owner));
    }

    [Fact]
    public void AFindingPlaybookProposesOnlyForItsFailingCheckInAConfigurableTenant()
    {
        var tenant = new Tenant
        {
            Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Creek", PrimaryDomain = "creek.example",
            ConsentState = TenantConsentState.ReadOnlyGranted, CredentialReference = ConfigData.Thumbprint, ConfigurationCredentialReference = ConfigData.Thumbprint
        };
        var fix = ConfigurationFixes.BlockLegacyAuth;
        var p = new FindingPlaybook
        {
            Id = Guid.NewGuid(), FixId = fix.Id, Enabled = true, CreatedAt = ConfigData.T0, UpdatedAt = ConfigData.T0, UpdatedByUserId = Guid.NewGuid(),
            UpdatedByName = "Olivia"
        };
        var failing = ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1");

        Assert.Equal("Finding playbook \"Block legacy authentication\": ScubaGear MS.AAD.1.1v1 failed (Check MS.AAD.1.1v1).",
            FindingPlaybookRules.Proposal(p, fix, tenant, [failing]));
        Assert.Null(FindingPlaybookRules.Proposal(p, fix, tenant, [failing with { Status = FindingStatus.Passed }]));
        Assert.Null(FindingPlaybookRules.Proposal(p, fix, tenant, [ConfigData.Failed(tenant.Id, "MS.AAD.3.2v1")]));
        Assert.Null(FindingPlaybookRules.Proposal(p, fix, tenant, [failing with { TenantId = Guid.NewGuid() }]));
        Assert.Null(FindingPlaybookRules.Proposal(p with { Enabled = false }, fix, tenant, [failing]));
        Assert.Null(FindingPlaybookRules.Proposal(p with { TenantId = Guid.NewGuid() }, fix, tenant, [failing]));
        Assert.NotNull(FindingPlaybookRules.Proposal(p with { TenantId = tenant.Id }, fix, tenant, [failing]));
        Assert.Null(FindingPlaybookRules.Proposal(p, fix, tenant with { ConfigurationCredentialReference = null }, [failing]));
        Assert.Null(FindingPlaybookRules.Proposal(p, ConfigurationFixes.MfaForAllUsers, tenant, [failing])); // wrong fix for the playbook
    }
}

public class GraphConditionalAccessWriterTests
{
    private sealed class Stub(Func<HttpRequestMessage, string?, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Url, string? Body, string? Auth)> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request.Method, request.RequestUri!.ToString(), body, request.Headers.Authorization?.ToString()));
            return respond(request, body);
        }
    }

    private static HttpResponseMessage Json(object body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(JsonSerializer.Serialize(body), System.Text.Encoding.UTF8, "application/json") };

    private static (GraphConditionalAccessWriter Writer, Stub Stub) Create(Func<HttpRequestMessage, string?, HttpResponseMessage> respond, TimeSpan? timeout = null)
    {
        var stub = new Stub(respond);
        return (new GraphConditionalAccessWriter(new HttpClient(stub), new IntuneOptions { GraphBaseUrl = "https://graph.example/" },
            new ConfigurationOptions { SendTimeout = timeout ?? TimeSpan.FromSeconds(30) }), stub);
    }

    private const string Policies = "https://graph.example/v1.0/identity/conditionalAccess/policies";

    [Fact]
    public async Task CreatesTheCatalogPolicyOnce_WhenItIsntThere()
    {
        var fix = ConfigurationFixes.BlockLegacyAuth;
        var (writer, stub) = Create((r, body) => r.Method == HttpMethod.Get
            ? Json(new { value = new[] { new { id = "p1", displayName = "Someone else's policy" } } })
            : Json(new { id = "new-policy", state = "enabledForReportingButNotEnforced" }, HttpStatusCode.Created));

        var result = await writer.ApplyAsync(fix, "tok");

        Assert.Equal(new ConditionalAccessResult(true, "new-policy", null), result);
        Assert.Equal(2, stub.Calls.Count);
        Assert.Equal((HttpMethod.Get, $"{Policies}?$select=id,displayName"), (stub.Calls[0].Method, stub.Calls[0].Url));
        Assert.Equal((HttpMethod.Post, Policies, fix.PolicyJson, "Bearer tok"), (stub.Calls[1].Method, stub.Calls[1].Url, stub.Calls[1].Body, stub.Calls[1].Auth));
    }

    [Fact]
    public async Task APolicyWithTheSameNameMeansNothingIsCreated_AcrossPages()
    {
        var fix = ConfigurationFixes.MfaForAllUsers;
        var (writer, stub) = Create((r, _) => r.RequestUri!.Query.Contains("skiptoken")
            ? Json(new { value = new[] { new { id = "existing", displayName = fix.PolicyDisplayName.ToUpperInvariant() } } })
            : Json(new Dictionary<string, object>
            {
                ["value"] = new[] { new { id = "p1", displayName = "Other" } },
                ["@odata.nextLink"] = $"{Policies}?$select=id,displayName&$skiptoken=abc"
            }));

        var result = await writer.ApplyAsync(fix, "tok");

        Assert.True(result.Succeeded);
        Assert.True(result.AlreadyPresent);
        Assert.Equal("existing", result.PolicyId);
        Assert.All(stub.Calls, c => Assert.Equal(HttpMethod.Get, c.Method));
    }

    [Fact]
    public async Task ANextLinkToAnotherHostIsNotFollowed_AndNothingIsCreated()
    {
        var (writer, stub) = Create((_, _) => Json(new Dictionary<string, object>
        {
            ["value"] = Array.Empty<object>(), ["@odata.nextLink"] = "https://evil.example/v1.0/identity/conditionalAccess/policies?x=1"
        }));

        var result = await writer.ApplyAsync(ConfigurationFixes.BlockLegacyAuth, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains("another host", result.Error);
        Assert.Single(stub.Calls);
    }

    [Fact]
    public async Task OnlyCatalogReportOnlyFixesAreSent()
    {
        var (writer, stub) = Create((_, _) => throw new InvalidOperationException("nothing should be sent"));
        var tampered = ConfigurationFixes.BlockLegacyAuth with { PolicyJson = ConfigurationFixes.BlockLegacyAuth.PolicyJson.Replace("enabledForReportingButNotEnforced", "enabled") };

        Assert.Contains("Not a catalog fix", (await writer.ApplyAsync(tampered, "tok")).Error);
        Assert.Contains("isn't report-only", GraphConditionalAccessWriter.ReportOnlyProblem(tampered));
        Assert.Empty(stub.Calls);
    }

    [Fact]
    public async Task APolicyCreatedInAnotherStateIsReported()
    {
        var (writer, _) = Create((r, _) => r.Method == HttpMethod.Get
            ? Json(new { value = Array.Empty<object>() })
            : Json(new { id = "p9", state = "enabled" }, HttpStatusCode.Created));

        var result = await writer.ApplyAsync(ConfigurationFixes.BlockLegacyAuth, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains("not report-only", result.Error);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "P1 licence")]
    [InlineData(HttpStatusCode.TooManyRequests, "throttling")]
    [InlineData(HttpStatusCode.BadRequest, "Graph returned 400")]
    public async Task ErrorsAreReadable_AndNeverRetried(HttpStatusCode status, string expected)
    {
        var (writer, stub) = Create((r, _) => r.Method == HttpMethod.Get
            ? Json(new { value = Array.Empty<object>() })
            : new HttpResponseMessage(status) { Content = new StringContent("{\"error\":{}}") });

        var result = await writer.ApplyAsync(ConfigurationFixes.BlockLegacyAuth, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains(expected, result.Error);
        Assert.Single(stub.Calls, c => c.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task AFailedListingCreatesNothing()
    {
        var (writer, stub) = Create((_, _) => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("{}") });

        var result = await writer.ApplyAsync(ConfigurationFixes.BlockLegacyAuth, "tok");

        Assert.False(result.Succeeded);
        Assert.Contains("Nothing was created", result.Error);
        Assert.DoesNotContain(stub.Calls, c => c.Method == HttpMethod.Post);
    }
}

/// <summary>The Worker's apply loop.</summary>
public class ConfigurationChangeServiceTests
{
    private sealed class Writer : IConditionalAccessWriter
    {
        public List<string> Applied { get; } = [];
        public ConditionalAccessResult Result { get; set; } = new(true, "policy-1", null);

        public Task<ConditionalAccessResult> ApplyAsync(ConfigurationFix fix, string accessToken, CancellationToken cancellationToken = default)
        {
            Applied.Add(fix.Id);
            return Task.FromResult(Result);
        }
    }

    private sealed class Tokens(Func<Guid, string> issue) : IConfigurationTokenProvider
    {
        public Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(issue(entraTenantId));
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(ConfigData.T0);
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public Writer Writer { get; } = new();
        public Func<Guid, string> Issue { get; set; } = tid => Jwt.With(tid, [.. ConfigurationPermissions.Required]);
        public IConfigurationChangeRepository Changes => Store;

        public Harness() => Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);

        public ConfigurationChangeService Service => new(Store, Store, new Tokens(tid => Issue(tid)), Writer, Audit,
            Options.Create(new ConfigurationChangeOptions()), Time, NullLogger<ConfigurationChangeService>.Instance);

        public async Task<ConfigurationChangeRequest> ApprovedAsync(PortalRole approverRole = PortalRole.Owner, bool self = false, Tenant? tenant = null)
        {
            tenant ??= await ConfigData.ConfigurableTenantAsync(Store);
            var requester = Guid.NewGuid();
            var (c, _) = await Changes.AddAsync(new ConfigurationChangeRequest
            {
                Id = Guid.NewGuid(), TenantId = tenant.Id, FixId = ConfigurationFixes.BlockLegacyAuth.Id, CheckId = "MS.AAD.1.1v1", Reason = "MS.AAD.1.1v1 failed",
                Status = DeviceActionStatus.PendingApproval, RequestedAt = Time.Now, RequestedByUserId = requester, RequestedByName = "Adam",
                ExpiresAt = Time.Now.AddDays(3)
            });
            return (await Changes.DecideAsync(c.Id, true, self ? requester : Guid.NewGuid(), "Omar", approverRole, null, Time.Now))!;
        }
    }

    [Fact]
    public async Task AnApprovedFixIsAuditedFirst_ThenAppliedOnce()
    {
        var h = new Harness();
        var c = await h.ApprovedAsync();
        string[]? auditedBeforeSend = null;
        h.Audit.OnRecord = e => auditedBeforeSend ??= h.Writer.Applied.Count == 0 && e.Action == AuditActions.ConfigChangeSending ? ["sending"] : null;

        Assert.Equal(1, await h.Service.RunOnceAsync());

        Assert.Equal(["block-legacy-auth"], h.Writer.Applied);
        Assert.Equal(["sending"], auditedBeforeSend!);
        var done = (await h.Changes.GetAsync(c.Id))!;
        Assert.Equal((DeviceActionStatus.Sent, "policy-1"), (done.Status, done.PolicyId));
        var result = Assert.Single(await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.ConfigChangeResult }));
        Assert.Contains("report-only mode (policy policy-1)", result.Summary);
        Assert.Equal(0, await h.Service.RunOnceAsync()); // never retried
    }

    [Fact]
    public async Task AnAlreadyPresentPolicyIsReportedAsSuch()
    {
        var h = new Harness();
        h.Writer.Result = new ConditionalAccessResult(true, "existing", null, AlreadyPresent: true);
        var c = await h.ApprovedAsync();

        await h.Service.RunOnceAsync();

        var done = (await h.Changes.GetAsync(c.Id))!;
        Assert.Equal(DeviceActionStatus.Sent, done.Status);
        Assert.Contains("already existed", done.Error);
    }

    [Theory]
    [InlineData("admin-approved", "Owner's approval")]
    [InlineData("self-approved", "own request")]
    [InlineData("extra-permission", "holds permissions it shouldn't")]
    [InlineData("missing-permission", "hasn't granted")]
    [InlineData("wrong-tenant", "was issued for tenant")]
    [InlineData("access-off", "configuration access for this tenant was turned off")]
    [InlineData("audit-down", "audit log couldn't be written")]
    public async Task NothingIsSentUnlessEverythingStillHolds(string problem, string expected)
    {
        var h = new Harness();
        var c = problem switch
        {
            "admin-approved" => await h.ApprovedAsync(PortalRole.MspAdmin),
            "self-approved" => await h.ApprovedAsync(self: true),
            _ => await h.ApprovedAsync()
        };
        switch (problem)
        {
            case "extra-permission": h.Issue = tid => Jwt.With(tid, [.. ConfigurationPermissions.Required, "Policy.ReadWrite.Authorization"]); break;
            case "missing-permission": h.Issue = tid => Jwt.With(tid, [ConfigurationPermissions.PolicyRead]); break;
            case "wrong-tenant": h.Issue = _ => Jwt.With(Guid.NewGuid(), [.. ConfigurationPermissions.Required]); break;
            case "access-off": await ((IOnboardingRepository)h.Store).DisableConfigurationAsync(c.TenantId); break;
            case "audit-down": h.Audit.Fail = true; break;
        }

        await h.Service.RunOnceAsync();

        Assert.Empty(h.Writer.Applied);
        var done = (await h.Changes.GetAsync(c.Id))!;
        Assert.Equal(DeviceActionStatus.Failed, done.Status);
        Assert.Contains(expected, done.Error);
    }
}

public class FindingPlaybookRunnerTests
{
    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(ConfigData.T0);
        public FindingPlaybookRunner Runner => new(Store, Store, Store, Store, Time, NullLogger<FindingPlaybookRunner>.Instance);
        public IFindingPlaybookRepository Playbooks => Store;
        public IConfigurationChangeRepository Changes => Store;
        public static readonly Guid Editor = Guid.NewGuid();

        public async Task<FindingPlaybook> PlaybookAsync(ConfigurationFix fix, Guid? tenantId = null, bool enabled = true)
        {
            var p = new FindingPlaybook
            {
                Id = Guid.NewGuid(), FixId = fix.Id, Enabled = enabled, TenantId = tenantId, CreatedAt = Time.Now, UpdatedAt = Time.Now,
                UpdatedByUserId = Editor, UpdatedByName = "Olivia Owner"
            };
            await Playbooks.AddAsync(p);
            return p;
        }
    }

    [Fact]
    public async Task AFailedCatalogCheckProposesItsFix_InTheEditorsName()
    {
        var h = new Harness();
        var tenant = await ConfigData.ConfigurableTenantAsync(h.Store);
        await ConfigData.SaveFindingsAsync(h.Store, tenant.Id, ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1"), ConfigData.Failed(tenant.Id, "MS.AAD.3.2v1", status: FindingStatus.Passed));
        var p = await h.PlaybookAsync(ConfigurationFixes.BlockLegacyAuth);
        await h.PlaybookAsync(ConfigurationFixes.MfaForAllUsers); // its check passed

        Assert.Equal(1, await h.Runner.RunForTenantAsync(tenant));

        var c = Assert.Single(await h.Changes.QueryAsync(new ConfigurationChangeQuery { TenantId = tenant.Id }));
        Assert.Equal((DeviceActionStatus.PendingApproval, "block-legacy-auth", "MS.AAD.1.1v1", p.Id), (c.Status, c.FixId, c.CheckId, c.PlaybookId!.Value));
        Assert.Equal(Harness.Editor, c.RequestedByUserId);
        Assert.Equal(ConfigData.T0 + ConfigurationChangePolicy.ApprovalWindow, c.ExpiresAt);
        Assert.Contains("own request", ConfigurationChangePolicy.WhyCannotApprove(c, Harness.Editor, PortalRole.Owner));
        var e = Assert.Single(await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.ConfigChangeRequested }));
        Assert.Equal("Finding playbook \"Block legacy authentication\"", e.ActorName);
    }

    [Fact]
    public async Task OneProposalPerTenantAndFixPerCooldown()
    {
        var h = new Harness();
        var tenant = await ConfigData.ConfigurableTenantAsync(h.Store);
        await ConfigData.SaveFindingsAsync(h.Store, tenant.Id, ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1"));
        await h.PlaybookAsync(ConfigurationFixes.BlockLegacyAuth);

        Assert.Equal(1, await h.Runner.RunForTenantAsync(tenant));
        var first = Assert.Single(await h.Changes.QueryAsync(new ConfigurationChangeQuery()));
        await h.Changes.DecideAsync(first.Id, false, Guid.NewGuid(), "Omar", PortalRole.Owner, "not yet", h.Time.Now);

        h.Time.Advance(TimeSpan.FromDays(6));
        Assert.Equal(0, await h.Runner.RunForTenantAsync(tenant));
        h.Time.Advance(TimeSpan.FromDays(1) + TimeSpan.FromMinutes(1));
        Assert.Equal(1, await h.Runner.RunForTenantAsync(tenant));
    }

    [Fact]
    public async Task NothingWithoutConfigurationAccess_OrWhenOff_OrOutOfScope()
    {
        var h = new Harness();
        var tenant = await ConfigData.ConfigurableTenantAsync(h.Store);
        await ConfigData.SaveFindingsAsync(h.Store, tenant.Id, ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1"));
        await h.PlaybookAsync(ConfigurationFixes.BlockLegacyAuth, enabled: false);
        await h.PlaybookAsync(ConfigurationFixes.BlockLegacyAuth, tenantId: Guid.NewGuid());
        Assert.Equal(0, await h.Runner.RunForTenantAsync(tenant));

        await h.PlaybookAsync(ConfigurationFixes.BlockLegacyAuth);
        Assert.Equal(0, await h.Runner.RunForTenantAsync(tenant with { ConfigurationCredentialReference = null }));
        Assert.Empty(await h.Changes.QueryAsync(new ConfigurationChangeQuery()));
    }
}

public class ConfigurationChangePortalTests
{
    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(ConfigData.T0);
        public FixedUser User { get; } = FixedUser.MspAdmin();
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public UserContext Admin { get; }
        public UserContext Owner1 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Olivia Owner <olivia@msp.example>");
        public UserContext Owner2 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Omar Owner <omar@msp.example>");

        public Harness()
        {
            Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);
            Admin = User.User;
        }

        public ConfigurationChangeRequestService Service => new(Store, Store, Store, Store, User, new AuditTrail(Audit, User, Time, NullLogger<AuditTrail>.Instance), Time);

        public Harness As(UserContext u)
        {
            User.User = u;
            return this;
        }

        public async Task<Tenant> TenantWithFailedLegacyAuthAsync()
        {
            var tenant = await ConfigData.ConfigurableTenantAsync(Store);
            await ConfigData.SaveFindingsAsync(Store, tenant.Id, ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1"));
            return tenant;
        }

        public Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) => Store.QueryAsync(new AuditQuery { Action = action });
    }

    [Fact]
    public async Task OperatorsRequestAFixForAFailingCheck_AnotherOwnerApproves()
    {
        var h = new Harness();
        var tenant = await h.TenantWithFailedLegacyAuthAsync();

        var requested = await h.As(h.Admin).Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "Legacy auth is open; ticket 4410");
        Assert.True(requested.Ok, requested.Message);
        var c = requested.Request!;
        Assert.Equal((DeviceActionStatus.PendingApproval, "block-legacy-auth", h.Admin.UserId!.Value), (c.Status, c.FixId, c.RequestedByUserId));
        Assert.Single(await h.EventsAsync(AuditActions.ConfigChangeRequested));

        // A second request for the same fix is the same open one.
        Assert.False((await h.Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "again")).Ok);

        Assert.Contains("Owner's approval", (await h.As(FixedUser.MspAdmin().User).Service.ApproveAsync(c.Id, null)).Message);
        var approved = await h.As(h.Owner1).Service.ApproveAsync(c.Id, "Reviewed the sign-in logs");
        Assert.True(approved.Ok, approved.Message);
        Assert.Equal(DeviceActionStatus.Approved, approved.Request!.Status);
        var e = Assert.Single(await h.EventsAsync(AuditActions.ConfigChangeApproved));
        Assert.Equal("Reviewed the sign-in logs", e.Details["note"]);
    }

    [Fact]
    public async Task OwnersCantApproveTheirOwnRequest_AndApprovalIsFailClosed()
    {
        var h = new Harness();
        var tenant = await h.TenantWithFailedLegacyAuthAsync();
        var c = (await h.As(h.Owner1).Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "Legacy auth is open")).Request!;

        Assert.Contains("own request", (await h.Service.ApproveAsync(c.Id, null)).Message);

        h.Audit.Fail = true;
        var refused = await h.As(h.Owner2).Service.ApproveAsync(c.Id, null);
        Assert.False(refused.Ok);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await ((IConfigurationChangeRepository)h.Store).GetAsync(c.Id))!.Status);
    }

    [Fact]
    public async Task RequestsNeedAFailingCatalogCheck_ConfigurationAccess_AndAReason()
    {
        var h = new Harness();
        var tenant = await h.TenantWithFailedLegacyAuthAsync();
        var plain = (await h.Store.GetAllAsync()).First(t => t.Id != tenant.Id && t.ConsentState == TenantConsentState.ReadOnlyGranted);

        Assert.Contains("no reviewed fix", (await h.Service.RequestAsync(tenant.Id, "MS.AAD.9.9v9", "x")).Message);
        Assert.Contains("isn't failing", (await h.Service.RequestAsync(tenant.Id, "MS.AAD.3.2v1", "x")).Message);
        Assert.Contains("hasn't granted configuration access", (await h.Service.RequestAsync(plain.Id, "MS.AAD.1.1v1", "x")).Message);
        Assert.Contains("Give a reason", (await h.Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", " ")).Message);
        Assert.Contains("Only Owners and MSP admins", (await h.As(FixedUser.Viewer(tenant.Id).User).Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "x")).Message);
        Assert.Empty(await ((IConfigurationChangeRepository)h.Store).QueryAsync(new ConfigurationChangeQuery()));
    }

    [Fact]
    public async Task TheFindingOffersItsFixOnlyWhenItCanBeRequested()
    {
        var h = new Harness();
        var tenant = await h.TenantWithFailedLegacyAuthAsync();
        var finding = ConfigData.Failed(tenant.Id, "MS.AAD.1.1v1");

        Assert.Same(ConfigurationFixes.BlockLegacyAuth, await h.Service.FixForAsync(finding));
        Assert.Null(await h.Service.FixForAsync(finding with { Status = FindingStatus.Passed }));
        Assert.Null(await h.Service.FixForAsync(finding with { SourceCheckId = "MS.AAD.9.9v9" }));
        Assert.Null(await h.As(FixedUser.Viewer(tenant.Id).User).Service.FixForAsync(finding));
    }

    [Fact]
    public async Task RejectAndCancel()
    {
        var h = new Harness();
        var tenant = await h.TenantWithFailedLegacyAuthAsync();
        var c = (await h.As(h.Admin).Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "open")).Request!;
        Assert.Contains("Cancel your own", (await h.Service.RejectAsync(c.Id, "no")).Message);
        Assert.Contains("Say why", (await h.As(h.Owner1).Service.RejectAsync(c.Id, " ")).Message);
        Assert.True((await h.Service.RejectAsync(c.Id, "Break-glass accounts first")).Ok);
        Assert.Single(await h.EventsAsync(AuditActions.ConfigChangeRejected));

        var again = (await h.As(h.Admin).Service.RequestAsync(tenant.Id, "MS.AAD.1.1v1", "retry")).Request!;
        Assert.True((await h.Service.CancelAsync(again.Id)).Ok);
        Assert.Equal(DeviceActionStatus.Cancelled, (await ((IConfigurationChangeRepository)h.Store).GetAsync(again.Id))!.Status);
    }

    [Fact]
    public async Task OnlyOwnersManageFindingPlaybooks_Audited()
    {
        var h = new Harness();
        Assert.False((await h.As(h.Admin).Service.CreatePlaybookAsync("block-legacy-auth", null)).Ok);

        Assert.True((await h.As(h.Owner1).Service.CreatePlaybookAsync("block-legacy-auth", null)).Ok);
        Assert.Contains("already a playbook", (await h.Service.CreatePlaybookAsync("block-legacy-auth", null)).Message);
        Assert.Contains("Unknown fix", (await h.Service.CreatePlaybookAsync("enable-everything", null)).Message);
        var p = (await ((IFindingPlaybookRepository)h.Store).GetAllAsync()).Single();
        Assert.Equal(h.Owner1.UserId, p.UpdatedByUserId);

        Assert.False((await h.As(h.Admin).Service.SetPlaybookEnabledAsync(p.Id, false, p.UpdatedAt)).Ok);
        h.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.True((await h.As(h.Owner2).Service.SetPlaybookEnabledAsync(p.Id, false, p.UpdatedAt)).Ok);
        Assert.Contains("Someone else changed", (await h.Service.SetPlaybookEnabledAsync(p.Id, true, p.UpdatedAt)).Message);
        var off = (await ((IFindingPlaybookRepository)h.Store).GetAsync(p.Id))!;
        Assert.Equal((false, h.Owner2.UserId), (off.Enabled, off.UpdatedByUserId));

        Assert.False((await h.As(h.Admin).Service.DeletePlaybookAsync(p.Id)).Ok);
        Assert.True((await h.As(h.Owner1).Service.DeletePlaybookAsync(p.Id)).Ok);
        Assert.Single(await h.EventsAsync(AuditActions.FindingPlaybookCreated));
        Assert.Single(await h.EventsAsync(AuditActions.FindingPlaybookChanged));
        Assert.Single(await h.EventsAsync(AuditActions.FindingPlaybookDeleted));

        var views = await h.As(h.Admin).Service.GetPlaybooksAsync();
        Assert.Equal(ConfigurationFixes.All.Count, views.Count); // every catalog fix listed, set up or not
        Assert.Empty(await h.As(FixedUser.Viewer(Guid.NewGuid()).User).Service.GetPlaybooksAsync());
    }
}

public class ConfigurationConsentPortalTests
{
    private static readonly Guid ConfigApp = Guid.NewGuid();
    private static readonly Guid RemediationApp = Guid.NewGuid();

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(ConfigData.T0);
        public FixedUser User { get; } = FixedUser.Owner();
        public EphemeralDataProtectionProvider Protection { get; } = new();
        public OnboardingOptions Options { get; set; } = new()
        {
            AppClientId = Guid.NewGuid().ToString(), RemediationAppClientId = RemediationApp.ToString(), ConfigurationAppClientId = ConfigApp.ToString()
        };

        public OnboardingService Service => new(Store, Store, Store, Store, new OnboardingServiceTests.Resolver(_ => Guid.NewGuid()),
            Protection, Options, Time, User, new AuditTrail(Store, User, Time, NullLogger<AuditTrail>.Instance),
            NullLogger<OnboardingService>.Instance);
    }

    [Fact]
    public async Task OwnersStartConfigurationConsent_ForTheConfigurationApp()
    {
        var h = new Harness();
        var tenant = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);

        var started = await h.Service.StartConfigurationAsync(tenant.Id);
        Assert.Null(started.Error);
        Assert.Equal(OnboardingKind.Configuration, started.Request!.Kind);
        Assert.Contains($"client_id={ConfigApp}", h.Service.GetConsentUrl(started.Request, "https://portal.example/"));
        Assert.True((await h.Service.StartConfigurationAsync(tenant.Id)).Reused);

        h.User.User = FixedUser.MspAdmin().User;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => h.Service.StartConfigurationAsync(tenant.Id));
    }

    [Theory]
    [InlineData("")]
    [InlineData("same-as-assessment")]
    [InlineData("same-as-remediation")]
    public async Task TheConfigurationAppMustBeItsOwnApp(string setting)
    {
        var h = new Harness();
        h.Options = new OnboardingOptions
        {
            AppClientId = "11111111-1111-1111-1111-111111111111", RemediationAppClientId = "22222222-2222-2222-2222-222222222222",
            ConfigurationAppClientId = setting switch
            {
                "same-as-assessment" => "11111111-1111-1111-1111-111111111111",
                "same-as-remediation" => "22222222-2222-2222-2222-222222222222",
                _ => ""
            }
        };
        var tenant = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);

        Assert.False(h.Service.IsConfigurationConfigured);
        Assert.Contains("ConfigurationAppClientId", (await h.Service.StartConfigurationAsync(tenant.Id)).Error);
    }

    [Fact]
    public async Task TurningItOffCancelsOpenChanges_Audited()
    {
        var h = new Harness();
        var tenant = await ConfigData.ConfigurableTenantAsync(h.Store);
        Assert.NotNull((await h.Service.StartConfigurationAsync(tenant.Id)).Error); // already has it
        IConfigurationChangeRepository changes = h.Store;
        var (c, _) = await changes.AddAsync(new ConfigurationChangeRequest
        {
            Id = Guid.NewGuid(), TenantId = tenant.Id, FixId = "block-legacy-auth", Reason = "r", Status = DeviceActionStatus.PendingApproval,
            RequestedAt = ConfigData.T0, RequestedByUserId = Guid.NewGuid(), RequestedByName = "Adam", ExpiresAt = ConfigData.T0.AddDays(3)
        });

        Assert.True(await h.Service.DisableConfigurationAsync(tenant.Id));

        Assert.False((await h.Store.GetAsync(tenant.Id))!.CanConfigure);
        Assert.Equal(DeviceActionStatus.Cancelled, (await changes.GetAsync(c.Id))!.Status);
        Assert.Single(await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.ConfigurationDisabled }));
        Assert.Single(await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.ConfigChangeCancelled }));
        Assert.False(await h.Service.DisableConfigurationAsync(tenant.Id));
    }
}

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;

namespace SecurePulse.Tests.Audit;

internal static class AuditAssert
{
    public static async Task<AuditEvent> SingleAsync(IAuditLog log, string action, AuditOutcome? outcome = null)
    {
        var events = (await log.QueryAsync(new AuditQuery { Limit = 1000 })).Where(e => e.Action == action).ToList();
        var match = Assert.Single(events, e => outcome is null || e.Outcome == outcome);
        return match;
    }

    public static async Task<IReadOnlyList<AuditEvent>> AllAsync(IAuditLog log) => await log.QueryAsync(new AuditQuery { Limit = 1000 });
}

public class AuditTrailTests
{
    private sealed class BrokenLog : IAuditLog
    {
        public Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default) => throw new InvalidOperationException("db down");
        public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken ct = default) => throw new NotSupportedException();
    }

    [Fact]
    public async Task FillsActorTimeAndCategory()
    {
        var store = new SampleDataStore();
        var user = FixedUser.MspAdmin();
        var time = new FakeTime(new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero));
        var trail = new AuditTrail(store, user, time, NullLogger<AuditTrail>.Instance);

        await trail.RecordAsync(AuditActions.Invited, AuditOutcome.Success, "Invited x", ipAddress: "10.0.0.5");

        var e = await AuditAssert.SingleAsync(store, AuditActions.Invited);
        Assert.Equal(user.User.UserId, e.ActorUserId);
        Assert.Equal(user.User.Name, e.ActorName);
        Assert.Equal(time.Now, e.OccurredAt);
        Assert.Equal("people", e.Category);
        Assert.Equal("10.0.0.5", e.IpAddress);
    }

    [Fact]
    public async Task AuditFailureDoesNotBreakTheAction()
    {
        var trail = new AuditTrail(new BrokenLog(), FixedUser.Owner(), TimeProvider.System, NullLogger<AuditTrail>.Instance);

        await trail.RecordAsync(AuditActions.SignOut, AuditOutcome.Success, "x"); // logged as critical, not thrown
    }

    [Theory]
    [InlineData("auth.sign-in", "auth")]
    [InlineData("people.invited", "people")]
    [InlineData("onboarding.tenant-connected", "onboarding")]
    [InlineData("device.action-requested", "device")]
    public void CategoryIsTheActionPrefix(string action, string category) =>
        Assert.Equal(category, AuditActions.CategoryOf(action));

    [Fact]
    public void EveryActionHasALabelAndAKnownCategory()
    {
        var actions = typeof(AuditActions).GetFields().Where(f => f.IsLiteral).Select(f => (string)f.GetRawConstantValue()!).ToList();

        Assert.NotEmpty(actions);
        Assert.All(actions, a =>
        {
            Assert.NotEqual(a, AuditActions.Label(a));
            Assert.Contains(AuditActions.CategoryOf(a), AuditActions.Categories.Keys);
        });
    }
}

public class PeopleAuditTests
{
    private static readonly Guid OperatorTenant = Guid.NewGuid();

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FixedUser Actor { get; set; } = FixedUser.Owner();

        public PortalUserService Service
        {
            get
            {
                var time = new FakeTime(DateTimeOffset.UtcNow);
                return new(Store, Store, new AuthOptions { OperatorTenantId = OperatorTenant }, Actor, time,
                    new AuditTrail(Store, Actor, time, NullLogger<AuditTrail>.Instance));
            }
        }

        public async Task<PortalUser> SignedInAsync(PortalRole role, string upn)
        {
            IPortalUserRepository users = Store;
            await users.AddAsync(new PortalUser { Id = Guid.NewGuid(), Role = role, EntraTenantId = OperatorTenant, UserPrincipalName = upn, CreatedAt = DateTimeOffset.UtcNow });
            return (await users.SignInAsync(OperatorTenant, Guid.NewGuid(), upn, null, DateTimeOffset.UtcNow))!;
        }
    }

    [Fact]
    public async Task InvitationIsAudited()
    {
        var h = new Harness();
        var tenant = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);

        var result = await h.Service.InviteAsync(new InviteForm { SignInName = "Vera@Client.example", Role = PortalRole.ClientViewer, ClientTenantId = tenant.Id });

        var e = await AuditAssert.SingleAsync(h.Store, AuditActions.Invited, AuditOutcome.Success);
        Assert.Equal(h.Actor.User.UserId, e.ActorUserId);
        Assert.Equal(tenant.Id, e.TenantId);
        Assert.Equal("PortalUser", e.TargetType);
        Assert.Equal(result.User!.Id.ToString(), e.TargetId);
        Assert.Contains("vera@client.example", e.Summary);
        Assert.Contains(tenant.DisplayName, e.Summary);
        Assert.Equal("ClientViewer", e.Details["role"]);
        Assert.Equal(tenant.EntraTenantId.ToString(), e.Details["entraTenantId"]);
    }

    [Fact]
    public async Task RefusedInvitationIsAuditedAsDenied()
    {
        var h = new Harness { Actor = FixedUser.MspAdmin() };

        await h.Service.InviteAsync(new InviteForm { SignInName = "someone@msp.example", Role = PortalRole.Owner });

        var e = await AuditAssert.SingleAsync(h.Store, AuditActions.Invited, AuditOutcome.Denied);
        Assert.Contains("without permission", e.Summary);
    }

    [Fact]
    public async Task ValidationErrorsAreNotAudited()
    {
        var h = new Harness();

        await h.Service.InviteAsync(new InviteForm { SignInName = "not an address", Role = PortalRole.MspAdmin });

        Assert.Empty(await AuditAssert.AllAsync(h.Store));
    }

    [Fact]
    public async Task RoleChangesAreAuditedWithOutcome()
    {
        var h = new Harness();
        var owner = await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        var admin = await h.SignedInAsync(PortalRole.MspAdmin, "adam@msp.example");

        await h.Service.ChangeRoleAsync(admin.Id, PortalRole.Owner);
        await h.Service.ChangeRoleAsync(admin.Id, PortalRole.MspAdmin);
        await h.Service.ChangeRoleAsync(owner.Id, PortalRole.MspAdmin); // last owner: refused
        h.Actor = FixedUser.MspAdmin();
        await h.Service.ChangeRoleAsync(owner.Id, PortalRole.MspAdmin); // not an Owner: denied

        var events = (await AuditAssert.AllAsync(h.Store)).Where(e => e.Action == AuditActions.RoleChanged).ToList();
        Assert.Equal(2, events.Count(e => e.Outcome == AuditOutcome.Success));
        var refused = Assert.Single(events, e => e.Outcome == AuditOutcome.Failure);
        Assert.Contains("At least one Owner", refused.Summary);
        Assert.Single(events, e => e.Outcome == AuditOutcome.Denied);
        Assert.Contains(events, e => e is { Outcome: AuditOutcome.Success } && e.Details["from"] == "MspAdmin" && e.Details["to"] == "Owner");
    }

    [Fact]
    public async Task RemovalsAreAuditedWithOutcome()
    {
        var h = new Harness();
        var owner = await h.SignedInAsync(PortalRole.Owner, "olivia@msp.example");
        var admin = await h.SignedInAsync(PortalRole.MspAdmin, "adam@msp.example");

        await h.Service.RemoveAsync(admin.Id);
        await h.Service.RemoveAsync(owner.Id); // last owner
        h.Actor = FixedUser.MspAdmin();
        await h.Service.RemoveAsync(owner.Id); // MSP admin can't remove an Owner

        var events = (await AuditAssert.AllAsync(h.Store)).Where(e => e.Action == AuditActions.Removed).ToList();
        Assert.Contains(events, e => e.Outcome == AuditOutcome.Success && e.TargetId == admin.Id.ToString());
        Assert.Contains(events, e => e.Outcome == AuditOutcome.Failure && e.TargetId == owner.Id.ToString());
        Assert.Contains(events, e => e.Outcome == AuditOutcome.Denied && e.TargetId == owner.Id.ToString());
    }
}

public class OnboardingAuditTests
{
    private static readonly Guid ClientTenant = Guid.NewGuid();

    private sealed class Resolver : IEntraTenantResolver
    {
        public Task<Guid?> ResolveAsync(string domain, CancellationToken ct = default) => Task.FromResult<Guid?>(ClientTenant);
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(DateTimeOffset.UtcNow);
        public FixedUser User { get; } = FixedUser.MspAdmin();
        private readonly IDataProtectionProvider _protection = new EphemeralDataProtectionProvider();

        public OnboardingService Service => new(Store, Store, new Resolver(), _protection, new OnboardingOptions { AppClientId = Guid.NewGuid().ToString() },
            Time, User, new AuditTrail(Store, User, Time, NullLogger<AuditTrail>.Instance), NullLogger<OnboardingService>.Instance);

        public async Task<(OnboardingRequest Request, string State)> StartAsync()
        {
            var result = await Service.StartAsync(new ConnectTenantForm { DisplayName = "Contoso Clinic", PrimaryDomain = "contoso.com" });
            var url = Service.GetConsentUrl(result.Request!, "https://portal.test/")!;
            return (result.Request!, QueryHelpers.ParseQuery(new Uri(url).Query)["state"].ToString());
        }
    }

    [Fact]
    public async Task LinkCreatedAndCancelledAreAudited()
    {
        var h = new Harness();
        var (request, _) = await h.StartAsync();
        await h.Service.CancelAsync(request.Id);

        var created = await AuditAssert.SingleAsync(h.Store, AuditActions.LinkCreated, AuditOutcome.Success);
        Assert.Equal(h.User.User.Name, created.ActorName);
        Assert.Equal(request.Id.ToString(), created.TargetId);
        Assert.Equal("contoso.com", created.Details["domain"]);
        Assert.Equal(ClientTenant.ToString(), created.Details["entraTenantId"]);
        await AuditAssert.SingleAsync(h.Store, AuditActions.LinkCancelled, AuditOutcome.Success);
    }

    [Fact]
    public async Task CallbackOutcomesAreAuditedWithTheCallersAddress()
    {
        var h = new Harness();
        var (_, state) = await h.StartAsync();

        await h.Service.HandleCallbackAsync(state, null, null, "access_denied", "AADSTS65004: declined\r\nTrace ID: 1", ipAddress: "203.0.113.7");
        await h.Service.HandleCallbackAsync(state, Guid.NewGuid().ToString(), "True", null, null, ipAddress: "203.0.113.7");
        await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null, ipAddress: "203.0.113.7");
        await h.Service.HandleCallbackAsync(state, ClientTenant.ToString(), "True", null, null, ipAddress: "203.0.113.7");

        var declined = await AuditAssert.SingleAsync(h.Store, AuditActions.ConsentDeclined, AuditOutcome.Failure);
        Assert.Equal("AADSTS65004: declined", declined.Details["reason"]);
        var wrong = await AuditAssert.SingleAsync(h.Store, AuditActions.ConsentWrongTenant, AuditOutcome.Denied);
        Assert.True(wrong.Details.ContainsKey("consentedTenantId"));
        var received = await AuditAssert.SingleAsync(h.Store, AuditActions.ConsentReceived, AuditOutcome.Success);
        Assert.Equal(AuditTrail.ConsentingAdmin.Name, received.ActorName);
        Assert.Null(received.ActorUserId);
        Assert.Equal("203.0.113.7", received.IpAddress);
        await AuditAssert.SingleAsync(h.Store, AuditActions.ConsentLinkUnusable, AuditOutcome.Failure);
    }

    [Fact]
    public async Task UnknownStatesAreNotAudited()
    {
        var h = new Harness();

        for (var i = 0; i < 20; i++)
            await h.Service.HandleCallbackAsync($"forged-{i}", ClientTenant.ToString(), "True", null, null, ipAddress: "198.51.100.1");

        Assert.Empty(await AuditAssert.AllAsync(h.Store));
    }
}

public class AuditExportFormatTests
{
    [Theory]
    [InlineData("plain", "\"plain\"")]
    [InlineData(null, "\"\"")]
    [InlineData("has \"quotes\", commas", "\"has \"\"quotes\"\", commas\"")]
    [InlineData("=HYPERLINK(\"http://evil\")", "\"'=HYPERLINK(\"\"http://evil\"\")\"")]
    [InlineData("+1", "\"'+1\"")]
    [InlineData("-2", "\"'-2\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("\tx", "\"'\tx\"")]
    [InlineData("line\nbreak", "\"line\nbreak\"")]
    public void CellsAreQuotedAndFormulasNeutralized(string? input, string expected) =>
        Assert.Equal(expected, AuditExport.Cell(input));

    [Fact]
    public void FilterRoundTripsThroughTheQueryString()
    {
        var tenant = Guid.NewGuid();
        var filter = new AuditFilter { Period = "30d", Category = "people", Outcome = AuditOutcome.Denied, TenantId = tenant, Search = "olivia" };

        var parsed = AuditFilter.FromQuery(new QueryCollection(QueryHelpers.ParseQuery(filter.ToQueryString())));

        Assert.Equal(filter, parsed);
    }

    [Fact]
    public void UnknownFilterValuesFallBackToDefaults()
    {
        var parsed = AuditFilter.FromQuery(new QueryCollection(new Dictionary<string, StringValues>
        {
            ["period"] = "forever", ["category"] = "nope", ["outcome"] = "Maybe", ["tenant"] = "x", ["search"] = new string('a', 500)
        }));

        Assert.Equal(new AuditFilter(), parsed);
    }

    [Fact]
    public void PeriodBecomesALowerBound()
    {
        var now = new DateTimeOffset(2026, 10, 13, 12, 0, 0, TimeSpan.Zero);

        Assert.Equal(now.AddDays(-7), new AuditFilter().ToQuery(now, 10).From);
        Assert.Null(new AuditFilter { Period = "all" }.ToQuery(now, 10).From);
    }
}

public class InMemoryAuditQueryTests
{
    private static AuditEvent E(DateTimeOffset at, string action = AuditActions.SignIn, AuditOutcome outcome = AuditOutcome.Success,
        string actor = "Pat <pat@msp.example>", Guid? tenant = null, string summary = "did a thing") => new()
    {
        Id = Guid.NewGuid(), OccurredAt = at, Action = action, Outcome = outcome, ActorName = actor, TenantId = tenant, Summary = summary
    };

    [Fact]
    public async Task FiltersAndPagesNewestFirst()
    {
        IAuditLog log = new SampleDataStore();
        var t0 = DateTimeOffset.UtcNow;
        var tenant = Guid.NewGuid();
        var all = Enumerable.Range(0, 25).Select(i => E(t0.AddMinutes(-i), i % 2 == 0 ? AuditActions.SignIn : AuditActions.Invited,
            i % 5 == 0 ? AuditOutcome.Denied : AuditOutcome.Success, i == 3 ? "Kim <kim@client.example>" : "Pat", i % 3 == 0 ? tenant : null)).ToList();
        foreach (var e in all.OrderBy(_ => Guid.NewGuid())) await log.RecordAsync(e);

        var first = await log.QueryAsync(new AuditQuery { Limit = 10 });
        var second = await log.QueryAsync(new AuditQuery { Limit = 10, Before = (first[^1].OccurredAt, first[^1].Id) });
        Assert.Equal(all.Take(20).Select(e => e.Id), first.Concat(second).Select(e => e.Id));

        Assert.All(await log.QueryAsync(new AuditQuery { Category = "people", Limit = 100 }), e => Assert.Equal("people", e.Category));
        Assert.Equal(5, (await log.QueryAsync(new AuditQuery { Outcome = AuditOutcome.Denied, Limit = 100 })).Count);
        Assert.Equal(9, (await log.QueryAsync(new AuditQuery { TenantId = tenant, Limit = 100 })).Count);
        Assert.Single(await log.QueryAsync(new AuditQuery { Search = "KIM@client", Limit = 100 }));
        Assert.Equal(11, (await log.QueryAsync(new AuditQuery { From = t0.AddMinutes(-10), Limit = 100 })).Count);
    }
}

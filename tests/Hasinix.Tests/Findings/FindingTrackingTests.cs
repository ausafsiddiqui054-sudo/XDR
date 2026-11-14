using Microsoft.Extensions.Logging.Abstractions;
using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Reporting;
using Hasinix.Reporting.Pdf;
using Hasinix.Tests.DeviceActions;
using Hasinix.Tests.Onboarding;
using Hasinix.Web.Security;
using Hasinix.Web.Services;

namespace Hasinix.Tests.Findings;

public class FindingTrackingPolicyTests
{
    private static readonly Guid Requester = Guid.NewGuid();

    private static FindingTracking Request(RiskAcceptanceStatus status = RiskAcceptanceStatus.Requested) => new()
    {
        TenantId = Guid.NewGuid(), FindingId = "maester:1", FindingTitle = "MFA for admins", Acceptance = status,
        RequestedByUserId = Requester, RequestedByName = "Adam Admin", UpdatedAt = DateTimeOffset.UtcNow
    };

    [Fact]
    public void OnlyAnotherOwnerDecidesARequest()
    {
        Assert.Null(FindingTrackingPolicy.WhyCannotDecide(Request(), Guid.NewGuid(), PortalRole.Owner));
        Assert.Contains("your own request", FindingTrackingPolicy.WhyCannotDecide(Request(), Requester, PortalRole.Owner));
        Assert.Contains("an Owner has to decide", FindingTrackingPolicy.WhyCannotDecide(Request(), Guid.NewGuid(), PortalRole.MspAdmin));
        Assert.Contains("an Owner has to decide", FindingTrackingPolicy.WhyCannotDecide(Request(), Guid.NewGuid(), PortalRole.ClientViewer));
        Assert.Contains("an Owner has to decide", FindingTrackingPolicy.WhyCannotDecide(Request(), null, null));
    }

    [Theory]
    [InlineData(RiskAcceptanceStatus.None)]
    [InlineData(RiskAcceptanceStatus.Accepted)]
    [InlineData(RiskAcceptanceStatus.Rejected)]
    public void NothingToDecideUnlessARequestIsWaiting(RiskAcceptanceStatus status) =>
        Assert.Contains("No risk acceptance is waiting", FindingTrackingPolicy.WhyCannotDecide(Request(status), Guid.NewGuid(), PortalRole.Owner));

    [Fact]
    public void AnAcceptanceRunsUntilItsEndDateThenCountsAsExpired()
    {
        var now = new DateTimeOffset(2026, 11, 14, 8, 0, 0, TimeSpan.Zero);
        var accepted = Request(RiskAcceptanceStatus.Accepted) with { AcceptanceExpiresAt = now.AddDays(1) };

        Assert.True(accepted.IsAccepted(now));
        Assert.False(accepted.CanRequest(now));
        Assert.True(accepted.IsExpired(now.AddDays(1)));
        Assert.False(accepted.IsAccepted(now.AddDays(1)));
        Assert.True(accepted.CanRequest(now.AddDays(1)));
        Assert.False(Request().CanRequest(now)); // a waiting request blocks another
    }

    [Fact]
    public void OnlyChecksThatFailedOrNeedReviewCanBeAccepted()
    {
        Assert.True(FindingTrackingPolicy.CanBeAccepted(FindingStatus.Failed));
        Assert.True(FindingTrackingPolicy.CanBeAccepted(FindingStatus.Investigate));
        Assert.False(FindingTrackingPolicy.CanBeAccepted(FindingStatus.Passed));
        Assert.False(FindingTrackingPolicy.CanBeAccepted(FindingStatus.NotEvaluated));
    }
}

public class FindingTrackingServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 14, 8, 0, 0, TimeSpan.Zero);
    private static readonly DateOnly Today = new(2026, 11, 14);

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(T0);
        public FixedUser User { get; } = FixedUser.MspAdmin();
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public UserContext Admin { get; }
        public UserContext Owner1 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Olivia Owner <olivia@msp.example>");
        public UserContext Owner2 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Omar Owner <omar@msp.example>");
        public Tenant Tenant { get; }
        public Tenant OtherTenant { get; }
        public Finding Failed { get; }
        public Finding Passed { get; }

        public Harness()
        {
            Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);
            Admin = User.User;
            var scanned = Store.GetAllAsync().Result.Where(t => t.LastScanAt is not null).ToList();
            (Tenant, OtherTenant) = (scanned[0], scanned[1]);
            var findings = Store.GetForTenantAsync(Tenant.Id).Result;
            Failed = findings.First(f => f.Status == FindingStatus.Failed);
            Passed = findings.First(f => f.Status == FindingStatus.Passed);
        }

        public FindingTrackingService Service => new(Store, Store, Store, User, new AuditTrail(Audit, User, Time, NullLogger<AuditTrail>.Instance),
            new ReportSettings { Enabled = false, Branding = new ReportBranding(), TimeZone = TimeZoneInfo.Utc }, Time);

        public IFindingTrackingRepository Tracking => Store;

        public Harness As(UserContext u)
        {
            User.User = u;
            return this;
        }

        public Task<TrackingOutcome> RequestAsync(Finding? finding = null, string? reason = "The lab system needs it until January; agreed with the manager.", int days = 30) =>
            Service.RequestAcceptanceAsync(Tenant.Id, (finding ?? Failed).Id, reason, Today.AddDays(days));

        public async Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) =>
            await Store.QueryAsync(new AuditQuery { Action = action });
    }

    // --- Owner and due date -------------------------------------------------------------

    [Fact]
    public async Task AnAdminAssignsAnOwnerAndDueDate_AndItIsAudited()
    {
        var h = new Harness();

        var outcome = await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "  Fatima (clinic IT) ", Today.AddDays(14));

        Assert.True(outcome.Ok, outcome.Message);
        var saved = (await h.Service.GetAsync())[(h.Tenant.Id, h.Failed.Id)];
        Assert.Equal(("Fatima (clinic IT)", Today.AddDays(14), RiskAcceptanceStatus.None, h.Failed.Title),
            (saved.Owner, saved.DueDate, saved.Acceptance, saved.FindingTitle));
        Assert.False(saved.IsOverdue(Today));
        Assert.True(saved.IsOverdue(Today.AddDays(15)));
        var audit = Assert.Single(await h.EventsAsync(AuditActions.FindingOwnerChanged));
        Assert.Equal((h.Tenant.Id, "Finding", h.Failed.Id, h.Admin.Name), (audit.TenantId!.Value, audit.TargetType, audit.TargetId, audit.ActorName));
        Assert.Contains("Fatima (clinic IT), due 28 Nov 2026", audit.Summary);
    }

    [Fact]
    public async Task ClearingBothRemovesTheOwnerButKeepsAnAcceptance()
    {
        var h = new Harness();
        await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Fatima", Today.AddDays(14));
        await h.RequestAsync();

        var outcome = await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, " ", null);

        Assert.Equal("Owner and due date cleared.", outcome.Message);
        Assert.Equal((null, null, RiskAcceptanceStatus.Requested), (outcome.Tracking!.Owner, outcome.Tracking.DueDate, outcome.Tracking.Acceptance));
    }

    [Fact]
    public async Task OnlyOperatorsAssign_AndOnlyRealFindingsOfTenantsTheySee()
    {
        var h = new Harness();

        Assert.False((await h.As(FixedUser.Viewer(h.Tenant.Id).User).Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Me", null)).Ok);
        Assert.False((await h.As(UserContext.Anonymous).Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Me", null)).Ok);
        Assert.Equal("Finding not found.", (await h.As(h.Admin).Service.SetOwnerAsync(h.Tenant.Id, "maester:nope", "Me", null)).Message);
        Assert.Equal("Finding not found.", (await h.Service.SetOwnerAsync(h.OtherTenant.Id, h.Failed.Id, "Me", null)).Message); // another tenant's ID
        Assert.Contains("under 200", (await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, new string('x', 201), null)).Message);
        Assert.Empty(await h.Service.GetAsync());
        Assert.Empty(await h.EventsAsync(AuditActions.FindingOwnerChanged));
    }

    // --- Asking for a risk to be accepted ------------------------------------------------

    [Fact]
    public async Task ARequestNeedsAReasonAndAnEndDateWithinAYear()
    {
        var h = new Harness();

        Assert.Contains("Give a reason", (await h.RequestAsync(reason: "  ")).Message);
        Assert.Contains("under 500", (await h.RequestAsync(reason: new string('x', 501))).Message);
        Assert.Contains("Choose an end date", (await h.Service.RequestAcceptanceAsync(h.Tenant.Id, h.Failed.Id, "why", null)).Message);
        Assert.Contains("after today", (await h.RequestAsync(days: 0)).Message);
        Assert.Contains("at most 365 days", (await h.RequestAsync(days: 366)).Message);
        Assert.Contains("failed or need review", (await h.RequestAsync(h.Passed)).Message);
        Assert.False((await h.As(FixedUser.Viewer(h.Tenant.Id).User).RequestAsync()).Ok);
        Assert.Empty(await h.As(h.Admin).Service.GetAsync());

        Assert.True((await h.RequestAsync(days: 365)).Ok);
    }

    [Fact]
    public async Task ARequestWaitsForAnOwner_RunsToTheEndOfItsLastDay_AndIsAudited()
    {
        var h = new Harness();

        var outcome = await h.RequestAsync(days: 30);

        Assert.True(outcome.Ok, outcome.Message);
        Assert.Contains("An Owner other than you has to approve it", outcome.Message);
        var t = outcome.Tracking!;
        Assert.Equal((RiskAcceptanceStatus.Requested, h.Admin.UserId, h.Admin.Name, T0), (t.Acceptance, t.RequestedByUserId, t.RequestedByName, t.RequestedAt!.Value));
        Assert.Equal(new DateTimeOffset(2026, 12, 15, 0, 0, 0, TimeSpan.Zero), t.AcceptanceExpiresAt); // end of 14 Dec
        Assert.Equal("14 Dec 2026", h.Service.Day(t.AcceptanceExpiresAt));
        Assert.False(t.IsAccepted(T0)); // not accepted until an Owner approves
        Assert.Contains("until 14 Dec 2026", Assert.Single(await h.EventsAsync(AuditActions.RiskAcceptanceRequested)).Summary);
        Assert.Contains("already has a risk acceptance waiting", (await h.RequestAsync()).Message);
    }

    // --- Deciding ------------------------------------------------------------------------

    [Fact]
    public async Task AnotherOwnerApproves_TheRequesterAndAdminsCannot()
    {
        var h = new Harness();
        await h.As(h.Owner1).RequestAsync();

        Assert.Contains("your own request", (await h.Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null)).Message);
        Assert.Contains("an Owner has to decide", (await h.As(h.Admin).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null)).Message);
        Assert.Equal(0, await h.As(h.Owner1).Service.CountAwaitingMyDecisionAsync());
        Assert.Equal(1, await h.As(h.Owner2).Service.CountAwaitingMyDecisionAsync());

        var outcome = await h.Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, " Review in January ");

        Assert.True(outcome.Ok, outcome.Message);
        var t = outcome.Tracking!;
        Assert.Equal((RiskAcceptanceStatus.Accepted, h.Owner2.UserId, h.Owner2.Name, "Review in January"), (t.Acceptance, t.DecidedByUserId, t.DecidedByName, t.DecisionNote));
        Assert.True(t.IsAccepted(h.Time.Now));
        Assert.Equal(0, await h.Service.CountAwaitingMyDecisionAsync());
        var audit = Assert.Single(await h.EventsAsync(AuditActions.RiskAcceptanceApproved));
        Assert.Equal((AuditOutcome.Success, "Review in January"), (audit.Outcome, audit.Details["note"]));
    }

    [Fact]
    public async Task AcceptingARiskChangesNeitherTheFindingNorTheScore()
    {
        var h = new Harness();
        var before = await h.Store.GetForTenantAsync(h.Tenant.Id);
        var score = RiskScoreCalculator.Calculate(before);
        await h.RequestAsync();

        Assert.True((await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null)).Ok);

        var after = await h.Store.GetForTenantAsync(h.Tenant.Id);
        Assert.Equal(before, after);
        Assert.Equal((score.Score, score.Grade, score.Failed), RiskScoreCalculator.Calculate(after) is var s ? (s.Score, s.Grade, s.Failed) : default);
    }

    [Fact]
    public async Task ApprovalIsNotAppliedWhenTheAuditLogIsDown()
    {
        var h = new Harness();
        await h.RequestAsync();
        h.Audit.Fail = true;

        var outcome = await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null);

        Assert.False(outcome.Ok);
        Assert.Contains("audit log couldn't be written", outcome.Message);
        Assert.Equal(RiskAcceptanceStatus.Requested, (await h.Tracking.GetAsync(h.Tenant.Id, h.Failed.Id))!.Acceptance);
    }

    [Fact]
    public async Task TheAuditEntryIsWrittenBeforeTheApprovalApplies()
    {
        var h = new Harness();
        await h.RequestAsync();
        RiskAcceptanceStatus? whenAudited = null;
        h.Audit.OnRecord = e =>
        {
            if (e.Action == AuditActions.RiskAcceptanceApproved) whenAudited = h.Tracking.GetAsync(h.Tenant.Id, h.Failed.Id).Result!.Acceptance;
        };

        await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null);

        Assert.Equal(RiskAcceptanceStatus.Requested, whenAudited);
    }

    [Fact]
    public async Task ARequestCannotBeApprovedOnceTheCheckPassesOrItsEndDateHasGone()
    {
        var h = new Harness();
        await h.RequestAsync(days: 2);

        h.Time.Advance(TimeSpan.FromDays(3));
        Assert.Contains("end date has passed", (await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null)).Message);

        // The next scan reports the check as passing: there is no risk left to accept.
        var h2 = new Harness();
        await h2.RequestAsync();
        await h2.Store.SaveScanAsync(new ScanResult
        {
            TenantId = h2.Tenant.Id, Source = h2.Failed.Source, StartedAt = T0, CompletedAt = T0,
            Findings = (await h2.Store.GetForTenantAsync(h2.Tenant.Id)).Where(f => f.Source == h2.Failed.Source)
                .Select(f => f.Id == h2.Failed.Id ? f with { Status = FindingStatus.Passed } : f).ToList()
        });
        Assert.Contains("no longer fails", (await h2.As(h2.Owner1).Service.ApproveAsync(h2.Tenant.Id, h2.Failed.Id, null)).Message);
    }

    [Fact]
    public async Task RejectingNeedsANote_AndANewRequestCanFollow()
    {
        var h = new Harness();
        await h.RequestAsync();

        Assert.Contains("Say why", (await h.As(h.Owner1).Service.RejectAsync(h.Tenant.Id, h.Failed.Id, " ")).Message);
        Assert.Contains("an Owner has to decide", (await h.As(h.Admin).Service.RejectAsync(h.Tenant.Id, h.Failed.Id, "no")).Message);
        var rejected = await h.As(h.Owner1).Service.RejectAsync(h.Tenant.Id, h.Failed.Id, "Fix it this month instead.");

        Assert.True(rejected.Ok, rejected.Message);
        Assert.Equal((RiskAcceptanceStatus.Rejected, "Fix it this month instead."), (rejected.Tracking!.Acceptance, rejected.Tracking.DecisionNote));
        Assert.Single(await h.EventsAsync(AuditActions.RiskAcceptanceRejected));
        Assert.Contains("No risk acceptance is waiting", (await h.Service.RejectAsync(h.Tenant.Id, h.Failed.Id, "again")).Message);

        var again = await h.As(h.Admin).RequestAsync();
        Assert.True(again.Ok, again.Message);
        Assert.Null(again.Tracking!.DecisionNote); // the old decision doesn't stick to the new request
    }

    // --- Ending --------------------------------------------------------------------------

    [Fact]
    public async Task AnAdminWithdrawsARequestOrEndsAnAcceptance_TheOwnerAndDueDateStay()
    {
        var h = new Harness();
        await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Fatima", Today.AddDays(14));
        await h.RequestAsync();

        var withdrawn = await h.Service.EndAsync(h.Tenant.Id, h.Failed.Id);
        Assert.Equal("Request withdrawn.", withdrawn.Message);
        Assert.Equal((RiskAcceptanceStatus.None, null, null, "Fatima"),
            (withdrawn.Tracking!.Acceptance, withdrawn.Tracking.AcceptanceReason, withdrawn.Tracking.RequestedByName, withdrawn.Tracking.Owner));

        await h.RequestAsync();
        await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null);
        var ended = await h.As(h.Admin).Service.EndAsync(h.Tenant.Id, h.Failed.Id);
        Assert.Equal("Risk acceptance ended.", ended.Message);
        Assert.False(ended.Tracking!.IsAccepted(h.Time.Now));

        Assert.Equal(2, (await h.EventsAsync(AuditActions.RiskAcceptanceEnded)).Count);
        Assert.Contains("no risk acceptance to end", (await h.Service.EndAsync(h.Tenant.Id, h.Failed.Id)).Message);
        Assert.False((await h.As(FixedUser.Viewer(h.Tenant.Id).User).Service.EndAsync(h.Tenant.Id, h.Failed.Id)).Ok);
    }

    [Fact]
    public async Task AnExpiredAcceptanceCanBeAskedForAgain()
    {
        var h = new Harness();
        await h.RequestAsync(days: 5);
        await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null);

        h.Time.Advance(TimeSpan.FromDays(6));
        var expired = (await h.Tracking.GetAsync(h.Tenant.Id, h.Failed.Id))!;
        Assert.True(expired.IsExpired(h.Time.Now));

        var again = await h.As(h.Admin).Service.RequestAcceptanceAsync(h.Tenant.Id, h.Failed.Id, "Still waiting for the new system.", Today.AddDays(40));
        Assert.True(again.Ok, again.Message);
        Assert.Equal((RiskAcceptanceStatus.Requested, null), (again.Tracking!.Acceptance, again.Tracking.DecidedByName));
    }

    // --- Staying power and scope ---------------------------------------------------------

    [Fact]
    public async Task TrackingSurvivesTheNextScan()
    {
        var h = new Harness();
        await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Fatima", Today.AddDays(14));
        await h.RequestAsync();
        await h.As(h.Owner1).Service.ApproveAsync(h.Tenant.Id, h.Failed.Id, null);

        // A scan replaces every finding from that engine; the check comes back with the same ID.
        await h.Store.SaveScanAsync(new ScanResult
        {
            TenantId = h.Tenant.Id, Source = h.Failed.Source, StartedAt = T0.AddDays(1), CompletedAt = T0.AddDays(1),
            Findings = (await h.Store.GetForTenantAsync(h.Tenant.Id)).Where(f => f.Source == h.Failed.Source)
                .Select(f => f with { DetectedAt = T0.AddDays(1) }).ToList()
        });

        var kept = (await h.Service.GetAsync())[(h.Tenant.Id, h.Failed.Id)];
        Assert.Equal(("Fatima", RiskAcceptanceStatus.Accepted), (kept.Owner, kept.Acceptance));
    }

    [Fact]
    public async Task AClientViewerSeesOnlyTheirTenantsTracking_ReadOnly()
    {
        var h = new Harness();
        var theirs = (await h.Store.GetForTenantAsync(h.OtherTenant.Id)).First(f => f.Status == FindingStatus.Failed);
        await h.Service.SetOwnerAsync(h.Tenant.Id, h.Failed.Id, "Fatima", null);
        await h.Service.SetOwnerAsync(h.OtherTenant.Id, theirs.Id, "Someone else", null);

        var seen = await h.As(FixedUser.Viewer(h.Tenant.Id).User).Service.GetAsync();

        Assert.Equal([(h.Tenant.Id, h.Failed.Id)], seen.Keys);
        Assert.Equal(0, await h.Service.CountAwaitingMyDecisionAsync());
        Assert.Equal("Request not found.", (await h.Service.ApproveAsync(h.OtherTenant.Id, theirs.Id, null)).Message);
        Assert.Empty(await h.As(UserContext.Anonymous).Service.GetAsync());
        Assert.Equal(2, (await h.As(h.Owner1).Service.GetAsync()).Count);
    }
}

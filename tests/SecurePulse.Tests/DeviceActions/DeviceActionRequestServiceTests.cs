using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Web.Services.Onboarding;

namespace SecurePulse.Tests.DeviceActions;

public class DeviceActionPolicyTests
{
    private static readonly Guid Requester = Guid.NewGuid();

    private static DeviceActionRequest Request(DeviceAction action) => new()
    {
        Id = Guid.NewGuid(), TenantId = Guid.NewGuid(), DeviceId = Guid.NewGuid().ToString(), DeviceName = "PC-1", Action = action, Reason = "r",
        Status = DeviceActionStatus.PendingApproval, RequestedAt = DateTimeOffset.UtcNow, RequestedByUserId = Requester, RequestedByName = "Req",
        ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
    };

    [Theory]
    [InlineData(DeviceAction.Sync, PortalRole.MspAdmin, true)]
    [InlineData(DeviceAction.Restart, PortalRole.MspAdmin, true)]
    [InlineData(DeviceAction.Retire, PortalRole.MspAdmin, false)]
    [InlineData(DeviceAction.Wipe, PortalRole.MspAdmin, false)]
    [InlineData(DeviceAction.Sync, PortalRole.Owner, true)]
    [InlineData(DeviceAction.Wipe, PortalRole.Owner, true)]
    [InlineData(DeviceAction.Sync, PortalRole.ClientViewer, false)]
    public void WhoMayApproveSomeoneElsesRequest(DeviceAction action, PortalRole role, bool allowed) =>
        Assert.Equal(allowed, DeviceActionPolicy.WhyCannotApprove(Request(action), Guid.NewGuid(), role) is null);

    [Theory]
    [InlineData(PortalRole.Owner)]
    [InlineData(PortalRole.MspAdmin)]
    public void NobodyApprovesTheirOwnRequest(PortalRole role)
    {
        foreach (var action in Enum.GetValues<DeviceAction>())
            Assert.Contains("own request", DeviceActionPolicy.WhyCannotApprove(Request(action), Requester, role));
    }

    [Fact]
    public void ApprovalNeedsAnIdentityAndAnOperatorRole()
    {
        Assert.NotNull(DeviceActionPolicy.WhyCannotApprove(Request(DeviceAction.Sync), null, PortalRole.Owner));
        Assert.NotNull(DeviceActionPolicy.WhyCannotApprove(Request(DeviceAction.Sync), Guid.NewGuid(), null));
        Assert.False(DeviceActionPolicy.CanRequest(PortalRole.ClientViewer));
        Assert.False(DeviceActionPolicy.CanRequest(null));
        Assert.True(DeviceActionPolicy.CanRequest(PortalRole.MspAdmin));
    }

    [Fact]
    public void RemediationAppMayHoldOnlyThePrivilegedOperationsPermission()
    {
        Assert.Empty(RemediationPermissions.Unexpected([RemediationPermissions.PrivilegedOperations]));
        Assert.Empty(RemediationPermissions.MissingFrom(["devicemanagementmanageddevices.privilegedoperations.all"]));
        Assert.Equal(["DeviceManagementManagedDevices.Read.All", "User.Read.All"],
            RemediationPermissions.Unexpected([RemediationPermissions.PrivilegedOperations, "User.Read.All", "DeviceManagementManagedDevices.Read.All"]));
        Assert.Equal([RemediationPermissions.PrivilegedOperations], RemediationPermissions.MissingFrom(["DeviceManagementManagedDevices.Read.All"]));
    }
}

public class DeviceActionRequestServiceTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 14, 9, 0, 0, TimeSpan.Zero);

    /// <summary>An audit log whose writes can be made to fail, to prove approvals are fail-closed.</summary>
    public sealed class FlakyAuditLog(IAuditLog inner) : IAuditLog
    {
        public bool Fail { get; set; }

        public Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default) =>
            Fail ? throw new InvalidOperationException("audit database down") : inner.RecordAsync(auditEvent, ct);

        public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery query, CancellationToken ct = default) => inner.QueryAsync(query, ct);
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(T0);
        public FixedUser User { get; } = FixedUser.MspAdmin();
        public FlakyAuditLog Audit { get; }

        public UserContext Owner1 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Olivia Owner <olivia@msp.example>");
        public UserContext Owner2 { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Omar Owner <omar@msp.example>");
        public UserContext Admin { get; } = new(Guid.NewGuid(), PortalRole.MspAdmin, null, "Adam Admin <adam@msp.example>");

        public Harness() => Audit = new FlakyAuditLog(Store);

        public DeviceActionRequestService Service => new(Store, Store, Store, User, Trail, Time);

        public AuditTrail Trail => new(Audit, User, Time, NullLogger<AuditTrail>.Instance);

        public IDeviceActionRepository Actions => Store;

        public Harness As(UserContext user)
        {
            User.User = user;
            return this;
        }

        public async Task<(Tenant Tenant, ManagedDevice Device)> RemediationDeviceAsync()
        {
            var tenant = (await Store.GetAllAsync()).Single(t => t.CanRemediate);
            return (tenant, (await ((IDeviceRepository)Store).GetForTenantAsync(tenant.Id))[0]);
        }

        public async Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) =>
            (await Store.QueryAsync(new AuditQuery { Limit = 1000 })).Where(e => e.Action == action).ToList();
    }

    private static async Task<DeviceActionRequest> RequestedAsync(Harness h, DeviceAction action, UserContext by)
    {
        var (tenant, device) = await h.RemediationDeviceAsync();
        var outcome = await h.As(by).Service.RequestAsync(tenant.Id, device.Id, action, "User reported the laptop stolen (ticket 5512)");
        Assert.True(outcome.Ok, outcome.Message);
        return outcome.Request!;
    }

    // --- Requesting --------------------------------------------------------------------------

    [Fact]
    public async Task DefenderActionsAreRefusedForDevicesThatArentWindows()
    {
        var h = new Harness();
        var (tenant, _) = await h.RemediationDeviceAsync();
        var mac = new ManagedDevice { Id = Guid.NewGuid().ToString(), TenantId = tenant.Id, DeviceName = "MAC-1", Platform = DevicePlatform.MacOS,
            ComplianceState = DeviceComplianceState.Compliant };
        var win = mac with { Id = Guid.NewGuid().ToString(), DeviceName = "WIN-1", Platform = DevicePlatform.Windows };
        await h.Store.SaveSyncAsync(new DeviceSyncResult { TenantId = tenant.Id, Source = "Intune", StartedAt = T0, CompletedAt = T0, Devices = [mac, win] });

        var refused = await h.As(h.Admin).Service.RequestAsync(tenant.Id, mac.Id, DeviceAction.DefenderQuickScan, "Scan after a phishing click");
        Assert.False(refused.Ok);
        Assert.Contains("only for Windows", refused.Message);

        var ok = await h.As(h.Admin).Service.RequestAsync(tenant.Id, win.Id, DeviceAction.DefenderQuickScan, "Scan after a phishing click");
        Assert.True(ok.Ok, ok.Message);
        Assert.Null(ok.Request!.PlaybookId);
    }

    [Fact]
    public async Task OperatorsRequestAndTheRequestWaitsForApproval()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Admin);

        Assert.Equal(DeviceActionStatus.PendingApproval, a.Status);
        Assert.Equal(h.Admin.UserId, a.RequestedByUserId);
        Assert.Equal(T0 + DeviceActionPolicy.ApprovalWindow, a.ExpiresAt);
        var e = Assert.Single(await h.EventsAsync(AuditActions.DeviceActionRequested));
        Assert.Equal(AuditOutcome.Success, e.Outcome);
        Assert.Equal(a.Id.ToString(), e.TargetId);
        Assert.Equal("User reported the laptop stolen (ticket 5512)", e.Details["reason"]);
    }

    [Fact]
    public async Task RequestsAreRefusedWithoutRemediationAccessReasonDeviceOrRole()
    {
        var h = new Harness();
        var (tenant, device) = await h.RemediationDeviceAsync();
        var readOnly = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);
        var readOnlyDevice = (await ((IDeviceRepository)h.Store).GetForTenantAsync(readOnly.Id))[0];
        var service = h.As(h.Owner1).Service;

        Assert.Contains("remediation access", (await service.RequestAsync(readOnly.Id, readOnlyDevice.Id, DeviceAction.Sync, "r")).Message);
        Assert.Contains("reason", (await service.RequestAsync(tenant.Id, device.Id, DeviceAction.Sync, "  ")).Message);
        Assert.Contains("Device not found", (await service.RequestAsync(tenant.Id, "not-a-device", DeviceAction.Sync, "r")).Message);
        Assert.Contains("under 500", (await service.RequestAsync(tenant.Id, device.Id, DeviceAction.Sync, new string('x', 501))).Message);
        Assert.False((await service.RequestAsync(tenant.Id, device.Id, (DeviceAction)42, "r")).Ok);
        Assert.False((await h.As(FixedUser.Viewer(tenant.Id).User).Service.RequestAsync(tenant.Id, device.Id, DeviceAction.Sync, "r")).Ok);
        Assert.Empty(await h.Actions.QueryAsync(new DeviceActionQuery()));
    }

    [Fact]
    public async Task ADeviceHasOneOpenActionAtATime()
    {
        var h = new Harness();
        var first = await RequestedAsync(h, DeviceAction.Sync, h.Admin);
        var (tenant, device) = await h.RemediationDeviceAsync();

        var second = await h.As(h.Owner1).Service.RequestAsync(tenant.Id, device.Id, DeviceAction.Wipe, "r");

        Assert.False(second.Ok);
        Assert.Equal(first.Id, second.Request!.Id);
        Assert.Single(await h.Actions.QueryAsync(new DeviceActionQuery()));
    }

    // --- Approving ---------------------------------------------------------------------------

    [Fact]
    public async Task AnotherAdminApprovesSyncAndTheApprovalIsAudited()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);

        Assert.False((await h.As(h.Owner1).Service.ApproveAsync(a.Id, null)).Ok); // not your own
        var approved = await h.As(h.Admin).Service.ApproveAsync(a.Id, "Checked with the user");

        Assert.True(approved.Ok, approved.Message);
        Assert.Equal(DeviceActionStatus.Approved, approved.Request!.Status);
        Assert.Equal((h.Admin.UserId, PortalRole.MspAdmin, "Checked with the user"),
            (approved.Request.DecidedByUserId, approved.Request.DecidedByRole, approved.Request.DecisionNote));
        var e = Assert.Single(await h.EventsAsync(AuditActions.DeviceActionApproved));
        Assert.Equal(h.Admin.UserId, e.ActorUserId);
        Assert.Equal("Checked with the user", e.Details["note"]);
    }

    [Theory]
    [InlineData(DeviceAction.Retire)]
    [InlineData(DeviceAction.Wipe)]
    public async Task RetireAndWipeNeedAnotherOwner(DeviceAction action)
    {
        var h = new Harness();
        var a = await RequestedAsync(h, action, h.Owner1);

        var byAdmin = await h.As(h.Admin).Service.ApproveAsync(a.Id, null);
        Assert.False(byAdmin.Ok);
        Assert.Contains("Owner", byAdmin.Message);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await h.Actions.GetAsync(a.Id))!.Status);

        Assert.True((await h.As(h.Owner2).Service.ApproveAsync(a.Id, null)).Ok);
        Assert.Equal(DeviceActionStatus.Approved, (await h.Actions.GetAsync(a.Id))!.Status);
    }

    [Fact]
    public async Task ApprovalIsFailClosedWhenTheAuditLogIsDown()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        h.Audit.Fail = true;

        var outcome = await h.As(h.Admin).Service.ApproveAsync(a.Id, null);

        Assert.False(outcome.Ok);
        Assert.Contains("audit log", outcome.Message);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await h.Actions.GetAsync(a.Id))!.Status);
    }

    [Fact]
    public async Task ExpiredRequestsCantBeApproved()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        h.Time.Advance(DeviceActionPolicy.ApprovalWindow + TimeSpan.FromMinutes(1));

        var outcome = await h.As(h.Admin).Service.ApproveAsync(a.Id, null);

        Assert.False(outcome.Ok);
        Assert.Equal(DeviceActionStatus.PendingApproval, (await h.Actions.GetAsync(a.Id))!.Status); // the Worker marks it expired
        // The audit trail shows the attempt didn't apply.
        Assert.Contains(await h.EventsAsync(AuditActions.DeviceActionApproved), e => e.Outcome == AuditOutcome.Failure);
    }

    [Fact]
    public async Task ApprovalIsRefusedOnceRemediationIsTurnedOff()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        await ((IOnboardingRepository)h.Store).DisableRemediationAsync(a.TenantId);

        Assert.Contains("turned off", (await h.As(h.Admin).Service.ApproveAsync(a.Id, null)).Message);
    }

    // --- Rejecting and cancelling ------------------------------------------------------------

    [Fact]
    public async Task RejectionNeedsAReasonAndAnotherAdmin()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Restart, h.Owner1);

        Assert.False((await h.As(h.Owner1).Service.RejectAsync(a.Id, "changed my mind")).Ok);
        Assert.False((await h.As(h.Admin).Service.RejectAsync(a.Id, " ")).Ok);
        var rejected = await h.As(h.Admin).Service.RejectAsync(a.Id, "Restart during clinic hours");

        Assert.True(rejected.Ok);
        Assert.Equal(DeviceActionStatus.Rejected, rejected.Request!.Status);
        Assert.Single(await h.EventsAsync(AuditActions.DeviceActionRejected));
        Assert.False((await h.As(h.Owner2).Service.ApproveAsync(a.Id, null)).Ok); // decided already
    }

    [Fact]
    public async Task CancelWorksUntilTheWorkerStartsSending()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        Assert.True((await h.As(h.Owner1).Service.CancelAsync(a.Id)).Ok);
        Assert.Single(await h.EventsAsync(AuditActions.DeviceActionCancelled));

        var b = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        await h.As(h.Admin).Service.ApproveAsync(b.Id, null);
        await h.Actions.ClaimNextApprovedAsync(T0);
        Assert.Contains("Too late", (await h.As(h.Owner1).Service.CancelAsync(b.Id)).Message);
        Assert.Equal(DeviceActionStatus.Sending, (await h.Actions.GetAsync(b.Id))!.Status);
    }

    // --- Visibility --------------------------------------------------------------------------

    [Fact]
    public async Task ViewersSeeTheirOwnDeviceHistoryButNotTheQueueOrOtherTenants()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Owner1);
        var other = (await h.Store.GetAllAsync()).First(t => t.Id != a.TenantId);

        Assert.Single(await h.As(FixedUser.Viewer(a.TenantId).User).Service.GetForDeviceAsync(a.TenantId, a.DeviceId));
        Assert.Empty(await h.As(FixedUser.Viewer(a.TenantId).User).Service.GetQueueAsync());
        Assert.Empty(await h.As(FixedUser.Viewer(other.Id).User).Service.GetForDeviceAsync(a.TenantId, a.DeviceId));
        Assert.False((await h.As(FixedUser.Viewer(other.Id).User).Service.CancelAsync(a.Id)).Ok);

        var queue = await h.As(h.Owner1).Service.GetQueueAsync();
        Assert.Contains("own request", Assert.Single(queue).WhyCannotApprove);
        Assert.Null(Assert.Single(await h.As(h.Admin).Service.GetQueueAsync()).WhyCannotApprove);
        Assert.Equal(1, await h.As(h.Admin).Service.CountAwaitingMyApprovalAsync());
        Assert.Equal(0, await h.As(h.Owner1).Service.CountAwaitingMyApprovalAsync());
    }

    // --- Remediation consent from the portal -------------------------------------------------

    private static OnboardingService Onboarding(Harness h, OnboardingOptions? options = null) =>
        new(h.Store, h.Store, h.Store, new OnboardingServiceTests.Resolver(_ => Guid.NewGuid()), new EphemeralDataProtectionProvider(),
            options ?? new OnboardingOptions { AppClientId = Guid.NewGuid().ToString(), RemediationAppClientId = RemediationApp.ToString() },
            h.Time, h.User, h.Trail, NullLogger<OnboardingService>.Instance);

    private static readonly Guid RemediationApp = Guid.Parse("22222222-3333-4444-5555-666666666666");

    [Fact]
    public async Task OwnersStartRemediationConsentWithTheRemediationApp()
    {
        var h = new Harness();
        var tenant = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.ReadOnlyGranted);

        var onboarding = Onboarding(h); // one instance: its data-protection keys decrypt the link it made
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => onboarding.StartRemediationAsync(tenant.Id)); // h.User is an MSP admin
        h.As(h.Owner1);
        var started = await onboarding.StartRemediationAsync(tenant.Id);

        Assert.Null(started.Error);
        var request = started.Request!;
        Assert.Equal(OnboardingKind.Remediation, request.Kind);
        Assert.Equal(tenant.EntraTenantId, request.EntraTenantId);
        var url = onboarding.GetConsentUrl(request, "https://portal.example/");
        Assert.Contains($"client_id={RemediationApp}", url);
        Assert.Contains($"/{tenant.EntraTenantId}/v2.0/adminconsent", url);
        Assert.True((await onboarding.StartRemediationAsync(tenant.Id)).Reused);
        Assert.Contains(await h.EventsAsync(AuditActions.LinkCreated), e => e.Details.GetValueOrDefault("kind") == "remediation");
    }

    [Fact]
    public async Task RemediationNeedsItsOwnAppAndAReadOnlyConnectedTenant()
    {
        var h = new Harness().As(new UserContext(Guid.NewGuid(), PortalRole.Owner, null, "Olivia"));
        var all = await h.Store.GetAllAsync();
        var sameApp = Guid.NewGuid().ToString();

        Assert.Contains("RemediationAppClientId",
            (await Onboarding(h, new OnboardingOptions { AppClientId = sameApp, RemediationAppClientId = sameApp }).StartRemediationAsync(all[0].Id)).Error);
        Assert.Contains("already has", (await Onboarding(h).StartRemediationAsync(all.Single(t => t.CanRemediate).Id)).Error);
        Assert.Contains("connected for assessment first",
            (await Onboarding(h).StartRemediationAsync(all.First(t => t.ConsentState == TenantConsentState.Pending).Id)).Error);
    }

    [Fact]
    public async Task TurningRemediationOffCancelsOpenActionsAndStopsRequests()
    {
        var h = new Harness();
        var a = await RequestedAsync(h, DeviceAction.Sync, h.Admin);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Onboarding(h.As(h.Admin)).DisableRemediationAsync(a.TenantId));
        Assert.True(await Onboarding(h.As(h.Owner1)).DisableRemediationAsync(a.TenantId));

        var tenant = (await h.Store.GetAsync(a.TenantId))!;
        Assert.Equal(TenantConsentState.ReadOnlyGranted, tenant.ConsentState);
        Assert.Null(tenant.RemediationCredentialReference);
        Assert.Equal(DeviceActionStatus.Cancelled, (await h.Actions.GetAsync(a.Id))!.Status);
        Assert.Single(await h.EventsAsync(AuditActions.RemediationDisabled));
        Assert.Single(await h.EventsAsync(AuditActions.DeviceActionCancelled));
        Assert.False((await h.As(h.Admin).Service.RequestAsync(a.TenantId, a.DeviceId, DeviceAction.Sync, "r")).Ok);
        Assert.False(await Onboarding(h.As(h.Owner1)).DisableRemediationAsync(a.TenantId)); // already off
    }
}

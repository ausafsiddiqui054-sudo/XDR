using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Worker;

namespace SecurePulse.Tests.DeviceActions;

public class PlaybookPreApprovalPolicyTests
{
    private static readonly Guid Granter = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static RemediationPlaybook PreApproved(DeviceAction action = DeviceAction.Sync, PlaybookTrigger trigger = PlaybookTrigger.NotCheckedIn) =>
        PlaybookData.Playbook(trigger, action) with
        {
            PreApprovedByUserId = Granter, PreApprovedByName = "Omar Owner", PreApprovedAt = PlaybookData.T0,
            PreApprovalExpiresAt = PlaybookData.T0 + PlaybookPreApproval.Validity
        };

    [Theory]
    [InlineData(DeviceAction.Sync, true)]
    [InlineData(DeviceAction.DefenderQuickScan, true)]
    [InlineData(DeviceAction.DefenderUpdateSignatures, true)]
    [InlineData(DeviceAction.Restart, false)]
    [InlineData(DeviceAction.Retire, false)]
    [InlineData(DeviceAction.Wipe, false)]
    public void OnlyActionsThatDontInterruptAnyoneArePreApprovable(DeviceAction action, bool eligible) =>
        Assert.Equal(eligible, PlaybookPreApproval.IsEligible(action));

    [Fact]
    public void AnotherOwnerGrants_NeverTheEditorOrAnAdmin()
    {
        var p = PlaybookData.Playbook();
        Assert.Null(PlaybookPreApproval.WhyCannotGrant(p, Granter, PortalRole.Owner));
        Assert.Contains("another Owner", PlaybookPreApproval.WhyCannotGrant(p, PlaybookData.Editor, PortalRole.Owner));
        Assert.Contains("Only Owners", PlaybookPreApproval.WhyCannotGrant(p, Granter, PortalRole.MspAdmin));
        Assert.Contains("Only Owners", PlaybookPreApproval.WhyCannotGrant(p, null, PortalRole.Owner));
        Assert.Contains("can't be pre-approved", PlaybookPreApproval.WhyCannotGrant(PlaybookData.Playbook(action: DeviceAction.Restart), Granter, PortalRole.Owner));
        Assert.NotNull(PlaybookPreApproval.WhyCannotGrant(p with { MaxPerRun = 0 }, Granter, PortalRole.Owner));
    }

    [Fact]
    public void APreApprovalIsActiveOnlyWhileEverythingStillHolds()
    {
        var now = PlaybookData.T0.AddDays(10);
        var p = PreApproved();
        Assert.True(PlaybookPreApproval.IsActive(p, now, granterIsOwner: true));

        Assert.False(PlaybookPreApproval.IsActive(p, now, granterIsOwner: false));                                   // demoted or removed
        Assert.False(PlaybookPreApproval.IsActive(p with { Enabled = false }, now, true));
        Assert.False(PlaybookPreApproval.IsActive(p, PlaybookData.T0 + PlaybookPreApproval.Validity, true));          // expired
        Assert.False(PlaybookPreApproval.IsActive(p, PlaybookData.T0.AddMinutes(-1), true));                          // not yet granted
        Assert.False(PlaybookPreApproval.IsActive(p with { PreApprovedByUserId = PlaybookData.Editor }, now, true));  // editor approved own rule
        Assert.False(PlaybookPreApproval.IsActive(p with { PreApprovalExpiresAt = PlaybookData.T0.AddYears(5) }, now, true)); // tampered expiry
        Assert.False(PlaybookPreApproval.IsActive(p with { PreApprovedAt = null }, now, true));
        Assert.False(PlaybookPreApproval.IsActive(PreApproved(DeviceAction.Restart), now, true));                    // not eligible
        Assert.False(PlaybookPreApproval.IsActive(p with { DailyAutoLimit = 0 }, now, true));                          // invalid playbook
    }

    [Fact]
    public void TheDailyLimitIsBounded()
    {
        Assert.Contains("daily limit", PlaybookRules.Problem(PlaybookData.Playbook() with { DailyAutoLimit = 0 }));
        Assert.Contains("daily limit", PlaybookRules.Problem(PlaybookData.Playbook() with { DailyAutoLimit = 101 }));
        Assert.Null(PlaybookRules.Problem(PlaybookData.Playbook() with { DailyAutoLimit = 100 }));
    }
}

/// <summary>Auto-approval in the Worker and the re-check before sending.</summary>
public class PreApprovedPlaybookRunTests
{
    private sealed class Sender : IDeviceActionSender
    {
        public List<(string Device, DeviceAction Action)> Sent { get; } = [];

        public Task<DeviceActionSendResult> SendAsync(Guid entraTenantId, string deviceId, DeviceAction action, string accessToken,
            CancellationToken cancellationToken = default)
        {
            Sent.Add((deviceId, action));
            return Task.FromResult(DeviceActionSendResult.Ok);
        }
    }

    private sealed class Tokens : IRemediationTokenProvider
    {
        public Task<string> GetTokenAsync(Guid entraTenantId, string thumbprint, CancellationToken cancellationToken = default) =>
            Task.FromResult(Jwt.With(entraTenantId, RemediationPermissions.PrivilegedOperations));
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(PlaybookData.T0);
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public Sender Sender { get; } = new();
        public Tenant Tenant { get; private set; } = null!;
        public PortalUser Granter { get; } = new()
        {
            Id = Guid.NewGuid(), Role = PortalRole.Owner, EntraTenantId = Guid.NewGuid(), UserPrincipalName = "omar@msp.example",
            DisplayName = "Omar Owner", CreatedAt = PlaybookData.T0.AddYears(-1)
        };

        public Harness() => Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);

        public PlaybookRunner Runner => new(Store, Store, Store, Audit, Store, Time, NullLogger<PlaybookRunner>.Instance);
        public DeviceActionService Sending => new(Store, Store, new Tokens(), Sender, Audit, Store, Store,
            Options.Create(new DeviceActionOptions()), Time, NullLogger<DeviceActionService>.Instance);
        public IPlaybookRepository Playbooks => Store;
        public IDeviceActionRepository Actions => Store;

        public async Task<Harness> WithDevicesAsync(int count)
        {
            await ((IPortalUserRepository)Store).AddAsync(Granter);
            // A signed-in Owner besides the granter, so the granter can be demoted (the last one can't).
            await ((IPortalUserRepository)Store).AddAsync(new PortalUser
        {
            Id = Guid.NewGuid(), Role = PortalRole.Owner, EntraTenantId = Guid.NewGuid(), UserPrincipalName = "keeper@msp.example",
            ObjectId = Guid.NewGuid(), CreatedAt = PlaybookData.T0.AddYears(-1)
        });
            Tenant = (await Store.GetAllAsync()).Single(t => t.CanRemediate);
            await Store.SaveSyncAsync(new DeviceSyncResult
            {
                TenantId = Tenant.Id, Source = "Intune", StartedAt = Time.Now, CompletedAt = Time.Now,
                Devices = Enumerable.Range(1, count).Select(i => PlaybookData.Device(Tenant.Id, $"PC-{i}", daysSinceSync: 9)).ToList()
            });
            return this;
        }

        public async Task<RemediationPlaybook> PreApprovedPlaybookAsync(int dailyLimit = 25, DeviceAction action = DeviceAction.Sync)
        {
            var p = PlaybookData.Playbook(action: action) with { DailyAutoLimit = dailyLimit };
            await Playbooks.AddAsync(p);
            Assert.True(await Playbooks.GrantPreApprovalAsync(p.Id, p.UpdatedAt, Granter.Id, "Omar Owner <omar@msp.example>", Time.Now,
                Time.Now + PlaybookPreApproval.Validity));
            return (await Playbooks.GetAsync(p.Id))!;
        }

        public async Task<IReadOnlyList<DeviceActionRequest>> RequestsAsync() =>
            (await Actions.QueryAsync(new DeviceActionQuery { TenantId = Tenant.Id })).Where(a => a.PlaybookId is not null).ToList();

        public async Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) => await Store.QueryAsync(new AuditQuery { Action = action });
    }

    [Fact]
    public async Task ProposalsOfAPreApprovedPlaybookAreApproved_UpToTheDailyLimit()
    {
        var h = await new Harness().WithDevicesAsync(3);
        var p = await h.PreApprovedPlaybookAsync(dailyLimit: 2);

        Assert.Equal(3, await h.Runner.RunForTenantAsync(h.Tenant));

        var requests = await h.RequestsAsync();
        var approved = requests.Where(a => a.Status == DeviceActionStatus.Approved).ToList();
        Assert.Equal(2, approved.Count);
        Assert.All(approved, a =>
        {
            Assert.True(a.AutoApproved);
            Assert.Equal(h.Granter.Id, a.DecidedByUserId);
            Assert.Equal(PortalRole.Owner, a.DecidedByRole);
            Assert.Equal("Omar Owner <omar@msp.example> (pre-approved playbook \"Stale devices\")", a.DecidedByName);
            Assert.Contains("valid until 2027-01-13", a.DecisionNote);
            Assert.Equal(PlaybookData.Editor, a.RequestedByUserId); // still four eyes: editor requested, another Owner approved
            Assert.Null(DeviceActionPolicy.WhyCannotApprove(a, a.DecidedByUserId, a.DecidedByRole));
        });
        // Beyond the limit, it waits for a person.
        var waiting = Assert.Single(requests, a => a.Status == DeviceActionStatus.PendingApproval);
        Assert.False(waiting.AutoApproved);

        var events = await h.EventsAsync(AuditActions.DeviceActionAutoApproved);
        Assert.Equal(2, events.Count);
        Assert.All(events, e => Assert.Equal("Playbook \"Stale devices\"", e.ActorName));
        Assert.Equal(p.Id.ToString(), events[0].Details["playbookId"]);

        // The limit counts automatic approvals over a rolling day.
        Assert.Equal(2, await h.Actions.CountAutoApprovedSinceAsync(p.Id, h.Tenant.Id, h.Time.Now.AddDays(-1)));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("expired")]
    [InlineData("demoted")]
    [InlineData("restart")]
    [InlineData("audit-down")]
    public async Task WithoutAValidPreApprovalProposalsWaitForAPerson(string why)
    {
        var h = await new Harness().WithDevicesAsync(2);
        switch (why)
        {
            case "none":
                await h.Playbooks.AddAsync(PlaybookData.Playbook());
                break;
            case "expired":
                await h.PreApprovedPlaybookAsync();
                h.Time.Advance(PlaybookPreApproval.Validity);
                await h.Store.SaveSyncAsync(new DeviceSyncResult
                {
                    TenantId = h.Tenant.Id, Source = "Intune", StartedAt = h.Time.Now, CompletedAt = h.Time.Now,
                    Devices = [PlaybookData.Device(h.Tenant.Id, "PC-X", daysSinceSync: null) with { LastSyncAt = h.Time.Now.AddDays(-9) }]
                });
                break;
            case "demoted":
                await h.PreApprovedPlaybookAsync();
                await ((IPortalUserRepository)h.Store).UpdateRoleAsync(h.Granter.Id, PortalRole.MspAdmin, null);
                break;
            case "restart":
                // Pre-approval fields on a Restart playbook (e.g. a tampered row): Restart is never automatic.
                var r = PlaybookData.Playbook(action: DeviceAction.Restart);
                await h.Playbooks.AddAsync(r);
                await h.Playbooks.GrantPreApprovalAsync(r.Id, r.UpdatedAt, h.Granter.Id, "Omar", h.Time.Now, h.Time.Now.AddDays(30));
                break;
            case "audit-down":
                await h.PreApprovedPlaybookAsync();
                h.Audit.Fail = true; // fail-closed: no audit entry, no automatic approval
                break;
        }

        Assert.True(await h.Runner.RunForTenantAsync(h.Tenant) > 0);
        Assert.All(await h.RequestsAsync(), a =>
        {
            Assert.Equal(DeviceActionStatus.PendingApproval, a.Status);
            Assert.False(a.AutoApproved);
        });
    }

    [Fact]
    public async Task AutoApprovedActionsAreSent_WhileThePreApprovalHolds()
    {
        var h = await new Harness().WithDevicesAsync(1);
        await h.PreApprovedPlaybookAsync();
        await h.Runner.RunForTenantAsync(h.Tenant);

        Assert.Equal(1, await h.Sending.RunOnceAsync());

        Assert.Equal(DeviceActionStatus.Sent, Assert.Single(await h.RequestsAsync()).Status);
        Assert.Equal(DeviceAction.Sync, Assert.Single(h.Sender.Sent).Action);
    }

    [Theory]
    [InlineData("withdrawn", "was withdrawn, expired or no longer matches")]
    [InlineData("demoted", "was withdrawn, expired or no longer matches")]
    [InlineData("changed", "was withdrawn, expired or no longer matches")]
    [InlineData("deleted", "no longer exists")]
    public async Task TheWorkerRechecksThePreApprovalBeforeSending(string change, string expected)
    {
        var h = await new Harness().WithDevicesAsync(1);
        var p = await h.PreApprovedPlaybookAsync();
        await h.Runner.RunForTenantAsync(h.Tenant);
        Assert.Equal(DeviceActionStatus.Approved, Assert.Single(await h.RequestsAsync()).Status);

        switch (change)
        {
            case "withdrawn": await h.Playbooks.WithdrawPreApprovalAsync(p.Id); break;
            case "demoted": await ((IPortalUserRepository)h.Store).UpdateRoleAsync(h.Granter.Id, PortalRole.MspAdmin, null); break;
            case "changed":
                // An edit (as the portal saves it) clears the pre-approval.
                await h.Playbooks.UpdateAsync(p with
                {
                    Days = 3, UpdatedAt = p.UpdatedAt.AddMinutes(1), PreApprovedByUserId = null, PreApprovedByName = null, PreApprovedAt = null,
                    PreApprovalExpiresAt = null
                }, p.UpdatedAt);
                break;
            case "deleted": await h.Playbooks.DeleteAsync(p.Id); break;
        }

        await h.Sending.RunOnceAsync();

        var a = Assert.Single(await h.RequestsAsync());
        Assert.Equal(DeviceActionStatus.Failed, a.Status);
        Assert.Contains(expected, a.Error);
        Assert.Empty(h.Sender.Sent);
    }

    [Fact]
    public async Task ManuallyApprovedPlaybookProposalsDontNeedAPreApproval()
    {
        var h = await new Harness().WithDevicesAsync(1);
        await h.Playbooks.AddAsync(PlaybookData.Playbook());
        await h.Runner.RunForTenantAsync(h.Tenant);
        var pending = Assert.Single(await h.RequestsAsync());
        await h.Actions.DecideAsync(pending.Id, true, Guid.NewGuid(), "Adam Admin", PortalRole.MspAdmin, null, h.Time.Now);

        await h.Sending.RunOnceAsync();

        Assert.Equal(DeviceActionStatus.Sent, Assert.Single(await h.RequestsAsync()).Status);
    }
}

public class PlaybookPreApprovalServiceTests
{
    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(PlaybookData.T0);
        public FixedUser User { get; } = FixedUser.Owner();
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public UserContext Editor { get; }
        public UserContext OtherOwner { get; } = new(Guid.NewGuid(), PortalRole.Owner, null, "Omar Owner <omar@msp.example>");

        public Harness()
        {
            Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);
            Editor = User.User;
        }

        public PlaybookService Service => new(Store, Store, Store, User, Store, new AuditTrail(Audit, User, Time, NullLogger<AuditTrail>.Instance), Time);
        public IPlaybookRepository Playbooks => Store;

        public async Task<RemediationPlaybook> CreateAsync(DeviceAction action = DeviceAction.Sync, PlaybookTrigger trigger = PlaybookTrigger.NotCheckedIn)
        {
            User.User = Editor;
            var created = await Service.CreateAsync(new PlaybookDraft("Stale devices", true, trigger, trigger == PlaybookTrigger.NotCheckedIn ? 7 : null,
                action, null, 20, TimeSpan.FromDays(1), 10));
            Assert.True(created.Ok, created.Message);
            return created.Playbook!;
        }

        public Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) => Store.QueryAsync(new AuditQuery { Action = action });
    }

    [Fact]
    public async Task AnotherOwnerPreApprovesTheVersionTheySaw_Audited()
    {
        var h = new Harness();
        var p = await h.CreateAsync();
        Assert.Equal(10, p.DailyAutoLimit);

        Assert.Contains("another Owner", (await h.Service.PreApproveAsync(p.Id, p.UpdatedAt)).Message); // the editor can't
        h.User.User = FixedUser.MspAdmin().User;
        Assert.Contains("Only Owners", (await h.Service.PreApproveAsync(p.Id, p.UpdatedAt)).Message);

        h.User.User = h.OtherOwner;
        Assert.Contains("changed since you opened it", (await h.Service.PreApproveAsync(p.Id, p.UpdatedAt.AddSeconds(-1))).Message);
        var ok = await h.Service.PreApproveAsync(p.Id, p.UpdatedAt);
        Assert.True(ok.Ok, ok.Message);

        var stored = (await h.Playbooks.GetAsync(p.Id))!;
        Assert.Equal(h.OtherOwner.UserId, stored.PreApprovedByUserId);
        Assert.Equal(PlaybookData.T0 + PlaybookPreApproval.Validity, stored.PreApprovalExpiresAt);
        Assert.Equal(p.UpdatedAt, stored.UpdatedAt); // a grant isn't an edit
        var e = Assert.Single(await h.EventsAsync(AuditActions.PlaybookPreApproved));
        Assert.Equal(h.OtherOwner.Name, e.ActorName);
        Assert.Equal(h.Editor.Name, e.Details["lastEditor"]);
        Assert.Equal("10", e.Details["dailyAutoLimit"]);
    }

    [Fact]
    public async Task PreApprovalIsFailClosedOnTheAuditLog()
    {
        var h = new Harness();
        var p = await h.CreateAsync();
        h.User.User = h.OtherOwner;
        h.Audit.Fail = true;

        var result = await h.Service.PreApproveAsync(p.Id, p.UpdatedAt);

        Assert.False(result.Ok);
        Assert.Contains("audit log", result.Message);
        Assert.Null((await h.Playbooks.GetAsync(p.Id))!.PreApprovedByUserId);
    }

    [Fact]
    public async Task RestartPlaybooksCantBePreApproved()
    {
        var h = new Harness();
        var p = await h.CreateAsync(DeviceAction.Restart);
        h.User.User = h.OtherOwner;
        Assert.Contains("can't be pre-approved", (await h.Service.PreApproveAsync(p.Id, p.UpdatedAt)).Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnySaveWithdrawsThePreApproval_EvenSwitchingItOff(bool toggleOnly)
    {
        var h = new Harness();
        var p = await h.CreateAsync();
        h.User.User = h.OtherOwner;
        Assert.True((await h.Service.PreApproveAsync(p.Id, p.UpdatedAt)).Ok);

        h.User.User = h.Editor;
        h.Time.Advance(TimeSpan.FromMinutes(1));
        var saved = toggleOnly
            ? await h.Service.SetEnabledAsync(p.Id, false, p.UpdatedAt)
            : await h.Service.UpdateAsync(p.Id, new PlaybookDraft("Stale devices", true, PlaybookTrigger.NotCheckedIn, 3, DeviceAction.Sync, null, 20,
                TimeSpan.FromDays(1), 10), p.UpdatedAt);
        Assert.True(saved.Ok, saved.Message);
        Assert.Contains("pre-approval was withdrawn", saved.Message);

        Assert.Null((await h.Playbooks.GetAsync(p.Id))!.PreApprovedByUserId);
        var e = Assert.Single(await h.EventsAsync(AuditActions.PlaybookPreApprovalWithdrawn));
        Assert.Equal("changed", e.Details["reason"]);
    }

    [Fact]
    public async Task OperatorsCanWithdraw_ViewersCant()
    {
        var h = new Harness();
        var p = await h.CreateAsync();
        h.User.User = h.OtherOwner;
        await h.Service.PreApproveAsync(p.Id, p.UpdatedAt);

        h.User.User = FixedUser.Viewer(Guid.NewGuid()).User;
        Assert.False((await h.Service.WithdrawPreApprovalAsync(p.Id)).Ok);
        Assert.NotNull((await h.Playbooks.GetAsync(p.Id))!.PreApprovedByUserId);

        h.User.User = FixedUser.MspAdmin().User;
        Assert.True((await h.Service.WithdrawPreApprovalAsync(p.Id)).Ok);
        Assert.Null((await h.Playbooks.GetAsync(p.Id))!.PreApprovedByUserId);
        Assert.Equal("withdrawn", Assert.Single(await h.EventsAsync(AuditActions.PlaybookPreApprovalWithdrawn)).Details["reason"]);
        Assert.Equal("It wasn't pre-approved.", (await h.Service.WithdrawPreApprovalAsync(p.Id)).Message);
    }

    [Fact]
    public async Task ThePageShowsWhetherItsActiveAndWhoCanPreApprove()
    {
        var h = new Harness();
        var p = await h.CreateAsync();
        await ((IPortalUserRepository)h.Store).AddAsync(new PortalUser
        {
            Id = h.OtherOwner.UserId!.Value, Role = PortalRole.Owner, EntraTenantId = Guid.NewGuid(), UserPrincipalName = "omar@msp.example",
            CreatedAt = PlaybookData.T0
        });

        var asEditor = Assert.Single(await h.Service.GetAllAsync());
        Assert.False(asEditor.PreApprovalActive);
        Assert.Contains("another Owner", asEditor.WhyCannotPreApprove);

        h.User.User = h.OtherOwner;
        Assert.Null(Assert.Single(await h.Service.GetAllAsync()).WhyCannotPreApprove);
        await h.Service.PreApproveAsync(p.Id, p.UpdatedAt);
        Assert.True(Assert.Single(await h.Service.GetAllAsync()).PreApprovalActive);

        await ((IPortalUserRepository)h.Store).AddAsync(new PortalUser
        {
            Id = Guid.NewGuid(), Role = PortalRole.Owner, EntraTenantId = Guid.NewGuid(), UserPrincipalName = "keeper@msp.example",
            ObjectId = Guid.NewGuid(), CreatedAt = PlaybookData.T0.AddYears(-1)
        });
        await ((IPortalUserRepository)h.Store).UpdateRoleAsync(h.OtherOwner.UserId!.Value, PortalRole.MspAdmin, null);
        Assert.False(Assert.Single(await h.Service.GetAllAsync()).PreApprovalActive); // shown as no longer valid
    }
}

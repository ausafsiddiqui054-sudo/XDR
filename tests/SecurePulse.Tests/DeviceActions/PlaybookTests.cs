using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Security;
using SecurePulse.Web.Services;
using SecurePulse.Worker;

namespace SecurePulse.Tests.DeviceActions;

internal static class PlaybookData
{
    public static readonly DateTimeOffset T0 = new(2026, 10, 15, 9, 0, 0, TimeSpan.Zero);
    public static readonly Guid Editor = Guid.Parse("11111111-1111-1111-1111-111111111111");

    public static RemediationPlaybook Playbook(PlaybookTrigger trigger = PlaybookTrigger.NotCheckedIn, DeviceAction action = DeviceAction.Sync,
        int? days = 7, Guid? tenantId = null, bool enabled = true, int maxPerRun = 20) => new()
    {
        Id = Guid.NewGuid(), Name = "Stale devices", Enabled = enabled, Trigger = trigger,
        Days = trigger == PlaybookTrigger.NotCheckedIn ? days : null, Action = action, TenantId = tenantId, MaxPerRun = maxPerRun,
        Cooldown = TimeSpan.FromDays(1), CreatedAt = T0, UpdatedAt = T0, UpdatedByUserId = Editor, UpdatedByName = "Olivia Owner <olivia@msp.example>"
    };

    public static Tenant Tenant(bool remediation = true) => new()
    {
        Id = Guid.NewGuid(), EntraTenantId = Guid.NewGuid(), DisplayName = "Creek Physio", PrimaryDomain = "creek.example",
        ConsentState = remediation ? TenantConsentState.RemediationGranted : TenantConsentState.ReadOnlyGranted,
        CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567",
        RemediationCredentialReference = remediation ? "FEDCBA9876543210FEDCBA9876543210FEDCBA98" : null
    };

    public static ManagedDevice Device(Guid tenantId, string name, DevicePlatform platform = DevicePlatform.Windows, int? daysSinceSync = 0,
        DeviceComplianceState compliance = DeviceComplianceState.Compliant, DefenderAntivirusStatus? av = null) => new()
    {
        Id = Guid.NewGuid().ToString(), TenantId = tenantId, DeviceName = name, Platform = platform, ComplianceState = compliance,
        LastSyncAt = daysSinceSync is { } d ? T0.AddDays(-d) : null,
        DefenderDetails = av is null ? null : new DefenderHealth { Antivirus = av }
    };
}

public class PlaybookRulesTests
{
    [Fact]
    public void AValidPlaybookHasNoProblem() => Assert.Null(PlaybookRules.Problem(PlaybookData.Playbook()));

    [Theory]
    [InlineData(DeviceAction.Retire)]
    [InlineData(DeviceAction.Wipe)]
    public void DestructiveActionsAreNeverAutomated(DeviceAction action)
    {
        foreach (var trigger in Enum.GetValues<PlaybookTrigger>())
        {
            Assert.DoesNotContain(action, PlaybookRules.ActionsFor(trigger));
            Assert.Contains("can't be automated", PlaybookRules.Problem(PlaybookData.Playbook(trigger, action)));
        }
    }

    [Fact]
    public void TheActionMustFitTheTrigger()
    {
        Assert.Contains("isn't an action for this trigger", PlaybookRules.Problem(PlaybookData.Playbook(PlaybookTrigger.DefenderQuickScanOverdue, DeviceAction.Restart)));
        Assert.Null(PlaybookRules.Problem(PlaybookData.Playbook(PlaybookTrigger.DefenderQuickScanOverdue, DeviceAction.DefenderQuickScan)));
        Assert.Null(PlaybookRules.Problem(PlaybookData.Playbook(PlaybookTrigger.DefenderSignaturesOutOfDate, DeviceAction.DefenderUpdateSignatures)));
    }

    [Fact]
    public void OtherLimits()
    {
        var p = PlaybookData.Playbook();
        Assert.Contains("name", PlaybookRules.Problem(p with { Name = " " }));
        Assert.Contains("under 100", PlaybookRules.Problem(p with { Name = new string('x', 101) }));
        Assert.Contains("between 1 and 90", PlaybookRules.Problem(p with { Days = null }));
        Assert.Contains("between 1 and 90", PlaybookRules.Problem(p with { Days = 91 }));
        Assert.Contains("only applies", PlaybookRules.Problem(PlaybookData.Playbook(PlaybookTrigger.Noncompliant) with { Days = 3 }));
        Assert.Contains("between 1 and 100", PlaybookRules.Problem(p with { MaxPerRun = 0 }));
        Assert.Contains("between 1 and 100", PlaybookRules.Problem(p with { MaxPerRun = 101 }));
        Assert.Contains("cooldown", PlaybookRules.Problem(p with { Cooldown = TimeSpan.FromMinutes(30) }));
        Assert.Contains("cooldown", PlaybookRules.Problem(p with { Cooldown = TimeSpan.FromDays(31) }));
        Assert.Contains("trigger", PlaybookRules.Problem(p with { Trigger = (PlaybookTrigger)42 }));
    }

    [Fact]
    public void DefenderActionsAreWindowsOnly()
    {
        Assert.True(DeviceActionPolicy.AppliesTo(DeviceAction.DefenderQuickScan, DevicePlatform.Windows));
        Assert.False(DeviceActionPolicy.AppliesTo(DeviceAction.DefenderQuickScan, DevicePlatform.MacOS));
        Assert.False(DeviceActionPolicy.AppliesTo(DeviceAction.DefenderUpdateSignatures, DevicePlatform.iOS));
        Assert.True(DeviceActionPolicy.AppliesTo(DeviceAction.Sync, DevicePlatform.Android));
        Assert.False(DeviceActionPolicy.IsDestructive(DeviceAction.DefenderQuickScan));
    }
}

public class PlaybookEvaluatorTests
{
    private static readonly IReadOnlySet<string> None = new HashSet<string>();

    [Fact]
    public void NotCheckedIn_MatchesDevicesSilentForTheDays_InNameOrder()
    {
        var tenant = PlaybookData.Tenant();
        var devices = new[]
        {
            PlaybookData.Device(tenant.Id, "ZED-PC", daysSinceSync: 30), PlaybookData.Device(tenant.Id, "alpha-pc", daysSinceSync: 7),
            PlaybookData.Device(tenant.Id, "FRESH-PC", daysSinceSync: 6), PlaybookData.Device(tenant.Id, "NEVER", daysSinceSync: null)
        };

        var proposals = PlaybookEvaluator.Evaluate(PlaybookData.Playbook(), tenant, devices, None, PlaybookData.T0);

        Assert.Equal(["alpha-pc", "ZED-PC"], proposals.Select(p => p.Device.DeviceName));
        Assert.Equal("Playbook \"Stale devices\": hasn't checked in with Intune for 7 days (last 2026-10-08).", proposals[0].Reason);
    }

    [Theory]
    [InlineData(PlaybookTrigger.Noncompliant, DeviceAction.Sync, "noncompliant")]
    [InlineData(PlaybookTrigger.DefenderSignaturesOutOfDate, DeviceAction.DefenderUpdateSignatures, "out of date (version 1.419.5)")]
    [InlineData(PlaybookTrigger.DefenderQuickScanOverdue, DeviceAction.DefenderQuickScan, "overdue (last 2026-09-30)")]
    [InlineData(PlaybookTrigger.DefenderRebootRequired, DeviceAction.Restart, "needs a restart")]
    public void EachTrigger_MatchesOnlyTheDeviceWithThatCondition(PlaybookTrigger trigger, DeviceAction action, string reason)
    {
        var tenant = PlaybookData.Tenant();
        var healthy = PlaybookData.Device(tenant.Id, "HEALTHY", av: new DefenderAntivirusStatus
        {
            SignaturesOutOfDate = false, QuickScanOverdue = false, RebootRequired = false, ThreatState = DefenderThreatState.Clean
        });
        var sick = PlaybookData.Device(tenant.Id, "SICK", compliance: DeviceComplianceState.Noncompliant, av: new DefenderAntivirusStatus
        {
            SignaturesOutOfDate = true, SignatureVersion = "1.419.5", QuickScanOverdue = true, LastQuickScanAt = new(2026, 9, 30, 8, 0, 0, TimeSpan.Zero),
            RebootRequired = true
        });

        var proposal = Assert.Single(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(trigger, action), tenant, [healthy, sick], None, PlaybookData.T0));

        Assert.Equal("SICK", proposal.Device.DeviceName);
        Assert.Contains(reason, proposal.Reason);
    }

    [Fact]
    public void ARebootPendingThreatStateAlsoMeansRestart()
    {
        var tenant = PlaybookData.Tenant();
        var d = PlaybookData.Device(tenant.Id, "PC", av: new DefenderAntivirusStatus { ThreatState = DefenderThreatState.RebootPending });
        Assert.Single(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(PlaybookTrigger.DefenderRebootRequired, DeviceAction.Restart), tenant, [d], None, PlaybookData.T0));
    }

    [Fact]
    public void DefenderActionsSkipDevicesThatArentWindows()
    {
        var tenant = PlaybookData.Tenant();
        var av = new DefenderAntivirusStatus { QuickScanOverdue = true };
        var devices = new[] { PlaybookData.Device(tenant.Id, "MAC", DevicePlatform.MacOS, av: av), PlaybookData.Device(tenant.Id, "WIN", av: av) };

        var proposal = Assert.Single(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(PlaybookTrigger.DefenderQuickScanOverdue, DeviceAction.DefenderQuickScan),
            tenant, devices, None, PlaybookData.T0));
        Assert.Equal("WIN", proposal.Device.DeviceName);
    }

    [Fact]
    public void CooldownCapScopeAndSwitches()
    {
        var tenant = PlaybookData.Tenant();
        var devices = Enumerable.Range(1, 5).Select(i => PlaybookData.Device(tenant.Id, $"PC-{i}", daysSinceSync: 10)).ToList();

        // Recently proposed devices are left alone.
        var recent = new HashSet<string> { devices[0].Id, devices[1].Id };
        Assert.Equal(["PC-3", "PC-4", "PC-5"], PlaybookEvaluator.Evaluate(PlaybookData.Playbook(), tenant, devices, recent, PlaybookData.T0).Select(p => p.Device.DeviceName));

        // At most MaxPerRun.
        Assert.Equal(2, PlaybookEvaluator.Evaluate(PlaybookData.Playbook(maxPerRun: 2), tenant, devices, None, PlaybookData.T0).Count);

        // Off, another tenant's playbook, no remediation access, or an invalid playbook: nothing.
        Assert.Empty(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(enabled: false), tenant, devices, None, PlaybookData.T0));
        Assert.Empty(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(tenantId: Guid.NewGuid()), tenant, devices, None, PlaybookData.T0));
        Assert.Equal(5, PlaybookEvaluator.Evaluate(PlaybookData.Playbook(tenantId: tenant.Id), tenant, devices, None, PlaybookData.T0).Count);
        Assert.Empty(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(), tenant with { ConsentState = TenantConsentState.ReadOnlyGranted }, devices, None, PlaybookData.T0));
        Assert.Empty(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(action: DeviceAction.Wipe), tenant, devices, None, PlaybookData.T0));

        // Another tenant's devices never match.
        var other = PlaybookData.Device(Guid.NewGuid(), "OTHER", daysSinceSync: 10);
        Assert.DoesNotContain(PlaybookEvaluator.Evaluate(PlaybookData.Playbook(), tenant, [other], None, PlaybookData.T0), p => p.Device.DeviceName == "OTHER");
    }

    [Fact]
    public void LongNamesKeepTheReasonWithinTheLimit()
    {
        var tenant = PlaybookData.Tenant();
        var p = PlaybookData.Playbook() with { Name = new string('n', 100) };
        var proposal = Assert.Single(PlaybookEvaluator.Evaluate(p, tenant, [PlaybookData.Device(tenant.Id, "PC", daysSinceSync: 9)], None, PlaybookData.T0));
        Assert.True(proposal.Reason.Length <= DeviceActionPolicy.MaxReasonLength);
    }
}

public class PlaybookRunnerTests
{
    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(PlaybookData.T0);
        public DeviceActionRequestServiceTests.FlakyAuditLog Audit { get; }
        public Tenant Tenant { get; private set; } = null!;

        public Harness() => Audit = new DeviceActionRequestServiceTests.FlakyAuditLog(Store);

        public PlaybookRunner Runner => new(Store, Store, Store, Audit, Time, NullLogger<PlaybookRunner>.Instance);
        public IPlaybookRepository Playbooks => Store;
        public IDeviceActionRepository Actions => Store;

        /// <summary>The sample remediation tenant, with exactly these devices.</summary>
        public async Task<Harness> WithDevicesAsync(params Func<Guid, ManagedDevice>[] devices)
        {
            Tenant = (await Store.GetAllAsync()).Single(t => t.CanRemediate);
            await Store.SaveSyncAsync(new DeviceSyncResult
            {
                TenantId = Tenant.Id, Source = "Intune", StartedAt = Time.Now, CompletedAt = Time.Now, Devices = devices.Select(d => d(Tenant.Id)).ToList()
            });
            return this;
        }

        public async Task<IReadOnlyList<DeviceActionRequest>> ProposalsAsync() =>
            (await Actions.QueryAsync(new DeviceActionQuery { TenantId = Tenant.Id })).Where(a => a.PlaybookId is not null).ToList();
    }

    [Fact]
    public async Task MatchingDevicesGetPendingRequests_InTheEditorsName_Audited()
    {
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-1", daysSinceSync: 9), t => PlaybookData.Device(t, "FRESH", daysSinceSync: 1));
        var playbook = PlaybookData.Playbook();
        await h.Playbooks.AddAsync(playbook);

        Assert.Equal(1, await h.Runner.RunForTenantAsync(h.Tenant));

        var a = Assert.Single(await h.ProposalsAsync());
        Assert.Equal(DeviceActionStatus.PendingApproval, a.Status);
        Assert.Equal(DeviceAction.Sync, a.Action);
        Assert.Equal("STALE-1", a.DeviceName);
        Assert.Equal(playbook.Id, a.PlaybookId);
        Assert.Equal(PlaybookData.Editor, a.RequestedByUserId);
        Assert.Equal("Olivia Owner <olivia@msp.example> (playbook \"Stale devices\")", a.RequestedByName);
        Assert.Equal(PlaybookData.T0 + DeviceActionPolicy.ApprovalWindow, a.ExpiresAt);
        Assert.StartsWith("Playbook \"Stale devices\": hasn't checked in", a.Reason);

        // Four eyes: whoever saved the playbook can't approve its proposals; someone else can.
        Assert.Contains("own request", DeviceActionPolicy.WhyCannotApprove(a, PlaybookData.Editor, PortalRole.Owner));
        Assert.Null(DeviceActionPolicy.WhyCannotApprove(a, Guid.NewGuid(), PortalRole.MspAdmin));

        var e = Assert.Single((await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.DeviceActionRequested })));
        Assert.Equal("Playbook \"Stale devices\"", e.ActorName);
        Assert.Equal(a.Id.ToString(), e.TargetId);
        Assert.Equal(playbook.Id.ToString(), e.Details["playbookId"]);
        Assert.Equal(PlaybookData.T0, (await h.Playbooks.GetAsync(playbook.Id))!.LastRunAt);
    }

    [Fact]
    public async Task TheCooldownAndOpenActionsPreventRepeats()
    {
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-1", daysSinceSync: 9));
        await h.Playbooks.AddAsync(PlaybookData.Playbook());

        Assert.Equal(1, await h.Runner.RunForTenantAsync(h.Tenant));
        var first = Assert.Single(await h.ProposalsAsync());
        await h.Actions.DecideAsync(first.Id, approve: false, Guid.NewGuid(), "Adam", PortalRole.MspAdmin, "not now", h.Time.Now);

        // Rejected an hour ago: still within the one-day cooldown.
        h.Time.Advance(TimeSpan.FromHours(1));
        Assert.Equal(0, await h.Runner.RunForTenantAsync(h.Tenant));

        // After the cooldown it's proposed again.
        h.Time.Advance(TimeSpan.FromDays(1));
        Assert.Equal(1, await h.Runner.RunForTenantAsync(h.Tenant));
        Assert.Equal(2, (await h.ProposalsAsync()).Count);
    }

    [Fact]
    public async Task ADeviceWithAnOpenActionIsLeftAlone()
    {
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-1", daysSinceSync: 9));
        var device = (await ((IDeviceRepository)h.Store).GetForTenantAsync(h.Tenant.Id))[0];
        await h.Actions.AddAsync(new DeviceActionRequest
        {
            Id = Guid.NewGuid(), TenantId = h.Tenant.Id, DeviceId = device.Id, DeviceName = device.DeviceName, Action = DeviceAction.Restart, Reason = "manual",
            Status = DeviceActionStatus.PendingApproval, RequestedAt = h.Time.Now, RequestedByUserId = Guid.NewGuid(), RequestedByName = "Adam",
            ExpiresAt = h.Time.Now.AddDays(1)
        });
        await h.Playbooks.AddAsync(PlaybookData.Playbook());

        Assert.Equal(0, await h.Runner.RunForTenantAsync(h.Tenant));
        Assert.Empty(await h.ProposalsAsync());
        Assert.Empty(await h.Store.QueryAsync(new AuditQuery { Action = AuditActions.DeviceActionRequested }));
    }

    [Fact]
    public async Task NothingForTenantsWithoutRemediation_OrWithoutEnabledPlaybooks()
    {
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-1", daysSinceSync: 9));
        await h.Playbooks.AddAsync(PlaybookData.Playbook(enabled: false));
        Assert.Equal(0, await h.Runner.RunForTenantAsync(h.Tenant));

        await h.Playbooks.AddAsync(PlaybookData.Playbook());
        Assert.Equal(0, await h.Runner.RunForTenantAsync(h.Tenant with { ConsentState = TenantConsentState.ReadOnlyGranted, RemediationCredentialReference = null }));
        Assert.Empty(await h.ProposalsAsync());
    }

    [Fact]
    public async Task AFailedAuditWrite_KeepsTheProposal_BecauseNothingWasSent()
    {
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-1", daysSinceSync: 9));
        await h.Playbooks.AddAsync(PlaybookData.Playbook());
        h.Audit.Fail = true;

        Assert.Equal(1, await h.Runner.RunForTenantAsync(h.Tenant));
        Assert.Equal(DeviceActionStatus.PendingApproval, Assert.Single(await h.ProposalsAsync()).Status);
    }

    [Fact]
    public async Task TheDeviceSyncRunsPlaybooksOnlyAfterASuccessfulSync()
    {
        // The stored inventory already has a stale device: a failed sync must not act on that old data.
        var h = await new Harness().WithDevicesAsync(t => PlaybookData.Device(t, "STALE-OLD", daysSinceSync: 9));
        await h.Playbooks.AddAsync(PlaybookData.Playbook());
        var succeed = true;
        var source = new Source(t => succeed
            ? new DeviceSyncResult { TenantId = t.Id, Source = "Intune", StartedAt = h.Time.Now, CompletedAt = h.Time.Now,
                Devices = [PlaybookData.Device(t.Id, "STALE-1", daysSinceSync: 9)] }
            : new DeviceSyncResult { TenantId = t.Id, Source = "Intune", StartedAt = h.Time.Now, CompletedAt = h.Time.Now, Devices = [],
                Succeeded = false, Error = "Graph down" });
        var sync = new DeviceSyncService(h.Store, h.Store, source, Options.Create(new DeviceSyncOptions()), NullLogger<DeviceSyncService>.Instance, h.Runner);

        succeed = false;
        Assert.False(await sync.SyncTenantAsync(h.Tenant));
        Assert.Empty(await h.ProposalsAsync());

        succeed = true;
        Assert.True(await sync.SyncTenantAsync(h.Tenant));
        Assert.Equal("STALE-1", Assert.Single(await h.ProposalsAsync()).DeviceName);

        // Without a runner (Playbooks:Enabled = false) the sync still works and proposes nothing.
        var plain = new DeviceSyncService(h.Store, h.Store, source, Options.Create(new DeviceSyncOptions()), NullLogger<DeviceSyncService>.Instance);
        h.Time.Advance(TimeSpan.FromDays(2));
        Assert.True(await plain.SyncTenantAsync(h.Tenant));
        Assert.Single(await h.ProposalsAsync());
    }

    private sealed class Source(Func<Tenant, DeviceSyncResult> sync) : IDeviceInventorySource
    {
        public string Name => "Intune";
        public Task<DeviceSyncResult> GetDevicesAsync(Tenant tenant, CancellationToken cancellationToken = default) => Task.FromResult(sync(tenant));
    }
}

public class PlaybookServiceTests
{
    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(PlaybookData.T0);
        public FixedUser User { get; } = FixedUser.Owner();
        public PlaybookService Service => new(Store, Store, Store, User, new AuditTrail(Store, User, Time, NullLogger<AuditTrail>.Instance), Time);

        public async Task<IReadOnlyList<AuditEvent>> EventsAsync(string action) => await Store.QueryAsync(new AuditQuery { Action = action });
    }

    private static PlaybookDraft Draft(string name = "Stale devices", bool enabled = true, PlaybookTrigger trigger = PlaybookTrigger.NotCheckedIn,
        int? days = 7, DeviceAction action = DeviceAction.Sync, Guid? tenantId = null) =>
        new(name, enabled, trigger, days, action, tenantId, 20, TimeSpan.FromDays(1));

    [Fact]
    public async Task OwnersCreate_ChangeAndDelete_EachAudited()
    {
        var h = new Harness();

        var created = await h.Service.CreateAsync(Draft(name: "  Stale devices  "));
        Assert.True(created.Ok, created.Message);
        var p = created.Playbook!;
        Assert.Equal("Stale devices", p.Name);
        Assert.Equal(h.User.User.UserId, p.UpdatedByUserId);
        Assert.Equal(h.User.User.Name, p.UpdatedByName);
        var e = Assert.Single(await h.EventsAsync(AuditActions.PlaybookCreated));
        Assert.Equal("Sync", e.Details["action"]);
        Assert.Equal("NotCheckedIn", e.Details["trigger"]);
        Assert.Equal("7", e.Details["days"]);
        Assert.Equal("all", e.Details["tenantId"]);

        // A second Owner edits: future proposals are in their name.
        var other = FixedUser.Owner().User with { Name = "Omar Owner <omar@msp.example>" };
        h.User.User = other;
        h.Time.Advance(TimeSpan.FromMinutes(5));
        var changed = await h.Service.UpdateAsync(p.Id, Draft(days: 14), p.UpdatedAt);
        Assert.True(changed.Ok, changed.Message);
        var stored = (await ((IPlaybookRepository)h.Store).GetAsync(p.Id))!;
        Assert.Equal(14, stored.Days);
        Assert.Equal(other.UserId, stored.UpdatedByUserId);
        var c = Assert.Single(await h.EventsAsync(AuditActions.PlaybookChanged));
        Assert.Contains("7 days", c.Details["previous"]);
        Assert.Contains("14 days", c.Summary);

        Assert.True((await h.Service.DeleteAsync(p.Id)).Ok);
        Assert.Null(await ((IPlaybookRepository)h.Store).GetAsync(p.Id));
        Assert.Single(await h.EventsAsync(AuditActions.PlaybookDeleted));
        Assert.Equal("Remediation playbooks", AuditActions.Categories[AuditActions.CategoryOf(AuditActions.PlaybookDeleted)]);
    }

    [Fact]
    public async Task MspAdminsAndViewersCantChangePlaybooks()
    {
        var h = new Harness();
        var p = (await h.Service.CreateAsync(Draft())).Playbook!;

        foreach (var user in new[] { FixedUser.MspAdmin().User, FixedUser.Viewer(Guid.NewGuid()).User })
        {
            h.User.User = user;
            Assert.False((await h.Service.CreateAsync(Draft())).Ok);
            Assert.False((await h.Service.UpdateAsync(p.Id, Draft(enabled: false), p.UpdatedAt)).Ok);
            Assert.False((await h.Service.SetEnabledAsync(p.Id, false, p.UpdatedAt)).Ok);
            Assert.False((await h.Service.DeleteAsync(p.Id)).Ok);
        }
        Assert.True((await ((IPlaybookRepository)h.Store).GetAsync(p.Id))!.Enabled);

        h.User.User = FixedUser.MspAdmin().User;
        Assert.Single(await h.Service.GetAllAsync()); // admins can see them
        h.User.User = FixedUser.Viewer(Guid.NewGuid()).User;
        Assert.Empty(await h.Service.GetAllAsync());
    }

    [Fact]
    public async Task InvalidPlaybooksAndStaleEditsAreRefused()
    {
        var h = new Harness();
        Assert.Contains("can't be automated", (await h.Service.CreateAsync(Draft(action: DeviceAction.Wipe))).Message);
        Assert.Contains("isn't an action", (await h.Service.CreateAsync(Draft(trigger: PlaybookTrigger.DefenderQuickScanOverdue))).Message);
        Assert.Equal("Tenant not found.", (await h.Service.CreateAsync(Draft(tenantId: Guid.NewGuid()))).Message);
        Assert.Empty(await h.EventsAsync(AuditActions.PlaybookCreated));

        var p = (await h.Service.CreateAsync(Draft())).Playbook!;
        h.Time.Advance(TimeSpan.FromMinutes(1));
        Assert.True((await h.Service.UpdateAsync(p.Id, Draft(days: 10), p.UpdatedAt)).Ok);
        // A second editor still holding the old version doesn't overwrite the change.
        var stale = await h.Service.UpdateAsync(p.Id, Draft(days: 3), p.UpdatedAt);
        Assert.False(stale.Ok);
        Assert.Contains("Someone else changed", stale.Message);
        Assert.Equal(10, (await ((IPlaybookRepository)h.Store).GetAsync(p.Id))!.Days);
    }

    [Fact]
    public async Task DaysAreDroppedForOtherTriggers_AndTheTogglePreservesTheRest()
    {
        var h = new Harness();
        var p = (await h.Service.CreateAsync(Draft(trigger: PlaybookTrigger.DefenderQuickScanOverdue, action: DeviceAction.DefenderQuickScan, days: 7))).Playbook!;
        Assert.Null(p.Days);

        h.Time.Advance(TimeSpan.FromMinutes(1));
        var off = await h.Service.SetEnabledAsync(p.Id, false, p.UpdatedAt);
        Assert.True(off.Ok, off.Message);
        var stored = (await ((IPlaybookRepository)h.Store).GetAsync(p.Id))!;
        Assert.False(stored.Enabled);
        Assert.Equal((p.Trigger, p.Action, p.MaxPerRun, p.Cooldown), (stored.Trigger, stored.Action, stored.MaxPerRun, stored.Cooldown));
        Assert.Equal("false", Assert.Single(await h.EventsAsync(AuditActions.PlaybookChanged)).Details["enabled"]);
    }

    [Fact]
    public async Task ThePageShowsRecentAndWaitingProposals()
    {
        var h = new Harness();
        var p = (await h.Service.CreateAsync(Draft())).Playbook!;
        var tenant = (await h.Store.GetAllAsync()).Single(t => t.CanRemediate);
        foreach (var (days, status) in new[] { (1, DeviceActionStatus.PendingApproval), (3, DeviceActionStatus.Rejected), (9, DeviceActionStatus.Expired) })
            await ((IDeviceActionRepository)h.Store).AddAsync(new DeviceActionRequest
            {
                Id = Guid.NewGuid(), TenantId = tenant.Id, DeviceId = Guid.NewGuid().ToString(), DeviceName = "PC", Action = DeviceAction.Sync, Reason = "r",
                Status = status, RequestedAt = h.Time.Now.AddDays(-days), RequestedByUserId = Guid.NewGuid(), RequestedByName = "x",
                ExpiresAt = h.Time.Now.AddDays(1), PlaybookId = p.Id
            });

        var view = Assert.Single(await h.Service.GetAllAsync());
        Assert.Equal(2, view.ProposedLastWeek);
        Assert.Equal(1, view.WaitingForApproval);
        Assert.Equal("Every tenant with remediation access", view.Scope);
    }
}

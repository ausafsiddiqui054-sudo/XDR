using Microsoft.Extensions.Logging.Abstractions;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Playbooks;
using SecurePulse.Tests.DeviceActions;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Services;

namespace SecurePulse.Tests.Demo;

public class DemoSampleDataTests
{
    [Fact]
    public async Task TheFullDemo_HasEveryEngine_ScanHistory_AndATenantThatTakesConfigurationFixes()
    {
        var store = new SampleDataStore(fullDemo: true);
        var tenants = await ((ITenantRepository)store).GetAllAsync();
        var alNoor = tenants.Single(t => t.DisplayName == "Al Noor Family Clinic");
        Assert.True(alNoor.CanConfigure);
        Assert.Equal(("alnoor", true), (alNoor.WazuhAgentGroup, alNoor.GoPhishEnabled));
        Assert.True(tenants.Single(t => t.DisplayName == "Creek Physio Center").CanRemediate);
        Assert.All(tenants.Where(t => t.ConsentState != TenantConsentState.Pending), t => Assert.True(ScanRequestService.IsOnboarded(t)));
        Assert.False(ScanRequestService.IsOnboarded(tenants.Single(t => t.ConsentState == TenantConsentState.Pending)));

        var findings = await ((IFindingRepository)store).GetForTenantAsync(alNoor.Id);
        Assert.Contains(findings, f => f.Source == ScanEngines.Wazuh && f.Status == FindingStatus.Failed && f.Evidence!.Contains("agents"));
        Assert.Contains(findings, f => f.Source == ScanEngines.GoPhish && f.Status == FindingStatus.Failed);
        Assert.DoesNotContain(findings, f => f.Source == ScanEngines.GoPhish && f.Evidence!.Contains('@')); // totals only, never who
        // Failed checks with a catalog fix, so "Propose this fix" shows.
        Assert.Contains(findings, f => f.Status == FindingStatus.Failed && ConfigurationFixes.ForCheck(f.SourceCheckId) == ConfigurationFixes.BlockLegacyAuth);
        Assert.Contains(findings, f => f.Status == FindingStatus.Failed && ConfigurationFixes.ForCheck(f.SourceCheckId) == ConfigurationFixes.PhishingResistantMfaForAdmins);

        var runs = (await ((IScanRunRepository)store).GetLatestAsync()).Where(r => r.TenantId == alNoor.Id).ToList();
        Assert.Equal(ScanEngines.All.Order(), runs.Select(r => r.Engine).Order());
        Assert.All(runs, r => Assert.Equal((ScanRunStatus.Succeeded, alNoor.LastScanAt), (r.Status, r.CompletedAt)));
        Assert.Equal(findings.Count(f => f.Source == ScanEngines.Wazuh), runs.Single(r => r.Engine == ScanEngines.Wazuh).FindingCount);
    }

    [Fact]
    public async Task ThePlainSet_StaysAsTestsExpectIt()
    {
        var store = new SampleDataStore();
        var tenants = await ((ITenantRepository)store).GetAllAsync();
        Assert.All(tenants, t => Assert.Equal((null, null, null, false), (t.CredentialReference, t.ConfigurationCredentialReference, t.WazuhAgentGroup, t.GoPhishEnabled)));
        Assert.Empty(await ((IScanRunRepository)store).GetLatestAsync());
        foreach (var t in tenants)
            Assert.DoesNotContain(await ((IFindingRepository)store).GetForTenantAsync(t.Id), f => f.Source is ScanEngines.Wazuh or ScanEngines.GoPhish);
    }

    [Fact]
    public void TheDevelopmentDatabaseSeed_LeavesOutTheSampleCertificateReferences()
    {
        // A real Worker would try to use them.
        var (tenants, findings, _) = new SampleDataStore(fullDemo: true).Snapshot();
        Assert.All(tenants, t => Assert.Equal((null, null), (t.CredentialReference, t.ConfigurationCredentialReference)));
        Assert.Contains(findings, f => f.Source == ScanEngines.Wazuh);
    }
}

public class DemoSimulatorTests
{
    private static readonly DateTimeOffset T0 = PlaybookData.T0;

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new(fullDemo: true);
        public FakeTime Time { get; }
        public DemoOptions Options { get; } = new() { SyncInterval = TimeSpan.FromSeconds(30), ScanDuration = TimeSpan.FromSeconds(5) };
        public DemoSimulator Simulator { get; }
        public static readonly Guid Requester = Guid.NewGuid();
        public static readonly Guid Approver = Guid.NewGuid();

        public Harness(DateTimeOffset? start = null)
        {
            Time = new FakeTime(start ?? T0);
            Simulator = new DemoSimulator(Store,
            new PlaybookRunner(Store, Store, Store, Store, Store, Time, NullLogger<PlaybookRunner>.Instance),
            new FindingPlaybookRunner(Store, Store, Store, Store, Time, NullLogger<FindingPlaybookRunner>.Instance),
            Options, Time, NullLogger<DemoSimulator>.Instance);
        }

        public async Task<Tenant> TenantAsync(string name) => (await ((ITenantRepository)Store).GetAllAsync()).Single(t => t.DisplayName == name);

        public async Task<IReadOnlyList<AuditEvent>> SimulatedAuditAsync() =>
            (await Store.QueryAsync(new AuditQuery())).Where(e => e.ActorName == DemoSimulator.Actor).OrderBy(e => e.OccurredAt).ToList();
    }

    [Fact]
    public async Task AQueuedScanRunsForAWhile_ThenFinishes_AndFindingPlaybooksPropose()
    {
        var h = new Harness(DateTimeOffset.UtcNow); // after the sample scan history
        var alNoor = await h.TenantAsync("Al Noor Family Clinic");
        await ((IFindingPlaybookRepository)h.Store).AddAsync(new FindingPlaybook
        {
            Id = Guid.NewGuid(), FixId = ConfigurationFixes.BlockLegacyAuth.Id, Enabled = true, CreatedAt = h.Time.Now, UpdatedAt = h.Time.Now,
            UpdatedByUserId = Harness.Requester, UpdatedByName = "Dev Owner"
        });
        IScanRunRepository runs = h.Store;
        var (run, _) = await runs.EnqueueAsync(alNoor.Id, ScanEngines.Maester, ScanTrigger.Manual, "Dev Owner", h.Time.Now);

        await h.Simulator.RunOnceAsync();
        Assert.Equal(ScanRunStatus.Running, Latest().Status);
        h.Time.Advance(TimeSpan.FromSeconds(3));
        await h.Simulator.RunOnceAsync();
        Assert.Equal(ScanRunStatus.Running, Latest().Status); // still within ScanDuration

        h.Time.Advance(TimeSpan.FromSeconds(3));
        await h.Simulator.RunOnceAsync();
        var done = Latest();
        Assert.Equal(ScanRunStatus.Succeeded, done.Status);
        Assert.Equal((await ((IFindingRepository)h.Store).GetForTenantAsync(alNoor.Id)).Count(f => f.Source == ScanEngines.Maester), done.FindingCount);
        Assert.Equal(h.Time.Now, (await h.TenantAsync("Al Noor Family Clinic")).LastScanAt);

        var proposal = Assert.Single(await ((IConfigurationChangeRepository)h.Store).QueryAsync(new ConfigurationChangeQuery { TenantId = alNoor.Id }));
        Assert.Equal((DeviceActionStatus.PendingApproval, "block-legacy-auth", Harness.Requester), (proposal.Status, proposal.FixId, proposal.RequestedByUserId));

        ScanRun Latest() => runs.GetLatestAsync().Result.Single(r => r.Id == run.Id);
    }

    [Fact]
    public async Task ApprovedDeviceActionsAreMarkedSent_WithAuditEntriesThatSayTheyWereSimulated()
    {
        var h = new Harness();
        var creek = await h.TenantAsync("Creek Physio Center");
        var device = (await ((IDeviceRepository)h.Store).GetForTenantAsync(creek.Id)).First();
        IDeviceActionRepository actions = h.Store;
        var (request, _) = await actions.AddAsync(new DeviceActionRequest
        {
            Id = Guid.NewGuid(), TenantId = creek.Id, DeviceId = device.Id, DeviceName = device.DeviceName, Action = DeviceAction.Restart,
            Reason = "Pending updates", Status = DeviceActionStatus.PendingApproval, RequestedAt = T0, RequestedByUserId = Harness.Requester,
            RequestedByName = "Dev MSP Admin", ExpiresAt = T0 + DeviceActionPolicy.ApprovalWindow
        });
        await h.Simulator.RunOnceAsync();
        Assert.Equal(DeviceActionStatus.PendingApproval, (await actions.GetAsync(request.Id))!.Status); // nothing happens before approval

        await actions.DecideAsync(request.Id, true, Harness.Approver, "Dev Owner", PortalRole.Owner, null, T0);
        await h.Simulator.RunOnceAsync();

        Assert.Equal(DeviceActionStatus.Sent, (await actions.GetAsync(request.Id))!.Status);
        var audit = await h.SimulatedAuditAsync();
        Assert.Equal([AuditActions.DeviceActionResult, AuditActions.DeviceActionSending], audit.Select(e => e.Action).Order());
        Assert.All(audit, e => Assert.StartsWith("Simulated:", e.Summary));
        Assert.All(audit, e => Assert.Equal("true", e.Details["simulated"]));
    }

    [Fact]
    public async Task ApprovedConfigurationChangesGetASamplePolicy()
    {
        var h = new Harness();
        var alNoor = await h.TenantAsync("Al Noor Family Clinic");
        IConfigurationChangeRepository changes = h.Store;
        var (change, _) = await changes.AddAsync(new ConfigurationChangeRequest
        {
            Id = Guid.NewGuid(), TenantId = alNoor.Id, FixId = ConfigurationFixes.PhishingResistantMfaForAdmins.Id, CheckId = "MS.AAD.3.6v1",
            Reason = "SMS MFA for admins", Status = DeviceActionStatus.PendingApproval, RequestedAt = T0, RequestedByUserId = Harness.Requester,
            RequestedByName = "Dev MSP Admin", ExpiresAt = T0 + ConfigurationChangePolicy.ApprovalWindow
        });
        await changes.DecideAsync(change.Id, true, Harness.Approver, "Dev Owner", PortalRole.Owner, null, T0);

        await h.Simulator.RunOnceAsync();

        var done = (await changes.GetAsync(change.Id))!;
        Assert.Equal(DeviceActionStatus.Sent, done.Status);
        Assert.True(Guid.TryParse(done.PolicyId, out _));
        Assert.Contains(await h.SimulatedAuditAsync(), e => e.Action == AuditActions.ConfigChangeResult && e.Summary.Contains("report-only"));
    }

    [Fact]
    public async Task DevicesAreSyncedOncePerInterval_AndPlaybooksProposeAfterEachSync()
    {
        var h = new Harness();
        var creek = await h.TenantAsync("Creek Physio Center");
        await h.Store.SaveSyncAsync(new DeviceSyncResult
        {
            TenantId = creek.Id, Source = "Intune", StartedAt = T0, CompletedAt = T0,
            Devices = [PlaybookData.Device(creek.Id, "CPC-OLD-1", daysSinceSync: 9), PlaybookData.Device(creek.Id, "CPC-NEW-1", daysSinceSync: 0)]
        });
        await ((IPlaybookRepository)h.Store).AddAsync(PlaybookData.Playbook(PlaybookTrigger.NotCheckedIn, DeviceAction.Sync, days: 7) with { TenantId = creek.Id });

        await h.Simulator.RunOnceAsync();
        var proposal = Assert.Single(await ((IDeviceActionRepository)h.Store).QueryAsync(new DeviceActionQuery { TenantId = creek.Id }));
        Assert.Equal(("CPC-OLD-1", DeviceActionStatus.PendingApproval), (proposal.DeviceName, proposal.Status));
        Assert.Equal(T0, (await ((IDeviceRepository)h.Store).GetSyncStatusAsync(creek.Id))!.LastSuccessAt);

        h.Time.Advance(TimeSpan.FromSeconds(10));
        await h.Simulator.RunOnceAsync();
        Assert.Equal(T0, (await ((IDeviceRepository)h.Store).GetSyncStatusAsync(creek.Id))!.LastSuccessAt); // not due yet

        h.Time.Advance(TimeSpan.FromSeconds(25));
        await h.Simulator.RunOnceAsync();
        Assert.Equal(h.Time.Now, (await ((IDeviceRepository)h.Store).GetSyncStatusAsync(creek.Id))!.LastSuccessAt);
        Assert.Single(await ((IDeviceActionRepository)h.Store).QueryAsync(new DeviceActionQuery { TenantId = creek.Id })); // still one open action
    }
}

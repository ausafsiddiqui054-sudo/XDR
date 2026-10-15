using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Intune;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Web.Services;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Scans;

public class ScanServiceTests
{
    private const string Thumbprint = "0123456789ABCDEF0123456789ABCDEF01234567";
    private static readonly string[] AllPermissions = AssessmentPermissions.Required.Select(p => p.Name).ToArray();

    private sealed class FakeEngine(Func<Tenant, CancellationToken, Task<ScanResult>>? run = null, string name = ScanEngines.Maester) : IScanEngine
    {
        public List<Guid> Scanned { get; } = [];
        public int Running;
        public int Peak;
        public string Name => name;

        public async Task<ScanResult> RunAsync(Tenant tenant, CancellationToken ct = default)
        {
            lock (Scanned) Scanned.Add(tenant.Id);
            var now = Interlocked.Increment(ref Running);
            int seen;
            while ((seen = Volatile.Read(ref Peak)) < now && Interlocked.CompareExchange(ref Peak, now, seen) != seen) { }
            try
            {
                return run is null ? Ok(tenant) : await run(tenant, ct);
            }
            finally
            {
                Interlocked.Decrement(ref Running);
            }
        }

        public static ScanResult Ok(Tenant t, int count = 3) => new()
        {
            TenantId = t.Id, Source = ScanEngines.Maester, StartedAt = DateTimeOffset.UtcNow, CompletedAt = DateTimeOffset.UtcNow,
            Findings = Enumerable.Range(1, count).Select(i => new Finding
            {
                Id = $"maester:{t.Id:N}:T{i}", TenantId = t.Id, Source = ScanEngines.Maester, Title = $"Test {i}",
                Severity = Severity.High, Status = FindingStatus.Failed
            }).ToList()
        };
    }

    private sealed class Tokens(Func<Tenant, string> issue) : IGraphTokenProvider
    {
        public int Calls;

        public Task<string> GetTokenAsync(Tenant tenant, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(issue(tenant));
        }
    }

    private sealed class Harness
    {
        public SampleDataStore Store { get; } = new();
        public FakeTime Time { get; } = new(DateTimeOffset.UtcNow);
        public FakeEngine Engine { get; init; } = new();
        public IReadOnlyList<FakeEngine> OtherEngines { get; init; } = [];
        public Tokens Tokens { get; init; } = new(t => Jwt.With(t.EntraTenantId, AllPermissions));
        public ScanOptions Options { get; } = new() { MaxParallelScans = 2 };
        public IScanRunRepository Runs => Store;

        public ScanService Service => new(Store, Store, Store, [Engine, .. OtherEngines], Tokens, Microsoft.Extensions.Options.Options.Create(Options), Time,
            NullLogger<ScanService>.Instance);

        /// <summary>Gives the sample's connected tenants a certificate so they count as onboarded.</summary>
        public async Task<IReadOnlyList<Tenant>> OnboardAsync(int count = int.MaxValue)
        {
            var connected = (await Store.GetAllAsync()).Where(t => t.ConsentState is TenantConsentState.ReadOnlyGranted or TenantConsentState.RemediationGranted)
                .Take(count).ToList();
            IOnboardingRepository onboarding = Store;
            var result = new List<Tenant>();
            foreach (var t in connected)
            {
                var request = new OnboardingRequest
                {
                    Id = Guid.NewGuid(), DisplayName = t.DisplayName, PrimaryDomain = t.PrimaryDomain, EntraTenantId = t.EntraTenantId,
                    Status = OnboardingStatus.AwaitingConsent, CreatedAt = Time.Now, ExpiresAt = Time.Now.AddDays(1)
                };
                await onboarding.AddAsync(request, Guid.NewGuid().ToString("N"));
                await onboarding.MarkConsentReceivedAsync(request.Id, Time.Now);
                result.Add(await onboarding.CompleteAsync(request.Id, t with { CredentialReference = Thumbprint }, AllPermissions, Time.Now));
            }
            return result;
        }

        public async Task<ScanRun?> LatestAsync(Guid tenantId) => (await Runs.GetLatestAsync()).SingleOrDefault(r => r.TenantId == tenantId);
    }

    // --- Scheduling ----------------------------------------------------------------------

    [Fact]
    public async Task QueuesOnlyOnboardedTenantsThatAreDue()
    {
        var h = new Harness();
        var onboarded = await h.OnboardAsync();

        Assert.Equal(onboarded.Count, await h.Service.EnqueueDueAsync());
        Assert.Equal(0, await h.Service.EnqueueDueAsync()); // already queued
        var queued = await h.Runs.GetLatestAsync();
        Assert.Equal(onboarded.Select(t => t.Id).Order(), queued.Select(r => r.TenantId).Order());
        Assert.All(queued, r => Assert.Equal(ScanTrigger.Scheduled, r.Trigger));
    }

    [Fact]
    public async Task SuccessfulTenantsWaitAnIntervalFailedOnesTheRetryDelay()
    {
        var h = new Harness { Engine = new FakeEngine((t, _) => Task.FromResult(t.DisplayName.StartsWith("Al Noor")
            ? new ScanResult { TenantId = t.Id, Source = "Maester", StartedAt = default, CompletedAt = default, Findings = [], Succeeded = false, Error = "boom" }
            : FakeEngine.Ok(t))) };
        var onboarded = await h.OnboardAsync();
        var failing = onboarded.Single(t => t.DisplayName.StartsWith("Al Noor"));
        await h.Service.EnqueueDueAsync();
        await h.Service.DrainAsync();

        h.Time.Advance(h.Options.RetryFailedAfter - TimeSpan.FromMinutes(1));
        Assert.Equal(0, await h.Service.EnqueueDueAsync());

        h.Time.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(1, await h.Service.EnqueueDueAsync());
        Assert.Equal(ScanRunStatus.Queued, (await h.LatestAsync(failing.Id))!.Status);

        h.Time.Advance(h.Options.Interval);
        Assert.Equal(onboarded.Count - 1, await h.Service.EnqueueDueAsync());
    }

    // --- Running -------------------------------------------------------------------------

    [Fact]
    public async Task RunSavesFindingsAndRecordsTheOutcome()
    {
        var h = new Harness();
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        Assert.True(await h.Service.RunNextAsync());
        Assert.False(await h.Service.RunNextAsync());

        var run = await h.LatestAsync(tenant.Id);
        Assert.Equal(ScanRunStatus.Succeeded, run!.Status);
        Assert.Equal(3, run.FindingCount);
        Assert.NotNull(run.StartedAt);
        Assert.NotNull(run.CompletedAt);
        var maester = (await h.Store.GetForTenantAsync(tenant.Id)).Where(f => f.Source == "Maester").ToList();
        Assert.Equal(3, maester.Count);
        Assert.All(maester, f => Assert.StartsWith("Test", f.Title));
    }

    [Fact]
    public async Task FailedScanKeepsThePreviousFindings()
    {
        var h = new Harness
        {
            Engine = new FakeEngine((t, _) => Task.FromResult(new ScanResult
            {
                TenantId = t.Id, Source = "Maester", StartedAt = default, CompletedAt = default, Findings = [], Succeeded = false, Error = "pwsh exited 1"
            }))
        };
        var tenant = (await h.OnboardAsync(1))[0];
        var before = await h.Store.GetForTenantAsync(tenant.Id);
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync();

        var run = await h.LatestAsync(tenant.Id);
        Assert.Equal(ScanRunStatus.Failed, run!.Status);
        Assert.Equal("pwsh exited 1", run.Error);
        Assert.Equal(before, await h.Store.GetForTenantAsync(tenant.Id));
    }

    [Fact]
    public async Task EngineExceptionsBecomeFailedRuns()
    {
        var h = new Harness { Engine = new FakeEngine((_, _) => throw new InvalidOperationException("kaboom")) };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        Assert.True(await h.Service.RunNextAsync());

        Assert.Contains("kaboom", (await h.LatestAsync(tenant.Id))!.Error);
    }

    [Fact]
    public async Task MissingPermissionsFailFastWithoutScanning()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, AssessmentPermissions.Required.Take(2).Select(p => p.Name).ToArray())) };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync();

        var run = await h.LatestAsync(tenant.Id);
        Assert.Equal(ScanRunStatus.Failed, run!.Status);
        Assert.StartsWith("Re-consent needed", run.Error);
        Assert.Contains("Directory.Read.All", run.Error);
        Assert.Empty(h.Engine.Scanned);
    }

    [Fact]
    public async Task EachEngineNeedsOnlyItsOwnPermissions()
    {
        // Connected before ScubaGear was added: Maester's permissions only.
        var maesterOnly = AssessmentPermissions.RequiredFor(ScanEngines.Maester).ToArray();
        var scubaGear = new FakeEngine((t, _) => Task.FromResult(FakeEngine.Ok(t) with { Source = ScanEngines.ScubaGear }), ScanEngines.ScubaGear);
        var h = new Harness { OtherEngines = [scubaGear], Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, maesterOnly)) };
        var tenant = (await h.OnboardAsync(1))[0];
        Assert.Equal(2, await h.Service.EnqueueDueAsync());

        await h.Service.DrainAsync();

        var runs = (await h.Runs.GetLatestAsync()).ToDictionary(r => r.Engine);
        Assert.Equal(ScanRunStatus.Succeeded, runs[ScanEngines.Maester].Status);
        Assert.Equal(ScanRunStatus.Failed, runs[ScanEngines.ScubaGear].Status);
        Assert.StartsWith("Re-consent needed", runs[ScanEngines.ScubaGear].Error);
        Assert.Contains("PrivilegedAccess.Read.AzureADGroup", runs[ScanEngines.ScubaGear].Error);
        Assert.DoesNotContain("AuditLog.Read.All", runs[ScanEngines.ScubaGear].Error); // Maester's, not ScubaGear's
        Assert.Equal([tenant.Id], h.Engine.Scanned);
        Assert.Empty(scubaGear.Scanned);
    }

    [Fact]
    public async Task AWorkerOnlyQueuesAndClaimsItsOwnEngines()
    {
        var h = new Harness();
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Runs.EnqueueAsync(tenant.Id, ScanEngines.ScubaGear, ScanTrigger.Manual, "Olivia", h.Time.Now);

        Assert.Equal(1, await h.Service.EnqueueDueAsync()); // Maester only
        await h.Service.DrainAsync();

        var runs = (await h.Runs.GetLatestAsync()).ToDictionary(r => r.Engine);
        Assert.Equal(ScanRunStatus.Succeeded, runs[ScanEngines.Maester].Status);
        Assert.Equal(ScanRunStatus.Queued, runs[ScanEngines.ScubaGear].Status); // left for a Worker that runs ScubaGear
    }

    [Fact]
    public async Task OneEnginesResultsDontReplaceAnothers()
    {
        var scubaGear = new FakeEngine((t, _) => Task.FromResult(FakeEngine.Ok(t, 2) with
        {
            Source = ScanEngines.ScubaGear,
            Findings = FakeEngine.Ok(t, 2).Findings.Select(f => f with { Id = f.Id.Replace("maester", "scubagear"), Source = ScanEngines.ScubaGear }).ToList()
        }), ScanEngines.ScubaGear);
        var h = new Harness { OtherEngines = [scubaGear] };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.DrainAsync();

        var stored = await ((IFindingRepository)h.Store).GetForTenantAsync(tenant.Id);
        Assert.Equal(3, stored.Count(f => f.Source == ScanEngines.Maester));
        Assert.Equal(2, stored.Count(f => f.Source == ScanEngines.ScubaGear));
    }

    [Fact]
    public async Task NonReadOnlyGrantIsRefused()
    {
        var h = new Harness { Tokens = new Tokens(t => Jwt.With(t.EntraTenantId, [.. AllPermissions, "Sites.FullControl.All"])) };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync();

        Assert.Contains("Sites.FullControl.All", (await h.LatestAsync(tenant.Id))!.Error);
        Assert.Empty(h.Engine.Scanned);
    }

    [Fact]
    public async Task TokenFailureIsReported()
    {
        var h = new Harness { Tokens = new Tokens(_ => throw new GraphAuthException("Certificate not found")) };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync();

        Assert.Equal("Certificate not found", (await h.LatestAsync(tenant.Id))!.Error);
    }

    [Fact]
    public async Task PermissionCheckCanBeTurnedOff()
    {
        var h = new Harness { Tokens = new Tokens(_ => throw new InvalidOperationException("should not be called")) };
        h.Options.CheckPermissions = false;
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync();

        Assert.Equal(ScanRunStatus.Succeeded, (await h.LatestAsync(tenant.Id))!.Status);
        Assert.Equal(0, h.Tokens.Calls);
    }

    [Fact]
    public async Task QueuedRunForATenantThatLostConsentFails()
    {
        var h = new Harness();
        var pending = (await h.Store.GetAllAsync()).First(t => t.ConsentState == TenantConsentState.Pending);
        await h.Runs.EnqueueAsync(pending.Id, ScanEngines.Maester, ScanTrigger.Manual, "someone", h.Time.Now);

        await h.Service.RunNextAsync();

        Assert.Contains("isn't onboarded", (await h.LatestAsync(pending.Id))!.Error);
        Assert.Empty(h.Engine.Scanned);
    }

    [Fact]
    public async Task ManualRunsGoFirst()
    {
        var h = new Harness();
        var tenants = await h.OnboardAsync(3);
        await h.Runs.EnqueueAsync(tenants[0].Id, ScanEngines.Maester, ScanTrigger.Scheduled, null, h.Time.Now.AddMinutes(-10));
        await h.Runs.EnqueueAsync(tenants[1].Id, ScanEngines.Maester, ScanTrigger.Scheduled, null, h.Time.Now.AddMinutes(-5));
        await h.Runs.EnqueueAsync(tenants[2].Id, ScanEngines.Maester, ScanTrigger.Manual, "Olivia", h.Time.Now);

        await h.Service.RunNextAsync();
        await h.Service.RunNextAsync();

        Assert.Equal([tenants[2].Id, tenants[0].Id], h.Engine.Scanned);
    }

    [Fact]
    public async Task DrainRunsEverythingWithinTheParallelLimit()
    {
        var h = new Harness { Engine = new FakeEngine(async (t, ct) => { await Task.Delay(40, ct); return FakeEngine.Ok(t); }) };
        var tenants = await h.OnboardAsync();
        await h.Service.EnqueueDueAsync();

        await h.Service.DrainAsync();

        Assert.Equal(tenants.Count, h.Engine.Scanned.Count);
        Assert.Equal(2, h.Engine.Peak);
        Assert.All(await h.Runs.GetLatestAsync(), r => Assert.Equal(ScanRunStatus.Succeeded, r.Status));
    }

    [Fact]
    public async Task ShutdownMidScanStillRecordsTheRun()
    {
        using var cts = new CancellationTokenSource();
        var h = new Harness
        {
            Engine = new FakeEngine(async (t, ct) =>
            {
                await cts.CancelAsync();
                await Task.Delay(Timeout.Infinite, ct);
                return FakeEngine.Ok(t);
            })
        };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Service.EnqueueDueAsync();

        await h.Service.RunNextAsync(cts.Token);

        var run = await h.LatestAsync(tenant.Id);
        Assert.Equal(ScanRunStatus.Failed, run!.Status);
        Assert.Contains("stopped", run.Error);
    }

    [Fact]
    public async Task StuckRunsAreFailedSoTheyCanBeRetried()
    {
        var h = new Harness();
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Runs.EnqueueAsync(tenant.Id, ScanEngines.Maester, ScanTrigger.Scheduled, null, h.Time.Now);
        await h.Runs.ClaimNextAsync([ScanEngines.Maester], h.Time.Now);

        h.Time.Advance(h.Options.StaleAfter + TimeSpan.FromMinutes(1));
        Assert.Equal(1, await h.Service.FailStaleAsync());

        Assert.Equal(ScanRunStatus.Failed, (await h.LatestAsync(tenant.Id))!.Status);
        h.Time.Advance(h.Options.RetryFailedAfter);
        Assert.Equal(1, await h.Service.EnqueueDueAsync());
    }
    // --- Wazuh ------------------------------------------------------------------------------

    [Fact]
    public async Task Wazuh_IsScheduledOnlyForTenantsWithAnAgentGroup()
    {
        var wazuh = new FakeEngine(name: ScanEngines.Wazuh);
        var h = new Harness { OtherEngines = [wazuh] };
        var onboarded = await h.OnboardAsync();
        var mapped = onboarded[0];
        await ((IOnboardingRepository)h.Store).SetWazuhAgentGroupAsync(mapped.Id, "clinic-a");

        await h.Service.EnqueueDueAsync();

        var queued = await h.Runs.GetLatestAsync();
        Assert.Equal([mapped.Id], queued.Where(r => r.Engine == ScanEngines.Wazuh).Select(r => r.TenantId));
        Assert.Equal(onboarded.Count, queued.Count(r => r.Engine == ScanEngines.Maester));
    }

    [Fact]
    public async Task Wazuh_DoesntNeedGraphPermissions()
    {
        // A token without any assessment permission would stop a Graph engine; Wazuh checks its own API user instead.
        var wazuh = new FakeEngine(name: ScanEngines.Wazuh);
        var h = new Harness { Engine = wazuh, Tokens = new Tokens(t => Jwt.With(t.EntraTenantId)) };
        var tenant = (await h.OnboardAsync(1))[0];
        await ((IOnboardingRepository)h.Store).SetWazuhAgentGroupAsync(tenant.Id, "clinic-a");
        await h.Runs.EnqueueAsync(tenant.Id, ScanEngines.Wazuh, ScanTrigger.Manual, "Olivia", h.Time.Now);

        await h.Service.DrainAsync();

        Assert.Equal(ScanRunStatus.Succeeded, (await h.LatestAsync(tenant.Id))!.Status);
        Assert.Equal(0, h.Tokens.Calls);
    }

    [Fact]
    public async Task AQueuedWazuhRun_FailsIfTheGroupWasRemoved()
    {
        var wazuh = new FakeEngine(name: ScanEngines.Wazuh);
        var h = new Harness { Engine = wazuh };
        var tenant = (await h.OnboardAsync(1))[0];
        await h.Runs.EnqueueAsync(tenant.Id, ScanEngines.Wazuh, ScanTrigger.Manual, "Olivia", h.Time.Now);

        await h.Service.DrainAsync();

        var run = (await h.LatestAsync(tenant.Id))!;
        Assert.Equal(ScanRunStatus.Failed, run.Status);
        Assert.Contains("no Wazuh agent group", run.Error);
        Assert.Empty(wazuh.Scanned);
    }
}

public class ScanRequestServiceTests
{
    private static async Task<(SampleDataStore Store, Tenant Ready, Tenant NotReady)> StoreAsync()
    {
        var store = new SampleDataStore();
        var connected = (await store.GetAllAsync()).Where(t => t.ConsentState == TenantConsentState.ReadOnlyGranted).ToList();
        IOnboardingRepository onboarding = store;
        var request = new OnboardingRequest
        {
            Id = Guid.NewGuid(), DisplayName = connected[0].DisplayName, PrimaryDomain = connected[0].PrimaryDomain, EntraTenantId = connected[0].EntraTenantId,
            Status = OnboardingStatus.AwaitingConsent, CreatedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddDays(1)
        };
        await onboarding.AddAsync(request, "h");
        await onboarding.MarkConsentReceivedAsync(request.Id, DateTimeOffset.UtcNow);
        var ready = await onboarding.CompleteAsync(request.Id, connected[0] with { CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567" }, [], DateTimeOffset.UtcNow);
        return (store, ready, connected[1]);
    }

    private static ScanRequestService Service(SampleDataStore store, FixedUser user, params string[] engines) =>
        new(store, store, user, new AuditTrail(store, user, TimeProvider.System, NullLogger<AuditTrail>.Instance),
            ScanEngineSelection.From(engines), TimeProvider.System);

    [Fact]
    public async Task OperatorsQueueManualScansForReadyTenantsAndAreAudited()
    {
        var (store, ready, notReady) = await StoreAsync();
        var admin = FixedUser.MspAdmin();

        Assert.Equal(1, await Service(store, admin).RequestAsync([ready.Id, notReady.Id]));
        Assert.Equal(0, await Service(store, admin).RequestAllAsync()); // already queued

        var run = Assert.Single(await ((IScanRunRepository)store).GetLatestAsync());
        Assert.Equal(ready.Id, run.TenantId);
        Assert.Equal(ScanTrigger.Manual, run.Trigger);
        Assert.Equal(admin.User.Name, run.RequestedBy);
        var e = await Audit.AuditAssert.SingleAsync(store, AuditActions.ScanRequested, AuditOutcome.Success);
        Assert.Equal(ready.Id, e.TenantId);
        Assert.Equal(run.Id.ToString(), e.TargetId);
    }

    [Fact]
    public async Task ClientViewersCantStartScansAndSeeOnlyTheirOwnStatus()
    {
        var (store, ready, notReady) = await StoreAsync();
        await Service(store, FixedUser.Owner()).RequestAsync([ready.Id]);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Service(store, FixedUser.Viewer(ready.Id)).RequestAllAsync());
        Assert.Single(await Service(store, FixedUser.Viewer(ready.Id)).GetLatestAsync());
        Assert.Empty(await Service(store, FixedUser.Viewer(notReady.Id)).GetLatestAsync());
    }

    [Fact]
    public async Task QueuesAndShowsEachConfiguredEngine()
    {
        var (store, ready, _) = await StoreAsync();
        var admin = FixedUser.MspAdmin();
        var both = Service(store, admin, ScanEngines.Maester, ScanEngines.ScubaGear);

        Assert.Equal(2, await both.RequestAsync([ready.Id]));

        var latest = await both.GetLatestAsync();
        Assert.Equal(ScanTrigger.Manual, latest[(ready.Id, ScanEngines.Maester)].Trigger);
        Assert.Equal(ScanTrigger.Manual, latest[(ready.Id, ScanEngines.ScubaGear)].Trigger);
        // A portal configured for Maester only neither shows nor queues ScubaGear.
        Assert.Equal([ScanEngines.Maester], (await Service(store, admin).GetLatestAsync()).Keys.Select(k => k.Engine));
    }

    [Fact]
    public void EngineSelectionDefaultsToMaesterAndRejectsUnknownNames()
    {
        Assert.Equal([ScanEngines.Maester], ScanEngineSelection.From(null).Engines);
        Assert.Equal([ScanEngines.Maester, ScanEngines.ScubaGear], ScanEngineSelection.From(["Maester", "ScubaGear", "Maester"]).Engines);
        Assert.Throws<InvalidOperationException>(() => ScanEngineSelection.From(["scubagear"]));
    }

}

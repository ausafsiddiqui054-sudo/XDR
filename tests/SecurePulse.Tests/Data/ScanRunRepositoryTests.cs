using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Data.Entities;

namespace SecurePulse.Tests.Data;

/// <summary>
/// The scan queue against real PostgreSQL. Each test uses its own engine name, so runs left queued
/// by one test are never claimed by another.
/// </summary>
public class ScanRunRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 13, 8, 0, 0, TimeSpan.Zero);

    private IScanRunRepository Runs => db.Services.GetRequiredService<IScanRunRepository>();

    private static string NewEngine() => $"Test-{Guid.NewGuid():N}";

    private async Task<Guid> AddTenantAsync()
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        var id = Guid.NewGuid();
        ctx.Tenants.Add(new TenantEntity
        {
            Id = id, EntraTenantId = Guid.NewGuid(), DisplayName = "Contoso Clinic", PrimaryDomain = "contoso.example",
            ConsentState = TenantConsentState.ReadOnlyGranted, CredentialReference = "0123456789ABCDEF0123456789ABCDEF01234567"
        });
        await ctx.SaveChangesAsync();
        return id;
    }

    [PostgresFact]
    public async Task EnqueueReturnsTheActiveRunInsteadOfADuplicate()
    {
        var tenant = await AddTenantAsync();
        var engine = NewEngine();

        var (first, created) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Scheduled, null, T0);
        var (second, createdAgain) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Manual, "Pat <pat@msp.example>", T0.AddMinutes(1));

        Assert.True(created);
        Assert.False(createdAgain);
        Assert.Equal(first, second);
        Assert.Equal(ScanRunStatus.Queued, first.Status);

        // Still deduplicated while it runs.
        await Runs.ClaimNextAsync([engine], T0.AddMinutes(2));
        var (_, createdWhileRunning) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Manual, null, T0.AddMinutes(3));
        Assert.False(createdWhileRunning);
    }

    [PostgresFact]
    public async Task ConcurrentEnqueuesCreateExactlyOneRun()
    {
        var tenant = await AddTenantAsync();
        var engine = NewEngine();

        var results = await Task.WhenAll(Enumerable.Range(0, 12)
            .Select(_ => Task.Run(() => Runs.EnqueueAsync(tenant, engine, ScanTrigger.Manual, null, T0))));

        Assert.Single(results, r => r.Created);
        Assert.Single(results.Select(r => r.Run.Id).Distinct());
    }

    [PostgresFact]
    public async Task ConcurrentClaimersEachGetADifferentRun()
    {
        var engine = NewEngine();
        var queued = new List<Guid>();
        for (var i = 0; i < 6; i++)
            queued.Add((await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0.AddSeconds(i))).Run.Id);

        var claims = await Task.WhenAll(Enumerable.Range(0, 10)
            .Select(_ => Task.Run(() => Runs.ClaimNextAsync([engine], T0.AddMinutes(5)))));

        var claimed = claims.Where(c => c is not null).Select(c => c!).ToList();
        Assert.Equal(6, claimed.Count);
        Assert.Equal(queued.Order(), claimed.Select(c => c.Id).Order());
        Assert.All(claimed, c =>
        {
            Assert.Equal(ScanRunStatus.Running, c.Status);
            Assert.Equal(T0.AddMinutes(5), c.StartedAt);
        });
        Assert.Null(await Runs.ClaimNextAsync([engine], T0.AddMinutes(6)));
    }

    [PostgresFact]
    public async Task ManualRunsAreClaimedFirstThenOldest()
    {
        var engine = NewEngine();
        var oldScheduled = (await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0)).Run;
        var newScheduled = (await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0.AddMinutes(2))).Run;
        var manual = (await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Manual, "Pat", T0.AddMinutes(5))).Run;

        Assert.Equal(manual.Id, (await Runs.ClaimNextAsync([engine], T0.AddMinutes(6)))!.Id);
        Assert.Equal(oldScheduled.Id, (await Runs.ClaimNextAsync([engine], T0.AddMinutes(6)))!.Id);
        Assert.Equal(newScheduled.Id, (await Runs.ClaimNextAsync([engine], T0.AddMinutes(6)))!.Id);
    }

    [PostgresFact]
    public async Task ClaimOnlyTakesTheRequestedEngines()
    {
        var tenant = await AddTenantAsync();
        var mine = NewEngine();
        await Runs.EnqueueAsync(tenant, NewEngine(), ScanTrigger.Manual, null, T0);

        Assert.Null(await Runs.ClaimNextAsync([mine], T0));
        Assert.Null(await Runs.ClaimNextAsync([], T0));
    }

    [PostgresFact]
    public async Task CompleteOnlyChangesRunningRunsAndClipsErrors()
    {
        var tenant = await AddTenantAsync();
        var engine = NewEngine();
        var (queued, _) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Scheduled, null, T0);

        // Not claimed yet: completing it does nothing.
        await Runs.CompleteAsync(queued.Id, true, 5, null, T0.AddMinutes(1));
        Assert.Equal(ScanRunStatus.Queued, Latest(await Runs.GetLatestAsync(), tenant, engine).Status);

        await Runs.ClaimNextAsync([engine], T0.AddMinutes(2));
        await Runs.CompleteAsync(queued.Id, false, null, new string('x', 5000), T0.AddMinutes(3));
        var failed = Latest(await Runs.GetLatestAsync(), tenant, engine);
        Assert.Equal(ScanRunStatus.Failed, failed.Status);
        Assert.Equal(T0.AddMinutes(3), failed.CompletedAt);
        Assert.Equal(2000, failed.Error!.Length);

        // Already finished (e.g. failed as stale meanwhile): a late completion can't flip it.
        await Runs.CompleteAsync(queued.Id, true, 9, null, T0.AddMinutes(4));
        Assert.Equal(ScanRunStatus.Failed, Latest(await Runs.GetLatestAsync(), tenant, engine).Status);
    }

    [PostgresFact]
    public async Task FailStaleOnlyFailsRunsStartedBeforeTheCutoff()
    {
        var engine = NewEngine();
        var (stale, _) = await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0);
        await Runs.ClaimNextAsync([engine], T0);
        var (recent, _) = await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0);
        await Runs.ClaimNextAsync([engine], T0.AddMinutes(50));
        var (stillQueued, _) = await Runs.EnqueueAsync(await AddTenantAsync(), engine, ScanTrigger.Scheduled, null, T0);

        var count = await Runs.FailStaleAsync(T0.AddMinutes(30), "Worker stopped responding.", T0.AddMinutes(60));

        Assert.True(count >= 1);
        var latest = (await Runs.GetLatestAsync()).Where(r => r.Engine == engine).ToDictionary(r => r.Id);
        Assert.Equal(ScanRunStatus.Failed, latest[stale.Id].Status);
        Assert.Equal("Worker stopped responding.", latest[stale.Id].Error);
        Assert.Equal(T0.AddMinutes(60), latest[stale.Id].CompletedAt);
        Assert.Equal(ScanRunStatus.Running, latest[recent.Id].Status);
        Assert.Equal(ScanRunStatus.Queued, latest[stillQueued.Id].Status);
    }

    [PostgresFact]
    public async Task AFinishedRunAllowsANewOneAndLatestReturnsIt()
    {
        var tenant = await AddTenantAsync();
        var engine = NewEngine();
        var other = NewEngine();
        var (first, _) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Scheduled, null, T0);
        await Runs.ClaimNextAsync([engine], T0.AddMinutes(1));
        await Runs.CompleteAsync(first.Id, true, 42, null, T0.AddMinutes(10));
        var (otherRun, _) = await Runs.EnqueueAsync(tenant, other, ScanTrigger.Scheduled, null, T0);

        var (second, created) = await Runs.EnqueueAsync(tenant, engine, ScanTrigger.Manual, "Pat", T0.AddHours(1));

        Assert.True(created);
        Assert.NotEqual(first.Id, second.Id);
        var latest = (await Runs.GetLatestAsync()).Where(r => r.TenantId == tenant).ToList();
        Assert.Equal(2, latest.Count);
        Assert.Equal(second.Id, Latest(latest, tenant, engine).Id);
        Assert.Equal(otherRun.Id, Latest(latest, tenant, other).Id);

        var finished = await LoadAsync(first.Id);
        Assert.Equal((ScanRunStatus.Succeeded, 42), (finished.Status, finished.FindingCount));
    }

    [PostgresFact]
    public async Task DeletingATenantRemovesItsRuns()
    {
        var tenant = await AddTenantAsync();
        var (run, _) = await Runs.EnqueueAsync(tenant, NewEngine(), ScanTrigger.Scheduled, null, T0);

        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using (var ctx = await factory.CreateDbContextAsync())
            await ctx.Tenants.Where(t => t.Id == tenant).ExecuteDeleteAsync();

        Assert.DoesNotContain(await Runs.GetLatestAsync(), r => r.Id == run.Id);
    }

    private static ScanRun Latest(IEnumerable<ScanRun> runs, Guid tenant, string engine) =>
        Assert.Single(runs, r => r.TenantId == tenant && r.Engine == engine);

    private async Task<ScanRunEntity> LoadAsync(Guid id)
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        return await ctx.ScanRuns.AsNoTracking().SingleAsync(r => r.Id == id);
    }
}

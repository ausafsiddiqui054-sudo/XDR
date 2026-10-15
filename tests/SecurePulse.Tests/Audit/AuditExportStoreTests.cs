using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Tests.Data;

namespace SecurePulse.Tests.Audit;

/// <summary>The export checkpoint against PostgreSQL. Each test uses its own destination name.</summary>
public class AuditExportStoreTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private IAuditLog Log => db.Services.GetRequiredService<IAuditLog>();
    private IAuditExportStore Store => db.Services.GetRequiredService<IAuditExportStore>();

    private static string NewDestination() => "t-" + Guid.NewGuid().ToString("N")[..20];

    private async Task<Guid> AddAsync(string summary, DateTimeOffset? occurredAt = null)
    {
        var id = Guid.NewGuid();
        await Log.RecordAsync(new AuditEvent
        {
            Id = id, OccurredAt = occurredAt ?? DateTimeOffset.UtcNow, Action = AuditActions.SignIn, Outcome = AuditOutcome.Success,
            ActorName = "Test", Summary = summary
        });
        return id;
    }

    /// <summary>Everything after the checkpoint, committing as it goes (what the Worker does).</summary>
    private async Task<List<AuditEvent>> DrainAsync(string destination)
    {
        var all = new List<AuditEvent>();
        while (true)
        {
            await using var lease = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 1000);
            Assert.NotNull(lease);
            if (lease.Events.Count == 0)
            {
                await lease.CommitAsync(0);
                return all;
            }
            all.AddRange(lease.Events);
            await lease.CommitAsync(lease.Events.Count);
        }
    }

    [PostgresFact]
    public async Task TheDatabaseStampsRecordedAt()
    {
        var id = await AddAsync("stamp");

        var stored = (await Log.QueryAsync(new AuditQuery { Search = "stamp", Limit = 10 })).Single(e => e.Id == id);

        Assert.NotNull(stored.RecordedAt);
        Assert.InRange(stored.RecordedAt!.Value, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    [PostgresFact]
    public async Task ExportsInStoredOrder_AndOnlyMovesOnCommit()
    {
        var destination = NewDestination();
        await DrainAsync(destination); // start after everything already in the table
        var a = await AddAsync("order a");
        var b = await AddAsync("order b");
        var c = await AddAsync("order c");

        await using (var first = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 2))
        {
            Assert.Equal([a, b], first!.Events.Select(e => e.Id));
            Assert.All(first.Events, e => Assert.NotNull(e.RecordedAt));
            // Not committed: the checkpoint stays.
        }
        await using (var again = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 2))
        {
            Assert.Equal([a, b], again!.Events.Select(e => e.Id));
            await again.CommitAsync(1); // only a was accepted
        }
        await using (var rest = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 10))
        {
            Assert.Equal([b, c], rest!.Events.Select(e => e.Id));
            await rest.CommitAsync(2);
        }

        var status = await Store.GetStatusAsync(destination);
        Assert.Equal(0, status!.Pending);
        Assert.Null(status.LastError);
        Assert.NotNull(status.LastExportedAt);
    }

    [PostgresFact]
    public async Task EventsWithAnEarlierClock_AreStillExported()
    {
        var destination = NewDestination();
        await DrainAsync(destination);
        await AddAsync("skew now");
        Assert.Single(await DrainAsync(destination));

        // A host whose clock is an hour behind writes after the checkpoint moved: ordered by the database's clock, it isn't skipped.
        var late = await AddAsync("skew behind", DateTimeOffset.UtcNow.AddHours(-1));

        Assert.Equal([late], (await DrainAsync(destination)).Select(e => e.Id));
    }

    [PostgresFact]
    public async Task TheNewestEventsWaitForTheLag()
    {
        var destination = NewDestination();
        await DrainAsync(destination);
        await AddAsync("lag");

        await using var lease = await Store.TryLeaseAsync(destination, TimeSpan.FromMinutes(5), 100);

        Assert.Empty(lease!.Events);
    }

    [PostgresFact]
    public async Task OnlyOneWorkerHoldsADestination()
    {
        var destination = NewDestination();
        await DrainAsync(destination);

        await using var first = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 10);
        await using var second = await Store.TryLeaseAsync(destination, TimeSpan.Zero, 10);
        await using var other = await Store.TryLeaseAsync(NewDestination(), TimeSpan.Zero, 1);

        Assert.NotNull(first);
        Assert.Null(second);
        Assert.NotNull(other); // destinations don't block each other
    }

    [PostgresFact]
    public async Task FailuresAreRecorded_AndClearedBySuccess()
    {
        var destination = NewDestination();
        await DrainAsync(destination);
        await AddAsync("failure");

        await Store.RecordFailureAsync(destination, "Sentinel returned 403 Forbidden." + new string('x', 3000));
        var failed = await Store.GetStatusAsync(destination);
        Assert.StartsWith("Sentinel returned 403", failed!.LastError);
        Assert.Equal(2000, failed.LastError!.Length);
        Assert.Equal(1, failed.Pending);

        await DrainAsync(destination);
        var ok = await Store.GetStatusAsync(destination);
        Assert.Null(ok!.LastError);
        Assert.Equal(0, ok.Pending);
    }

    [PostgresFact]
    public async Task NoStatusUntilADestinationIsUsed() => Assert.Null(await Store.GetStatusAsync(NewDestination()));
}

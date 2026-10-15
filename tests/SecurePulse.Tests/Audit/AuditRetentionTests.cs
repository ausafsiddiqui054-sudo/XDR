using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;
using SecurePulse.Tests.Data;
using SecurePulse.Tests.Onboarding;
using SecurePulse.Worker;

namespace SecurePulse.Tests.Audit;

/// <summary>Needs SECUREPULSE_TEST_POSTGRES and a maintenance login that is a member of securepulse_audit_purge.</summary>
public sealed class AuditMaintenanceFactAttribute : FactAttribute
{
    public static string? MaintenanceConnectionString => Environment.GetEnvironmentVariable("SECUREPULSE_TEST_AUDIT_MAINTENANCE");

    public AuditMaintenanceFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(PostgresDatabase.ServerConnectionString) || string.IsNullOrWhiteSpace(MaintenanceConnectionString))
            Skip = "Set SECUREPULSE_TEST_POSTGRES and SECUREPULSE_TEST_AUDIT_MAINTENANCE (a member of securepulse_audit_purge) to run audit retention tests.";
    }
}

/// <summary>The database side: who may delete audit events, and which ones.</summary>
public class AuditPurgeDatabaseTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private IAuditLog Log => db.Services.GetRequiredService<IAuditLog>();

    private string DatabaseName
    {
        get
        {
            using var context = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>().CreateDbContext();
            return context.Database.GetDbConnection().Database;
        }
    }

    private NpgsqlDataSource Maintenance() => NpgsqlDataSource.Create(
        new NpgsqlConnectionStringBuilder(AuditMaintenanceFactAttribute.MaintenanceConnectionString) { Database = DatabaseName }.ConnectionString);

    private PostgresAuditPurger Purger(NpgsqlDataSource source) => new(source);

    /// <summary>Events tagged with a fresh marker, so each test only looks at its own rows.</summary>
    private async Task<string> AddEventsAsync(params int[] daysAgo)
    {
        var marker = Guid.NewGuid().ToString("N");
        foreach (var days in daysAgo)
        {
            await Log.RecordAsync(new AuditEvent
            {
                Id = Guid.NewGuid(), OccurredAt = DateTimeOffset.UtcNow.AddDays(-days), Action = AuditActions.SignIn, Outcome = AuditOutcome.Success,
                ActorName = "Test", Summary = $"{marker} {days} days ago"
            });
        }
        return marker;
    }

    private async Task<int[]> RemainingAsync(string marker) =>
        (await Log.QueryAsync(new AuditQuery { Search = marker, Limit = 100 }))
        .Select(e => int.Parse(e.Summary.Split(' ')[1])).Order().ToArray();

    private async Task ClearOldAsync()
    {
        // Rows from earlier tests in this class (older than 100 days) would make counts ambiguous.
        await using var source = Maintenance();
        await Purger(source).PurgeOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-100), 1000);
    }

    [PostgresFact]
    public async Task TheApplicationsRoleCantDeleteOrTruncate_EvenOldEvents()
    {
        var marker = await AddEventsAsync(400);
        await using var context = await db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>().CreateDbContextAsync();

        var delete = await Assert.ThrowsAsync<PostgresException>(() => context.AuditEvents.Where(e => e.Summary.StartsWith(marker)).ExecuteDeleteAsync());
        var truncate = await Assert.ThrowsAsync<PostgresException>(() => context.Database.ExecuteSqlRawAsync("TRUNCATE audit_events"));

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, delete.SqlState);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, truncate.SqlState);
        Assert.Equal(new[] { 400 }, await RemainingAsync(marker));
    }

    [PostgresFact]
    public async Task TheApplicationsRoleCantBecomeThePurgeRole()
    {
        await using var context = await db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>().CreateDbContextAsync();
        await context.Database.OpenConnectionAsync();
        var exists = await context.Database.SqlQueryRaw<bool>("SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = 'securepulse_audit_purge') AS \"Value\"").SingleAsync();
        if (!exists) return; // nothing to become

        var ex = await Assert.ThrowsAsync<PostgresException>(() => context.Database.ExecuteSqlRawAsync("SET ROLE securepulse_audit_purge"));
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, ex.SqlState);
    }

    [PostgresFact]
    public async Task QueryFiltersByExactAction()
    {
        var marker = await AddEventsAsync(1);
        await Log.RecordAsync(new AuditEvent
        {
            Id = Guid.NewGuid(), OccurredAt = DateTimeOffset.UtcNow, Action = AuditActions.AuditPurged, Outcome = AuditOutcome.Success,
            ActorName = "SecurePulse Worker", Summary = $"{marker} purged"
        });

        var purged = await Log.QueryAsync(new AuditQuery { Action = AuditActions.AuditPurged, Search = marker });

        Assert.Equal([AuditActions.AuditPurged], purged.Select(e => e.Action));
    }

    [AuditMaintenanceFact]
    public async Task PurgeDeletesOnlyEventsOlderThanTheCutoff_InBatches()
    {
        await ClearOldAsync();
        var marker = await AddEventsAsync(400, 380, 370, 365 - 1, 200, 120, 10);
        await using var source = Maintenance();

        Assert.Equal(3, await Purger(source).CountOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-365)));
        var deleted = await Purger(source).PurgeOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-365), batchSize: 2);

        Assert.Equal(3, deleted);
        Assert.Equal(new[] { 10, 120, 200, 364 }, await RemainingAsync(marker));
        Assert.Equal(0, await Purger(source).CountOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-365)));
    }

    [AuditMaintenanceFact]
    public async Task EventsAnExportHasntSent_AreNeverDeleted()
    {
        await ClearOldAsync();
        var marker = await AddEventsAsync(400, 380, 370); // stored in this order
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var context = await factory.CreateDbContextAsync();
        var mine = await context.AuditEvents.AsNoTracking().Where(e => e.Summary.StartsWith(marker)).OrderBy(e => e.RecordedAt).ToListAsync();
        var exportedUpTo = mine.Single(e => e.Summary.EndsWith(" 380 days ago"));
        await using var source = Maintenance();
        var cutoff = DateTimeOffset.UtcNow.AddDays(-365);

        try
        {
            // An export that hasn't sent anything yet holds every event back.
            context.AuditExportCheckpoints.Add(new SecurePulse.Data.Entities.AuditExportCheckpointEntity { Destination = "guard-new" });
            await context.SaveChangesAsync();
            Assert.Equal(0, await Purger(source).CountOlderThanAsync(cutoff));
            Assert.Equal(0, await Purger(source).PurgeOlderThanAsync(cutoff, 100));

            // Once it has sent up to the 380-day event, those can go; the 370-day one waits.
            await context.AuditExportCheckpoints.Where(c => c.Destination == "guard-new").ExecuteDeleteAsync();
            context.AuditExportCheckpoints.Add(new SecurePulse.Data.Entities.AuditExportCheckpointEntity
            {
                Destination = "guard-sent", RecordedAt = exportedUpTo.RecordedAt, LastId = exportedUpTo.Id
            });
            await context.SaveChangesAsync();

            Assert.Equal(2, await Purger(source).CountOlderThanAsync(cutoff));
            Assert.Equal(1, await Purger(source).CountAwaitingExportAsync(cutoff));
            Assert.Equal(2, await Purger(source).PurgeOlderThanAsync(cutoff, 100));
            Assert.Equal(new[] { 370 }, await RemainingAsync(marker));
        }
        finally
        {
            await context.AuditExportCheckpoints.Where(c => c.Destination.StartsWith("guard-")).ExecuteDeleteAsync();
        }

        Assert.Equal(1, await Purger(source).PurgeOlderThanAsync(cutoff, 100)); // no export: nothing held back
    }

    [AuditMaintenanceFact]
    public async Task TheDatabaseRefusesToDeleteAnythingYoungerThanTheFloor()
    {
        await ClearOldAsync();
        var marker = await AddEventsAsync(120, 89);
        await using var source = Maintenance();

        // A misconfigured cutoff (now) reaches an 89-day-old row: the trigger refuses, and the batch rolls back.
        var ex = await Assert.ThrowsAsync<AuditPurgeException>(() => Purger(source).PurgeOlderThanAsync(DateTimeOffset.UtcNow, 100));

        Assert.Equal(0, ex.Deleted);
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, Assert.IsType<PostgresException>(ex.InnerException).SqlState);
        Assert.Equal(new[] { 89, 120 }, await RemainingAsync(marker));
        Assert.Equal(AuditRetention.Minimum, TimeSpan.FromDays(90)); // the trigger's literal floor
    }

    [AuditMaintenanceFact]
    public async Task ThePurgeRoleStillCantUpdateOrTruncate()
    {
        var marker = await AddEventsAsync(400);
        await using var source = Maintenance();
        await using var connection = await source.OpenConnectionAsync();

        foreach (var sql in new[] { $"UPDATE audit_events SET \"Summary\" = 'x' WHERE \"Summary\" LIKE '{marker}%'", "TRUNCATE audit_events" })
        {
            await using var tx = await connection.BeginTransactionAsync();
            await new NpgsqlCommand("SET LOCAL ROLE securepulse_audit_purge", connection, tx).ExecuteNonQueryAsync();
            var ex = await Assert.ThrowsAsync<PostgresException>(() => new NpgsqlCommand(sql, connection, tx).ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, ex.SqlState);
            await tx.RollbackAsync();
        }
        Assert.Equal(new[] { 400 }, await RemainingAsync(marker));
    }

    [AuditMaintenanceFact]
    public async Task WithoutSwitchingRole_TheMaintenanceLoginCantDelete()
    {
        var marker = await AddEventsAsync(400);
        await using var source = Maintenance();
        await using var connection = await source.OpenConnectionAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            new NpgsqlCommand($"DELETE FROM audit_events WHERE \"Summary\" LIKE '{marker}%'", connection).ExecuteNonQueryAsync());

        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, ex.SqlState);
        Assert.Equal(new[] { 400 }, await RemainingAsync(marker));
    }

    [AuditMaintenanceFact]
    public async Task OnlyOneWorkerPurgesAtATime()
    {
        await ClearOldAsync();
        var marker = await AddEventsAsync(400);
        await using var source = Maintenance();
        await using var other = await source.OpenConnectionAsync();
        await new NpgsqlCommand($"SELECT pg_advisory_lock({PostgresAuditPurger.LockKey})", other).ExecuteScalarAsync();

        var result = await Purger(source).PurgeOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-365), 100);

        Assert.Null(result);
        Assert.Equal(new[] { 400 }, await RemainingAsync(marker));

        await new NpgsqlCommand($"SELECT pg_advisory_unlock({PostgresAuditPurger.LockKey})", other).ExecuteScalarAsync();
        Assert.Equal(1, await Purger(source).PurgeOlderThanAsync(DateTimeOffset.UtcNow.AddDays(-365), 100));
    }
}

/// <summary>The Worker job: fail-closed auditing around the purge.</summary>
public class AuditRetentionServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 3, 0, 0, TimeSpan.Zero);

    private sealed class FakePurger : IAuditPurger
    {
        public long Due = 42;
        public Func<long?> Purge = () => 42;
        public List<string> Calls { get; } = [];
        public DateTimeOffset? Cutoff;
        public int BatchSize;

        public Task<long> CountOlderThanAsync(DateTimeOffset cutoff, CancellationToken ct = default)
        {
            Calls.Add("count");
            Cutoff = cutoff;
            return Task.FromResult(Due);
        }

        public long Held;

        public Task<long> CountAwaitingExportAsync(DateTimeOffset cutoff, CancellationToken ct = default)
        {
            Calls.Add("held");
            return Task.FromResult(Held);
        }

        public Task<long?> PurgeOlderThanAsync(DateTimeOffset cutoff, int batchSize, CancellationToken ct = default)
        {
            Calls.Add("purge");
            BatchSize = batchSize;
            return Task.FromResult(Purge());
        }
    }

    private sealed class RecordingLog(List<string> calls, bool fail = false) : IAuditLog
    {
        public List<AuditEvent> Events { get; } = [];

        public Task RecordAsync(AuditEvent e, CancellationToken ct = default)
        {
            calls.Add("audit:" + e.Action);
            if (fail) throw new InvalidOperationException("database down");
            Events.Add(e);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery q, CancellationToken ct = default) => Task.FromResult<IReadOnlyList<AuditEvent>>(Events);
    }

    private static (AuditRetentionService Service, FakePurger Purger, RecordingLog Log) Create(TimeSpan? retainFor = null, bool auditFails = false,
        bool unset = false)
    {
        var purger = new FakePurger();
        var log = new RecordingLog(purger.Calls, auditFails);
        var options = Options.Create(new AuditRetentionOptions { RetainFor = unset ? null : retainFor ?? TimeSpan.FromDays(365), BatchSize = 777 });
        return (new AuditRetentionService(purger, log, options, new FakeTime(Now), NullLogger<AuditRetentionService>.Instance), purger, log);
    }

    [Fact]
    public async Task NotConfigured_DeletesNothing()
    {
        var (service, purger, _) = Create(unset: true);

        Assert.Null(await service.RunOnceAsync());
        Assert.Empty(purger.Calls);
    }

    [Fact]
    public async Task NothingDue_WritesNothing()
    {
        var (service, purger, log) = Create();
        purger.Due = 0;

        var result = await service.RunOnceAsync();

        Assert.Equal(0, result!.Deleted);
        Assert.Equal(["count", "held"], purger.Calls);
        Assert.Empty(log.Events);
    }

    [Fact]
    public async Task AuditsBeforeDeleting_ThenRecordsTheResult()
    {
        var (service, purger, log) = Create(TimeSpan.FromDays(400));

        var result = await service.RunOnceAsync();

        Assert.Equal(["count", "held", "audit:audit.purge-started", "purge", "audit:audit.purged"], purger.Calls);
        Assert.Equal(Now.AddDays(-400), purger.Cutoff);
        Assert.Equal(777, purger.BatchSize);
        Assert.Equal(42, result!.Deleted);
        Assert.Null(result.Error);

        var started = log.Events[0];
        Assert.Equal(AuditOutcome.Success, started.Outcome);
        Assert.Equal("SecurePulse Worker", started.ActorName);
        Assert.Equal("42", started.Details["due"]);
        Assert.Equal("400", started.Details["retainForDays"]);
        Assert.Equal(Now.AddDays(-400), DateTimeOffset.Parse(started.Details["cutoff"]));

        var done = log.Events[1];
        Assert.Equal(AuditActions.AuditPurged, done.Action);
        Assert.Equal(AuditOutcome.Success, done.Outcome);
        Assert.Equal("42", done.Details["deleted"]);
        Assert.Contains("Removed 42 audit events older than 2025-09-10", done.Summary);
    }

    [Fact]
    public async Task EventsNotYetExported_AreReportedAsHeld()
    {
        var (service, purger, log) = Create();
        purger.Held = 7;

        var result = await service.RunOnceAsync();

        Assert.Equal(7, result!.HeldForExport);
        Assert.Equal("7", log.Events[0].Details["heldForExport"]);
        Assert.False(log.Events[1].Details.ContainsKey("heldForExport") && log.Events[1].Details["heldForExport"] != "7");
    }

    [Fact]
    public async Task IfTheAuditEntryCantBeWritten_NothingIsDeleted()
    {
        var (service, purger, _) = Create(auditFails: true);

        var result = await service.RunOnceAsync();

        Assert.DoesNotContain("purge", purger.Calls);
        Assert.Equal(0, result!.Deleted);
        Assert.Contains("nothing was deleted", result.Error);
    }

    [Fact]
    public async Task APartialFailure_IsRecordedWithHowManyWereDeleted()
    {
        var (service, purger, log) = Create();
        purger.Purge = () => throw new AuditPurgeException(10_000, new InvalidOperationException("connection reset"));

        var result = await service.RunOnceAsync();

        Assert.Equal(10_000, result!.Deleted);
        var done = log.Events.Single(e => e.Action == AuditActions.AuditPurged);
        Assert.Equal(AuditOutcome.Failure, done.Outcome);
        Assert.Equal("10000", done.Details["deleted"]);
        Assert.Contains("connection reset", done.Summary);
    }

    [Fact]
    public async Task AFailureBeforeDeleting_IsRecorded()
    {
        var (service, purger, log) = Create();
        purger.Purge = () => throw new InvalidOperationException("permission denied to set role \"securepulse_audit_purge\"");

        var result = await service.RunOnceAsync();

        Assert.Equal(0, result!.Deleted);
        var done = log.Events.Single(e => e.Action == AuditActions.AuditPurged);
        Assert.Equal(AuditOutcome.Failure, done.Outcome);
        Assert.Contains("permission denied to set role", done.Summary);
    }

    [Fact]
    public async Task AnotherWorkerPurging_IsRecordedAsSkipped()
    {
        var (service, purger, log) = Create();
        purger.Purge = () => null;

        var result = await service.RunOnceAsync();

        Assert.True(result!.Skipped);
        Assert.Contains(log.Events, e => e.Action == AuditActions.AuditPurged && e.Outcome == AuditOutcome.Failure && e.Summary.StartsWith("Skipped"));
    }

    [Theory]
    [InlineData(89)]
    [InlineData(1)]
    public async Task APeriodBelowTheMinimum_IsRefused(int days)
    {
        var (service, purger, _) = Create(TimeSpan.FromDays(days));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => service.RunOnceAsync());

        Assert.Contains("at least 90 days", ex.Message);
        Assert.Empty(purger.Calls);
    }

    [Fact]
    public void TheMinimumIsAccepted() => Assert.Null(AuditRetention.Problem(TimeSpan.FromDays(90)));

    [Fact]
    public void PurgeActionsHaveLabelsInTheAuditCategory()
    {
        Assert.Equal("audit", AuditActions.CategoryOf(AuditActions.AuditPurged));
        Assert.Equal("audit", AuditActions.CategoryOf(AuditActions.AuditPurgeStarted));
        Assert.NotEqual(AuditActions.AuditPurged, AuditActions.Label(AuditActions.AuditPurged));
        Assert.NotEqual(AuditActions.AuditPurgeStarted, AuditActions.Label(AuditActions.AuditPurgeStarted));
    }
}

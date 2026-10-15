using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data;

namespace SecurePulse.Tests.Data;

public class AuditLogRepositoryTests(PostgresDatabase db) : IClassFixture<PostgresDatabase>
{
    private IAuditLog Log => db.Services.GetRequiredService<IAuditLog>();

    private static AuditEvent E(DateTimeOffset at, string actor = "Pat <pat@msp.example>", string summary = "did a thing", Guid? tenant = null,
        string action = AuditActions.Invited, AuditOutcome outcome = AuditOutcome.Success) => new()
    {
        Id = Guid.NewGuid(), OccurredAt = at, Action = action, Outcome = outcome, ActorName = actor, ActorUserId = Guid.NewGuid(),
        TenantId = tenant, TargetType = "PortalUser", TargetId = "t-1", Summary = summary, IpAddress = "203.0.113.9",
        Details = new Dictionary<string, string> { ["role"] = "Owner", ["quote\"key"] = "value with \"quotes\" and ünïcode" }
    };

    private async Task<int> ExecuteAsync(string sql)
    {
        var factory = db.Services.GetRequiredService<IDbContextFactory<SecurePulseDbContext>>();
        await using var ctx = await factory.CreateDbContextAsync();
        return await ctx.Database.ExecuteSqlRawAsync(sql);
    }

    [PostgresFact]
    public async Task RoundTripsEveryField()
    {
        var tenant = Guid.NewGuid();
        var e = E(new DateTimeOffset(2026, 10, 1, 9, 0, 0, 123, TimeSpan.Zero), tenant: tenant);

        await Log.RecordAsync(e);

        var loaded = Assert.Single(await Log.QueryAsync(new AuditQuery { TenantId = tenant }));
        Assert.Equal(e with { Details = loaded.Details, RecordedAt = loaded.RecordedAt }, loaded);
        Assert.NotNull(loaded.RecordedAt); // stamped by the database, not the writer
        Assert.Equal(e.Details, loaded.Details);
        Assert.Equal("people", loaded.Category);
    }

    [PostgresFact]
    public async Task UpdateDeleteAndTruncateAreRejectedByTheDatabase()
    {
        var e = E(DateTimeOffset.UtcNow);
        await Log.RecordAsync(e);

        foreach (var sql in new[]
                 {
                     $"UPDATE audit_events SET \"Summary\" = 'rewritten' WHERE \"Id\" = '{e.Id}'",
                     $"DELETE FROM audit_events WHERE \"Id\" = '{e.Id}'",
                     "TRUNCATE audit_events"
                 })
        {
            var ex = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(sql));
            Assert.Contains("append-only", ex.MessageText);
        }

        Assert.Equal("did a thing", (await Log.QueryAsync(new AuditQuery { Search = "did a thing", Limit = 1000 })).Single(x => x.Id == e.Id).Summary);
    }

    [PostgresFact]
    public async Task KeysetPagingReturnsEveryEventOnceEvenWithIdenticalTimestamps()
    {
        var tenant = Guid.NewGuid();
        var at = DateTimeOffset.UtcNow.AddDays(-1);
        var events = Enumerable.Range(0, 23).Select(i => E(i < 10 ? at : at.AddSeconds(-i), tenant: tenant)).ToList();
        foreach (var e in events) await Log.RecordAsync(e);

        var seen = new List<AuditEvent>();
        (DateTimeOffset, Guid)? before = null;
        while (true)
        {
            var page = await Log.QueryAsync(new AuditQuery { TenantId = tenant, Limit = 4, Before = before });
            if (page.Count == 0) break;
            seen.AddRange(page);
            before = (page[^1].OccurredAt, page[^1].Id);
        }

        Assert.Equal(events.Select(e => e.Id).Order(), seen.Select(e => e.Id).Order());
        Assert.Equal(seen.Count, seen.Select(e => e.Id).Distinct().Count());
        Assert.True(seen.Zip(seen.Skip(1)).All(p => p.First.OccurredAt >= p.Second.OccurredAt));
    }

    [PostgresFact]
    public async Task FiltersTranslateToSql()
    {
        var tenant = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;
        await Log.RecordAsync(E(now.AddMinutes(-1), "Kim <kim@client.example>", "100% done_ok", tenant, AuditActions.SignIn, AuditOutcome.Denied));
        await Log.RecordAsync(E(now.AddMinutes(-2), "Pat", "100 percent doneXok", tenant, AuditActions.Invited));
        await Log.RecordAsync(E(now.AddDays(-10), "Pat", "old", tenant, AuditActions.Removed));

        AuditQuery Q(AuditQuery q) => q with { TenantId = tenant };
        Assert.Single(await Log.QueryAsync(Q(new() { Category = "auth" })));
        Assert.Single(await Log.QueryAsync(Q(new() { Outcome = AuditOutcome.Denied })));
        Assert.Equal(2, (await Log.QueryAsync(Q(new() { From = now.AddDays(-1) }))).Count);
        Assert.Single(await Log.QueryAsync(Q(new() { Search = "KIM@CLIENT" })));
        // LIKE wildcards in the search box are literal text, not patterns (unescaped, each would match more rows).
        Assert.Single(await Log.QueryAsync(Q(new() { Search = "100%" })));
        Assert.Single(await Log.QueryAsync(Q(new() { Search = "done_ok" })));
        Assert.Single(await Log.QueryAsync(Q(new() { Search = "%" })));
    }

    [PostgresFact]
    public async Task LongValuesAreClippedNotRejected()
    {
        var tenant = Guid.NewGuid();
        await Log.RecordAsync(E(DateTimeOffset.UtcNow, new string('a', 2000), new string('s', 5000), tenant));

        var e = Assert.Single(await Log.QueryAsync(new AuditQuery { TenantId = tenant }));
        Assert.Equal(512, e.ActorName.Length);
        Assert.Equal(1000, e.Summary.Length);
    }
}

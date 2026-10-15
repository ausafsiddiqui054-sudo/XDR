using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

/// <summary>
/// Export checkpoints in <c>audit_export_checkpoints</c>. A lease holds the destination's row lock
/// (FOR UPDATE SKIP LOCKED) in an open transaction, so two Workers never send the same batch, and the
/// checkpoint only moves when the lease is committed after the destination accepted the events.
/// </summary>
public sealed class EfAuditExportStore(IDbContextFactory<SecurePulseDbContext> factory, TimeProvider time) : IAuditExportStore
{
    private const int MaxErrorLength = 2000;

    public async Task<IAuditExportLease?> TryLeaseAsync(string destination, TimeSpan lag, int maxEvents, CancellationToken ct = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEvents, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(lag, TimeSpan.Zero);

        var db = await factory.CreateDbContextAsync(ct);
        IDbContextTransaction? tx = null;
        try
        {
            // The row must exist to be locked; a new destination starts before the oldest event.
            await db.Database.ExecuteSqlAsync($"""
                INSERT INTO audit_export_checkpoints ("Destination", "ExportedCount") VALUES ({destination}, 0)
                ON CONFLICT ("Destination") DO NOTHING
                """, ct);

            tx = await db.Database.BeginTransactionAsync(ct);
            var checkpoint = (await db.AuditExportCheckpoints.FromSql($"""
                SELECT * FROM audit_export_checkpoints WHERE "Destination" = {destination} FOR UPDATE SKIP LOCKED
                """).ToListAsync(ct)).SingleOrDefault();
            if (checkpoint is null)
            {
                await tx.DisposeAsync();
                await db.DisposeAsync();
                return null; // another Worker is exporting
            }

            var seconds = lag.TotalSeconds;
            var rows = checkpoint.RecordedAt is { } after && checkpoint.LastId is { } afterId
                ? await db.AuditEvents.FromSql($"""
                    SELECT * FROM audit_events
                    WHERE ("RecordedAt", "Id") > ({after}, {afterId})
                      AND "RecordedAt" < clock_timestamp() - make_interval(secs => {seconds})
                    ORDER BY "RecordedAt", "Id" LIMIT {maxEvents}
                    """).AsNoTracking().ToListAsync(ct)
                : await db.AuditEvents.FromSql($"""
                    SELECT * FROM audit_events
                    WHERE "RecordedAt" < clock_timestamp() - make_interval(secs => {seconds})
                    ORDER BY "RecordedAt", "Id" LIMIT {maxEvents}
                    """).AsNoTracking().ToListAsync(ct);

            return new Lease(db, tx, destination, rows, time);
        }
        catch
        {
            if (tx is not null) await tx.DisposeAsync();
            await db.DisposeAsync();
            throw;
        }
    }

    public async Task RecordFailureAsync(string destination, string error, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var trimmed = error.Length > MaxErrorLength ? error[..MaxErrorLength] : error;
        var now = time.GetUtcNow();
        await db.AuditExportCheckpoints.Where(c => c.Destination == destination)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.LastAttemptAt, now).SetProperty(c => c.LastError, trimmed), ct);
    }

    public async Task<AuditExportStatus?> GetStatusAsync(string destination, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        if (await db.AuditExportCheckpoints.AsNoTracking().FirstOrDefaultAsync(c => c.Destination == destination, ct) is not { } c)
            return null;

        var pending = c.RecordedAt is { } after && c.LastId is { } afterId
            ? await db.Database.SqlQuery<long>($"""
                SELECT count(*) AS "Value" FROM audit_events WHERE ("RecordedAt", "Id") > ({after}, {afterId})
                """).SingleAsync(ct)
            : await db.AuditEvents.LongCountAsync(ct);

        return new AuditExportStatus
        {
            Destination = c.Destination,
            ExportedCount = c.ExportedCount,
            Pending = pending,
            LastExportedAt = c.LastExportedAt,
            LastAttemptAt = c.LastAttemptAt,
            LastError = c.LastError
        };
    }

    private sealed class Lease(SecurePulseDbContext db, IDbContextTransaction tx, string destination, List<AuditEventEntity> rows, TimeProvider time)
        : IAuditExportLease
    {
        private bool _done;
        private bool _disposed;

        public IReadOnlyList<AuditEvent> Events { get; } = rows.Select(r => r.ToModel()).ToList();

        public async Task CommitAsync(int count, CancellationToken ct = default)
        {
            ObjectDisposedException.ThrowIf(_done, this);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, rows.Count);

            var now = time.GetUtcNow();
            if (count == 0)
            {
                await db.AuditExportCheckpoints.Where(c => c.Destination == destination)
                    .ExecuteUpdateAsync(s => s.SetProperty(c => c.LastAttemptAt, now).SetProperty(c => c.LastError, (string?)null), ct);
            }
            else
            {
                var last = rows[count - 1];
                await db.AuditExportCheckpoints.Where(c => c.Destination == destination)
                    .ExecuteUpdateAsync(s => s
                        .SetProperty(c => c.RecordedAt, last.RecordedAt)
                        .SetProperty(c => c.LastId, last.Id)
                        .SetProperty(c => c.ExportedCount, c => c.ExportedCount + count)
                        .SetProperty(c => c.LastExportedAt, now)
                        .SetProperty(c => c.LastAttemptAt, now)
                        .SetProperty(c => c.LastError, (string?)null), ct);
            }
            await tx.CommitAsync(ct);
            _done = true;
        }

        public async ValueTask DisposeAsync()
        {
            // Not committed: the transaction rolls back and the checkpoint stays where it was. Safe to call twice.
            if (_disposed) return;
            _disposed = true;
            _done = true;
            await tx.DisposeAsync();
            await db.DisposeAsync();
        }
    }
}

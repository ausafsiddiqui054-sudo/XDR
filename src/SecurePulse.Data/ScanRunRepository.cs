using Microsoft.EntityFrameworkCore;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class EfScanRunRepository(IDbContextFactory<SecurePulseDbContext> factory) : IScanRunRepository
{
    private const int MaxErrorLength = 2000;

    public async Task<(ScanRun Run, bool Created)> EnqueueAsync(Guid tenantId, string engine, ScanTrigger trigger, string? requestedBy,
        DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var run = new ScanRunEntity
        {
            Id = Guid.NewGuid(), TenantId = tenantId, Engine = engine, Trigger = trigger, Status = ScanRunStatus.Queued,
            QueuedAt = at, RequestedBy = requestedBy
        };
        db.ScanRuns.Add(run);
        try
        {
            await db.SaveChangesAsync(ct);
            return (run.ToModel(), true);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_scan_runs_active" })
        {
            // Already queued or running: hand back that run instead of a duplicate.
            await using var read = await factory.CreateDbContextAsync(ct);
            var active = await read.ScanRuns.AsNoTracking().FirstAsync(r => r.TenantId == tenantId && r.Engine == engine
                && (r.Status == ScanRunStatus.Queued || r.Status == ScanRunStatus.Running), ct);
            return (active.ToModel(), false);
        }
    }

    public async Task<ScanRun?> ClaimNextAsync(IReadOnlyCollection<string> engines, DateTimeOffset at, CancellationToken ct = default)
    {
        if (engines.Count == 0) return null;
        await using var db = await factory.CreateDbContextAsync(ct);
        var names = engines.ToArray();

        // SKIP LOCKED: concurrent claimers each get a different row (or none) without blocking.
        var claimed = await db.ScanRuns.FromSql($"""
            UPDATE scan_runs SET "Status" = 'Running', "StartedAt" = {at}
            WHERE "Id" = (
                SELECT "Id" FROM scan_runs
                WHERE "Status" = 'Queued' AND "Engine" = ANY({names})
                ORDER BY CASE WHEN "Trigger" = 'Manual' THEN 0 ELSE 1 END, "QueuedAt"
                LIMIT 1
                FOR UPDATE SKIP LOCKED)
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return claimed.FirstOrDefault()?.ToModel();
    }

    public async Task CompleteAsync(Guid runId, bool succeeded, int? findingCount, string? error, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = succeeded ? ScanRunStatus.Succeeded : ScanRunStatus.Failed;
        var trimmed = error is { Length: > MaxErrorLength } ? error[..MaxErrorLength] : error;
        await db.ScanRuns.Where(r => r.Id == runId && r.Status == ScanRunStatus.Running)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, status)
                .SetProperty(r => r.CompletedAt, at)
                .SetProperty(r => r.FindingCount, findingCount)
                .SetProperty(r => r.Error, trimmed), ct);
    }

    public async Task<int> FailStaleAsync(DateTimeOffset startedBefore, string error, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.ScanRuns.Where(r => r.Status == ScanRunStatus.Running && r.StartedAt < startedBefore)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, ScanRunStatus.Failed)
                .SetProperty(r => r.CompletedAt, at)
                .SetProperty(r => r.Error, error), ct);
    }

    public async Task<IReadOnlyList<ScanRun>> GetLatestAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var latest = await db.ScanRuns.FromSql($"""
            SELECT DISTINCT ON ("TenantId", "Engine") * FROM scan_runs
            ORDER BY "TenantId", "Engine", "QueuedAt" DESC
            """).AsNoTracking().ToListAsync(ct);
        return latest.Select(r => r.ToModel()).ToList();
    }
}

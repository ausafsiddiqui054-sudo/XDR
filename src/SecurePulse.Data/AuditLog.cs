using Microsoft.EntityFrameworkCore;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class EfAuditLog(IDbContextFactory<SecurePulseDbContext> factory) : IAuditLog
{
    public async Task RecordAsync(AuditEvent e, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.AuditEvents.Add(new AuditEventEntity
        {
            Id = e.Id,
            OccurredAt = e.OccurredAt,
            Action = Clip(e.Action, 64)!,
            Category = Clip(e.Category, 32)!,
            Outcome = e.Outcome,
            ActorUserId = e.ActorUserId,
            ActorName = Clip(e.ActorName, 512)!,
            TenantId = e.TenantId,
            TargetType = Clip(e.TargetType, 64),
            TargetId = Clip(e.TargetId, 128),
            Summary = Clip(e.Summary, 1000)!,
            Details = e.Details.ToDictionary(kv => Clip(kv.Key, 100)!, kv => Clip(kv.Value, 2000)!),
            IpAddress = Clip(e.IpAddress, 64)
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AuditEvent>> QueryAsync(AuditQuery q, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = db.AuditEvents.AsNoTracking();

        if (q.From is { } from) rows = rows.Where(e => e.OccurredAt >= from);
        if (q.To is { } to) rows = rows.Where(e => e.OccurredAt < to);
        if (!string.IsNullOrEmpty(q.Category)) rows = rows.Where(e => e.Category == q.Category);
        if (!string.IsNullOrEmpty(q.Action)) rows = rows.Where(e => e.Action == q.Action);
        if (q.Outcome is { } outcome) rows = rows.Where(e => e.Outcome == outcome);
        if (q.TenantId is { } tenantId) rows = rows.Where(e => e.TenantId == tenantId);
        if (!string.IsNullOrWhiteSpace(q.Search))
        {
            var pattern = "%" + EscapeLike(q.Search.Trim()) + "%";
            // Pass the escape character explicitly: Npgsql's two-argument ILike emits ESCAPE '' (none).
            rows = rows.Where(e => EF.Functions.ILike(e.ActorName, pattern, "\\") || EF.Functions.ILike(e.Summary, pattern, "\\"));
        }
        if (q.Before is { } before)
            rows = rows.Where(e => e.OccurredAt < before.OccurredAt || (e.OccurredAt == before.OccurredAt && e.Id.CompareTo(before.Id) < 0));

        var list = await rows.OrderByDescending(e => e.OccurredAt).ThenByDescending(e => e.Id)
            .Take(Math.Clamp(q.Limit, 1, 1000))
            .ToListAsync(ct);
        return list.Select(e => e.ToModel()).ToList();
    }

    // Escapes LIKE wildcards with backslash, the escape character passed to ILike above.
    private static string EscapeLike(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    private static string? Clip(string? s, int max) => s is null || s.Length <= max ? s : s[..max];
}

using Microsoft.EntityFrameworkCore;
using Npgsql;
using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Data.Entities;

namespace Hasinix.Data;

/// <summary>
/// Like the action queues: every acceptance change is one conditional UPDATE on the current state, so two
/// people acting at once can't both win. Rows are created on first use (owner set, or acceptance requested).
/// </summary>
public sealed class EfFindingTrackingRepository(IDbContextFactory<HasinixDbContext> factory) : IFindingTrackingRepository
{
    private const int MaxTitleLength = 512;

    public async Task<IReadOnlyList<FindingTracking>> GetAllAsync(Guid? tenantId = null, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.FindingTracking.AsNoTracking().Where(t => tenantId == null || t.TenantId == tenantId).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<FindingTracking?> GetAsync(Guid tenantId, string findingId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.FindingTracking.AsNoTracking().FirstOrDefaultAsync(t => t.TenantId == tenantId && t.FindingId == findingId, ct))?.ToModel();
    }

    public async Task<FindingTracking> SetOwnerAsync(Guid tenantId, string findingId, string findingTitle, string? owner, DateOnly? dueDate,
        DateTimeOffset at, CancellationToken ct = default)
    {
        var title = Clip(findingTitle);
        // Update, or insert when there is no row yet; if someone inserts in between, the second pass updates theirs.
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await using var db = await factory.CreateDbContextAsync(ct);
            var changed = await db.FindingTracking.Where(t => t.TenantId == tenantId && t.FindingId == findingId)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(t => t.Owner, owner)
                    .SetProperty(t => t.DueDate, dueDate)
                    .SetProperty(t => t.FindingTitle, title)
                    .SetProperty(t => t.UpdatedAt, at), ct);
            if (changed > 0) break;

            db.FindingTracking.Add(new FindingTrackingEntity
            {
                TenantId = tenantId, FindingId = findingId, FindingTitle = title, Owner = owner, DueDate = dueDate,
                Acceptance = RiskAcceptanceStatus.None, UpdatedAt = at
            });
            try
            {
                await db.SaveChangesAsync(ct);
                break;
            }
            catch (DbUpdateException ex) when (attempt == 0 && ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
            }
        }
        return (await GetAsync(tenantId, findingId, ct))!;
    }

    public async Task<FindingTracking?> RequestAcceptanceAsync(Guid tenantId, string findingId, string findingTitle, string reason, DateTimeOffset expiresAt,
        Guid requestedByUserId, string requestedByName, DateTimeOffset at, CancellationToken ct = default)
    {
        var title = Clip(findingTitle);
        await using var db = await factory.CreateDbContextAsync(ct);
        var changed = await db.FindingTracking
            .Where(t => t.TenantId == tenantId && t.FindingId == findingId && t.Acceptance != RiskAcceptanceStatus.Requested
                        && !(t.Acceptance == RiskAcceptanceStatus.Accepted && t.AcceptanceExpiresAt > at))
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.Acceptance, RiskAcceptanceStatus.Requested)
                .SetProperty(t => t.AcceptanceReason, reason)
                .SetProperty(t => t.AcceptanceExpiresAt, expiresAt)
                .SetProperty(t => t.RequestedByUserId, requestedByUserId)
                .SetProperty(t => t.RequestedByName, requestedByName)
                .SetProperty(t => t.RequestedAt, at)
                .SetProperty(t => t.DecidedByUserId, (Guid?)null)
                .SetProperty(t => t.DecidedByName, (string?)null)
                .SetProperty(t => t.DecidedAt, (DateTimeOffset?)null)
                .SetProperty(t => t.DecisionNote, (string?)null)
                .SetProperty(t => t.FindingTitle, title)
                .SetProperty(t => t.UpdatedAt, at), ct);
        if (changed == 0)
        {
            // Either the row exists and already has a waiting request or a running acceptance, or there is no row yet.
            if (await db.FindingTracking.AnyAsync(t => t.TenantId == tenantId && t.FindingId == findingId, ct)) return null;
            db.FindingTracking.Add(new FindingTrackingEntity
            {
                TenantId = tenantId, FindingId = findingId, FindingTitle = title, Acceptance = RiskAcceptanceStatus.Requested,
                AcceptanceReason = reason, AcceptanceExpiresAt = expiresAt, RequestedByUserId = requestedByUserId,
                RequestedByName = requestedByName, RequestedAt = at, UpdatedAt = at
            });
            try
            {
                await db.SaveChangesAsync(ct);
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                // Someone else started tracking this finding at the same moment: theirs stands.
                return null;
            }
        }
        return await GetAsync(tenantId, findingId, ct);
    }

    public async Task<FindingTracking?> DecideAcceptanceAsync(Guid tenantId, string findingId, bool approve, Guid deciderId, string deciderName, string? note,
        DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = approve ? RiskAcceptanceStatus.Accepted : RiskAcceptanceStatus.Rejected;
        // A request whose end date has already passed can be rejected but not approved.
        var changed = await db.FindingTracking
            .Where(t => t.TenantId == tenantId && t.FindingId == findingId && t.Acceptance == RiskAcceptanceStatus.Requested
                        && (!approve || t.AcceptanceExpiresAt > at))
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.Acceptance, status)
                .SetProperty(t => t.DecidedByUserId, deciderId)
                .SetProperty(t => t.DecidedByName, deciderName)
                .SetProperty(t => t.DecidedAt, at)
                .SetProperty(t => t.DecisionNote, note)
                .SetProperty(t => t.UpdatedAt, at), ct);
        return changed == 0 ? null : await GetAsync(tenantId, findingId, ct);
    }

    public async Task<FindingTracking?> EndAcceptanceAsync(Guid tenantId, string findingId, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var changed = await db.FindingTracking
            .Where(t => t.TenantId == tenantId && t.FindingId == findingId
                        && (t.Acceptance == RiskAcceptanceStatus.Requested || t.Acceptance == RiskAcceptanceStatus.Accepted))
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.Acceptance, RiskAcceptanceStatus.None)
                .SetProperty(t => t.AcceptanceReason, (string?)null)
                .SetProperty(t => t.AcceptanceExpiresAt, (DateTimeOffset?)null)
                .SetProperty(t => t.RequestedByUserId, (Guid?)null)
                .SetProperty(t => t.RequestedByName, (string?)null)
                .SetProperty(t => t.RequestedAt, (DateTimeOffset?)null)
                .SetProperty(t => t.DecidedByUserId, (Guid?)null)
                .SetProperty(t => t.DecidedByName, (string?)null)
                .SetProperty(t => t.DecidedAt, (DateTimeOffset?)null)
                .SetProperty(t => t.DecisionNote, (string?)null)
                .SetProperty(t => t.UpdatedAt, at), ct);
        return changed == 0 ? null : await GetAsync(tenantId, findingId, ct);
    }

    private static string Clip(string title) => title.Length > MaxTitleLength ? title[..MaxTitleLength] : title;
}

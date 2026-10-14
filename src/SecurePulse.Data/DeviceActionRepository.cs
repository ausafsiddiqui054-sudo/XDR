using Microsoft.EntityFrameworkCore;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

/// <summary>
/// Every transition is one conditional UPDATE on the current status, so concurrent approvers,
/// cancellers and Workers can't both win: whoever loses gets null or zero rows back.
/// </summary>
public sealed class EfDeviceActionRepository(IDbContextFactory<SecurePulseDbContext> factory) : IDeviceActionRepository
{
    private const int MaxErrorLength = 2000;

    public async Task<(DeviceActionRequest Request, bool Created)> AddAsync(DeviceActionRequest request, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.DeviceActions.Add(request.ToEntity());
        try
        {
            await db.SaveChangesAsync(ct);
            return (request, true);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_device_actions_open" })
        {
            await using var read = await factory.CreateDbContextAsync(ct);
            var open = await read.DeviceActions.AsNoTracking().FirstAsync(a => a.TenantId == request.TenantId && a.DeviceId == request.DeviceId
                && (a.Status == DeviceActionStatus.PendingApproval || a.Status == DeviceActionStatus.Approved || a.Status == DeviceActionStatus.Sending), ct);
            return (open.ToModel(), false);
        }
    }

    public async Task<DeviceActionRequest?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.DeviceActions.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, ct))?.ToModel();
    }

    public async Task<IReadOnlyList<DeviceActionRequest>> QueryAsync(DeviceActionQuery query, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var q = db.DeviceActions.AsNoTracking();
        if (query.TenantId is { } tenantId) q = q.Where(a => a.TenantId == tenantId);
        if (query.DeviceId is { } deviceId) q = q.Where(a => a.DeviceId == deviceId);
        if (query.OpenOnly)
            q = q.Where(a => a.Status == DeviceActionStatus.PendingApproval || a.Status == DeviceActionStatus.Approved || a.Status == DeviceActionStatus.Sending);
        var rows = await q.OrderByDescending(a => a.RequestedAt).ThenBy(a => a.Id).Take(Math.Clamp(query.Limit, 1, 1000)).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<DeviceActionRequest?> DecideAsync(Guid id, bool approve, Guid deciderId, string deciderName, PortalRole deciderRole, string? note,
        DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = approve ? DeviceActionStatus.Approved : DeviceActionStatus.Rejected;
        var changed = await db.DeviceActions
            .Where(a => a.Id == id && a.Status == DeviceActionStatus.PendingApproval && a.ExpiresAt > at)
            .ExecuteUpdateAsync(s => s
                .SetProperty(a => a.Status, status)
                .SetProperty(a => a.DecidedAt, at)
                .SetProperty(a => a.DecidedByUserId, deciderId)
                .SetProperty(a => a.DecidedByName, deciderName)
                .SetProperty(a => a.DecidedByRole, deciderRole)
                .SetProperty(a => a.DecisionNote, note), ct);
        return changed == 0 ? null : await GetAsync(id, ct);
    }

    public async Task<DeviceActionRequest?> CancelAsync(Guid id, string cancelledBy, string? reason, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var changed = await db.DeviceActions
            .Where(a => a.Id == id && (a.Status == DeviceActionStatus.PendingApproval || a.Status == DeviceActionStatus.Approved))
            .ExecuteUpdateAsync(s => s
                .SetProperty(a => a.Status, DeviceActionStatus.Cancelled)
                .SetProperty(a => a.CancelledAt, at)
                .SetProperty(a => a.CancelledBy, cancelledBy)
                .SetProperty(a => a.Error, reason), ct);
        return changed == 0 ? null : await GetAsync(id, ct);
    }

    public async Task<IReadOnlyList<DeviceActionRequest>> CancelOpenForTenantAsync(Guid tenantId, string cancelledBy, string reason, DateTimeOffset at,
        CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.DeviceActions.FromSql($"""
            UPDATE device_actions SET "Status" = 'Cancelled', "CancelledAt" = {at}, "CancelledBy" = {cancelledBy}, "Error" = {reason}
            WHERE "TenantId" = {tenantId} AND "Status" IN ('PendingApproval', 'Approved')
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<DeviceActionRequest?> ClaimNextApprovedAsync(DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // SKIP LOCKED: two Workers never claim the same action.
        var claimed = await db.DeviceActions.FromSql($"""
            UPDATE device_actions SET "Status" = 'Sending', "SentAt" = {at}
            WHERE "Id" = (
                SELECT "Id" FROM device_actions
                WHERE "Status" = 'Approved'
                ORDER BY "DecidedAt"
                LIMIT 1
                FOR UPDATE SKIP LOCKED)
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return claimed.FirstOrDefault()?.ToModel();
    }

    public async Task CompleteAsync(Guid id, bool succeeded, string? error, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = succeeded ? DeviceActionStatus.Sent : DeviceActionStatus.Failed;
        var trimmed = error is { Length: > MaxErrorLength } ? error[..MaxErrorLength] : error;
        await db.DeviceActions.Where(a => a.Id == id && a.Status == DeviceActionStatus.Sending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(a => a.Status, status)
                .SetProperty(a => a.CompletedAt, at)
                .SetProperty(a => a.Error, trimmed), ct);
    }

    public async Task<IReadOnlyList<DeviceActionRequest>> ExpireAsync(DateTimeOffset at, TimeSpan sendWindow, DateTimeOffset sendingBefore,
        CancellationToken ct = default)
    {
        var approvedBefore = at - sendWindow;
        await using var db = await factory.CreateDbContextAsync(ct);
        var expired = await db.DeviceActions.FromSql($"""
            UPDATE device_actions SET "Status" = 'Expired', "CompletedAt" = {at},
                "Error" = CASE WHEN "Status" = 'PendingApproval'
                    THEN {ExpiredPendingMessage}
                    ELSE {ExpiredApprovedMessage} END
            WHERE ("Status" = 'PendingApproval' AND "ExpiresAt" <= {at})
               OR ("Status" = 'Approved' AND "DecidedAt" < {approvedBefore})
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        var stuck = await db.DeviceActions.FromSql($"""
            UPDATE device_actions SET "Status" = 'Failed', "CompletedAt" = {at}, "Error" = {StuckSendingMessage}
            WHERE "Status" = 'Sending' AND "SentAt" < {sendingBefore}
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return expired.Concat(stuck).Select(r => r.ToModel()).ToList();
    }

    public const string ExpiredPendingMessage = "Nobody approved it in time.";
    public const string ExpiredApprovedMessage = "Approved, but not sent in time (the Worker wasn't running). Request it again if it's still needed.";
    public const string StuckSendingMessage =
        "No result was recorded (the Worker stopped while sending). It may have reached Intune: check the device in Intune before requesting it again.";
}

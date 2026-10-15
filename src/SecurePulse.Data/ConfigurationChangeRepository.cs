using Microsoft.EntityFrameworkCore;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

/// <summary>Same rules as the device action queue: each transition is one conditional UPDATE on the current status.</summary>
public sealed class EfConfigurationChangeRepository(IDbContextFactory<SecurePulseDbContext> factory) : IConfigurationChangeRepository
{
    private const int MaxErrorLength = 2000;

    public async Task<(ConfigurationChangeRequest Request, bool Created)> AddAsync(ConfigurationChangeRequest request, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.ConfigurationChanges.Add(request.ToEntity());
        try
        {
            await db.SaveChangesAsync(ct);
            return (request, true);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation, ConstraintName: "IX_configuration_changes_open" })
        {
            await using var read = await factory.CreateDbContextAsync(ct);
            var open = await read.ConfigurationChanges.AsNoTracking().FirstAsync(c => c.TenantId == request.TenantId && c.FixId == request.FixId
                && (c.Status == DeviceActionStatus.PendingApproval || c.Status == DeviceActionStatus.Approved || c.Status == DeviceActionStatus.Sending), ct);
            return (open.ToModel(), false);
        }
    }

    public async Task<ConfigurationChangeRequest?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.ConfigurationChanges.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct))?.ToModel();
    }

    public async Task<IReadOnlyList<ConfigurationChangeRequest>> QueryAsync(ConfigurationChangeQuery query, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var q = db.ConfigurationChanges.AsNoTracking();
        if (query.TenantId is { } tenantId) q = q.Where(c => c.TenantId == tenantId);
        if (query.OpenOnly)
            q = q.Where(c => c.Status == DeviceActionStatus.PendingApproval || c.Status == DeviceActionStatus.Approved || c.Status == DeviceActionStatus.Sending);
        return (await q.OrderByDescending(c => c.RequestedAt).Take(Math.Clamp(query.Limit, 1, 1000)).ToListAsync(ct)).Select(c => c.ToModel()).ToList();
    }

    public async Task<ConfigurationChangeRequest?> DecideAsync(Guid id, bool approve, Guid deciderId, string deciderName, PortalRole deciderRole,
        string? note, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = approve ? DeviceActionStatus.Approved : DeviceActionStatus.Rejected;
        var changed = await db.ConfigurationChanges
            .Where(c => c.Id == id && c.Status == DeviceActionStatus.PendingApproval && c.ExpiresAt > at)
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Status, status)
                .SetProperty(c => c.DecidedAt, at)
                .SetProperty(c => c.DecidedByUserId, deciderId)
                .SetProperty(c => c.DecidedByName, deciderName)
                .SetProperty(c => c.DecidedByRole, deciderRole)
                .SetProperty(c => c.DecisionNote, note), ct);
        return changed == 0 ? null : await GetAsync(id, ct);
    }

    public async Task<ConfigurationChangeRequest?> CancelAsync(Guid id, string cancelledBy, string? reason, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var changed = await db.ConfigurationChanges
            .Where(c => c.Id == id && (c.Status == DeviceActionStatus.PendingApproval || c.Status == DeviceActionStatus.Approved))
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Status, DeviceActionStatus.Cancelled)
                .SetProperty(c => c.CancelledAt, at)
                .SetProperty(c => c.CancelledBy, cancelledBy)
                .SetProperty(c => c.Error, reason), ct);
        return changed == 0 ? null : await GetAsync(id, ct);
    }

    public async Task<IReadOnlyList<ConfigurationChangeRequest>> CancelOpenForTenantAsync(Guid tenantId, string cancelledBy, string reason,
        DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.ConfigurationChanges.FromSql($"""
            UPDATE configuration_changes SET "Status" = 'Cancelled', "CancelledAt" = {at}, "CancelledBy" = {cancelledBy}, "Error" = {reason}
            WHERE "TenantId" = {tenantId} AND "Status" IN ('PendingApproval', 'Approved')
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<ConfigurationChangeRequest?> ClaimNextApprovedAsync(DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // SKIP LOCKED: two Workers never claim the same change.
        var claimed = await db.ConfigurationChanges.FromSql($"""
            UPDATE configuration_changes SET "Status" = 'Sending', "SentAt" = {at}
            WHERE "Id" = (
                SELECT "Id" FROM configuration_changes
                WHERE "Status" = 'Approved'
                ORDER BY "DecidedAt"
                LIMIT 1
                FOR UPDATE SKIP LOCKED)
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return claimed.FirstOrDefault()?.ToModel();
    }

    public async Task CompleteAsync(Guid id, bool succeeded, string? error, string? policyId, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var status = succeeded ? DeviceActionStatus.Sent : DeviceActionStatus.Failed;
        var trimmed = error is { Length: > MaxErrorLength } ? error[..MaxErrorLength] : error;
        await db.ConfigurationChanges.Where(c => c.Id == id && c.Status == DeviceActionStatus.Sending)
            .ExecuteUpdateAsync(s => s
                .SetProperty(c => c.Status, status)
                .SetProperty(c => c.CompletedAt, at)
                .SetProperty(c => c.Error, trimmed)
                .SetProperty(c => c.PolicyId, policyId), ct);
    }

    public async Task<IReadOnlyList<ConfigurationChangeRequest>> ExpireAsync(DateTimeOffset at, TimeSpan sendWindow, DateTimeOffset sendingBefore,
        CancellationToken ct = default)
    {
        var approvedBefore = at - sendWindow;
        await using var db = await factory.CreateDbContextAsync(ct);
        var expired = await db.ConfigurationChanges.FromSql($"""
            UPDATE configuration_changes SET "Status" = 'Expired', "CompletedAt" = {at},
                "Error" = CASE WHEN "Status" = 'PendingApproval'
                    THEN {EfDeviceActionRepository.ExpiredPendingMessage}
                    ELSE {EfDeviceActionRepository.ExpiredApprovedMessage} END
            WHERE ("Status" = 'PendingApproval' AND "ExpiresAt" <= {at})
               OR ("Status" = 'Approved' AND "DecidedAt" < {approvedBefore})
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        var stuck = await db.ConfigurationChanges.FromSql($"""
            UPDATE configuration_changes SET "Status" = 'Failed', "CompletedAt" = {at}, "Error" = {StuckSendingMessage}
            WHERE "Status" = 'Sending' AND "SentAt" < {sendingBefore}
            RETURNING *
            """).AsNoTracking().ToListAsync(ct);
        return expired.Concat(stuck).Select(r => r.ToModel()).ToList();
    }

    public async Task<bool> HasPlaybookProposalSinceAsync(Guid playbookId, Guid tenantId, DateTimeOffset since, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.ConfigurationChanges.AnyAsync(c => c.PlaybookId == playbookId && c.TenantId == tenantId && c.RequestedAt >= since, ct);
    }

    public const string StuckSendingMessage =
        "No result was recorded (the Worker stopped while sending). The policy may have been created: check Conditional Access in Entra before requesting it again.";
}

public sealed class EfFindingPlaybookRepository(IDbContextFactory<SecurePulseDbContext> factory) : IFindingPlaybookRepository
{
    public async Task<IReadOnlyList<FindingPlaybook>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.FindingPlaybooks.AsNoTracking().OrderBy(p => p.FixId).ThenBy(p => p.CreatedAt).ToListAsync(ct)).Select(p => p.ToModel()).ToList();
    }

    public async Task<FindingPlaybook?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.FindingPlaybooks.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct))?.ToModel();
    }

    public async Task AddAsync(FindingPlaybook playbook, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.FindingPlaybooks.Add(playbook.ToEntity());
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> UpdateAsync(FindingPlaybook p, DateTimeOffset expectedUpdatedAt, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.FindingPlaybooks.Where(x => x.Id == p.Id && x.UpdatedAt == expectedUpdatedAt)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.FixId, p.FixId)
                .SetProperty(x => x.Enabled, p.Enabled)
                .SetProperty(x => x.TenantId, p.TenantId)
                .SetProperty(x => x.UpdatedByUserId, p.UpdatedByUserId)
                .SetProperty(x => x.UpdatedByName, p.UpdatedByName)
                .SetProperty(x => x.UpdatedAt, p.UpdatedAt), ct) > 0;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.FindingPlaybooks.Where(p => p.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task RecordRunAsync(Guid id, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await db.FindingPlaybooks.Where(p => p.Id == id).ExecuteUpdateAsync(s => s.SetProperty(p => p.LastRunAt, at), ct);
    }
}

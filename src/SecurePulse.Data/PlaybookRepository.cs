using Microsoft.EntityFrameworkCore;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class EfPlaybookRepository(IDbContextFactory<SecurePulseDbContext> factory) : IPlaybookRepository
{
    public async Task<IReadOnlyList<RemediationPlaybook>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.Playbooks.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct)).Select(p => p.ToModel()).ToList();
    }

    public async Task<RemediationPlaybook?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.Playbooks.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct))?.ToModel();
    }

    public async Task AddAsync(RemediationPlaybook playbook, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.Playbooks.Add(playbook.ToEntity());
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> UpdateAsync(RemediationPlaybook p, DateTimeOffset expectedUpdatedAt, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // Conditional on the version the editor saw; the run fields belong to the Worker and aren't touched.
        return await db.Playbooks.Where(x => x.Id == p.Id && x.UpdatedAt == expectedUpdatedAt)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.Name, p.Name)
                .SetProperty(x => x.Enabled, p.Enabled)
                .SetProperty(x => x.Trigger, p.Trigger)
                .SetProperty(x => x.Days, p.Days)
                .SetProperty(x => x.Action, p.Action)
                .SetProperty(x => x.TenantId, p.TenantId)
                .SetProperty(x => x.MaxPerRun, p.MaxPerRun)
                .SetProperty(x => x.Cooldown, p.Cooldown)
                .SetProperty(x => x.UpdatedByUserId, p.UpdatedByUserId)
                .SetProperty(x => x.UpdatedByName, p.UpdatedByName)
                .SetProperty(x => x.UpdatedAt, p.UpdatedAt)
                .SetProperty(x => x.DailyAutoLimit, p.DailyAutoLimit)
                .SetProperty(x => x.PreApprovedByUserId, p.PreApprovedByUserId)
                .SetProperty(x => x.PreApprovedByName, p.PreApprovedByName)
                .SetProperty(x => x.PreApprovedAt, p.PreApprovedAt)
                .SetProperty(x => x.PreApprovalExpiresAt, p.PreApprovalExpiresAt), ct) > 0;
    }

    public async Task<bool> GrantPreApprovalAsync(Guid id, DateTimeOffset expectedUpdatedAt, Guid byUserId, string byName, DateTimeOffset at,
        DateTimeOffset expiresAt, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // Conditional on the version the Owner reviewed: an edit in between means they approved something else.
        return await db.Playbooks.Where(x => x.Id == id && x.UpdatedAt == expectedUpdatedAt && x.UpdatedByUserId != byUserId)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.PreApprovedByUserId, byUserId)
                .SetProperty(x => x.PreApprovedByName, byName)
                .SetProperty(x => x.PreApprovedAt, at)
                .SetProperty(x => x.PreApprovalExpiresAt, expiresAt), ct) > 0;
    }

    public async Task<bool> WithdrawPreApprovalAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.Playbooks.Where(x => x.Id == id && x.PreApprovedByUserId != null)
            .ExecuteUpdateAsync(s => s
                .SetProperty(x => x.PreApprovedByUserId, (Guid?)null)
                .SetProperty(x => x.PreApprovedByName, (string?)null)
                .SetProperty(x => x.PreApprovedAt, (DateTimeOffset?)null)
                .SetProperty(x => x.PreApprovalExpiresAt, (DateTimeOffset?)null), ct) > 0;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.Playbooks.Where(p => p.Id == id).ExecuteDeleteAsync(ct) > 0;
    }

    public async Task RecordRunAsync(Guid id, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await db.Playbooks.Where(p => p.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.LastRunAt, at), ct);
    }
}

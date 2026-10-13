using System.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class EfPortalUserRepository(IDbContextFactory<SecurePulseDbContext> factory) : IPortalUserRepository
{
    public async Task<IReadOnlyList<PortalUser>> GetAllAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.PortalUsers.AsNoTracking().OrderBy(u => u.Role).ThenBy(u => u.UserPrincipalName).ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<PortalUser?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.PortalUsers.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct))?.ToModel();
    }

    public async Task<PortalUser?> FindByObjectIdAsync(Guid entraTenantId, Guid objectId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.PortalUsers.AsNoTracking()
            .FirstOrDefaultAsync(u => u.EntraTenantId == entraTenantId && u.ObjectId == objectId, ct))?.ToModel();
    }

    public async Task<PortalUser?> SignInAsync(Guid entraTenantId, Guid objectId, string? userPrincipalName, string? displayName,
        DateTimeOffset at, CancellationToken ct = default)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            await using var db = await factory.CreateDbContextAsync(ct);

            var user = await db.PortalUsers.FirstOrDefaultAsync(u => u.EntraTenantId == entraTenantId && u.ObjectId == objectId, ct);
            if (user is null && Normalize(userPrincipalName) is { } upn)
            {
                // First sign-in: claim the invitation issued for this sign-in name in this tenant.
                user = await db.PortalUsers.FirstOrDefaultAsync(
                    u => u.EntraTenantId == entraTenantId && u.UserPrincipalName == upn && u.ObjectId == null, ct);
                if (user is not null) user.ObjectId = objectId;
            }
            if (user is null) return null;

            user.LastSignInAt = at;
            if (!string.IsNullOrWhiteSpace(displayName)) user.DisplayName = displayName.Trim();

            try
            {
                await db.SaveChangesAsync(ct);
                return user.ToModel();
            }
            catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                // Two sign-ins raced to bind the same identity; the other won. Read the bound row.
            }
        }
        return await FindByObjectIdAsync(entraTenantId, objectId, ct);
    }

    public async Task AddAsync(PortalUser user, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.PortalUsers.Add(new PortalUserEntity
        {
            Id = user.Id,
            Role = user.Role,
            EntraTenantId = user.EntraTenantId,
            UserPrincipalName = Normalize(user.UserPrincipalName) ?? throw new ArgumentException("Sign-in name is required.", nameof(user)),
            ObjectId = user.ObjectId,
            DisplayName = user.DisplayName,
            ClientTenantId = user.ClientTenantId,
            CreatedAt = user.CreatedAt,
            CreatedBy = user.CreatedBy,
            LastSignInAt = user.LastSignInAt
        });
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw new DuplicatePortalUserException();
        }
    }

    public Task UpdateRoleAsync(Guid id, PortalRole role, Guid? clientTenantId, CancellationToken ct = default) =>
        ChangeOwnersSafelyAsync(id, async (db, user) =>
        {
            user.Role = role;
            user.ClientTenantId = role == PortalRole.ClientViewer ? clientTenantId : null;
            await db.SaveChangesAsync(ct);
        }, ct);

    public Task RemoveAsync(Guid id, CancellationToken ct = default) =>
        ChangeOwnersSafelyAsync(id, async (db, user) =>
        {
            db.PortalUsers.Remove(user);
            await db.SaveChangesAsync(ct);
        }, ct);

    /// <summary>
    /// Applies a change and refuses it if no signed-in Owner would remain. Serializable, so two
    /// Owners demoting each other at the same moment can't both succeed.
    /// </summary>
    private async Task ChangeOwnersSafelyAsync(Guid id, Func<SecurePulseDbContext, PortalUserEntity, Task> change, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);

        var user = await db.PortalUsers.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return;

        await change(db, user);

        var owners = await db.PortalUsers.CountAsync(u => u.Role == PortalRole.Owner && u.ObjectId != null, ct);
        if (owners == 0) throw new LastOwnerException(); // disposing the transaction rolls back

        await tx.CommitAsync(ct);
    }

    private static string? Normalize(string? upn) =>
        string.IsNullOrWhiteSpace(upn) ? null : upn.Trim().ToLowerInvariant();
}

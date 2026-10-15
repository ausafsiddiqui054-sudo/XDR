using Npgsql;
using Microsoft.EntityFrameworkCore;
using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Data.Entities;

namespace SecurePulse.Data;

public sealed class EfOnboardingRepository(IDbContextFactory<SecurePulseDbContext> factory) : IOnboardingRepository
{
    private const int MaxErrorLength = 2000;
    private static readonly TimeSpan OpenWindow = TimeSpan.FromDays(30);

    public async Task AddAsync(OnboardingRequest request, string stateHash, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        db.OnboardingRequests.Add(new OnboardingRequestEntity
        {
            Id = request.Id,
            Kind = request.Kind,
            DisplayName = request.DisplayName,
            PrimaryDomain = request.PrimaryDomain,
            PartnerName = request.PartnerName,
            Industry = request.Industry,
            EntraTenantId = request.EntraTenantId,
            Status = request.Status,
            CreatedAt = request.CreatedAt,
            ExpiresAt = request.ExpiresAt,
            StateHash = stateHash,
            ProtectedState = request.ProtectedState,
            StartedBy = request.StartedBy
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<OnboardingRequest?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.OnboardingRequests.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct))?.ToModel();
    }

    public async Task<OnboardingRequest?> FindByStateHashAsync(string stateHash, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return (await db.OnboardingRequests.AsNoTracking().FirstOrDefaultAsync(r => r.StateHash == stateHash, ct))?.ToModel();
    }

    public async Task<IReadOnlyList<OnboardingRequest>> GetOpenAsync(CancellationToken ct = default)
    {
        var since = DateTimeOffset.UtcNow - OpenWindow;
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.OnboardingRequests.AsNoTracking()
            .Where(r => r.CreatedAt >= since
                        && (r.Status == OnboardingStatus.AwaitingConsent || r.Status == OnboardingStatus.Verifying || r.Status == OnboardingStatus.Failed))
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<IReadOnlyList<OnboardingRequest>> GetVerifyingAsync(CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var rows = await db.OnboardingRequests.AsNoTracking()
            .Where(r => r.Status == OnboardingStatus.Verifying)
            .OrderBy(r => r.ConsentReceivedAt)
            .ToListAsync(ct);
        return rows.Select(r => r.ToModel()).ToList();
    }

    public async Task<bool> MarkConsentReceivedAsync(Guid id, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        // Conditional update: two callbacks racing with the same link can't both succeed.
        var updated = await db.OnboardingRequests
            .Where(r => r.Id == id && r.Status == OnboardingStatus.AwaitingConsent && r.ExpiresAt > at)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, OnboardingStatus.Verifying)
                .SetProperty(r => r.ConsentReceivedAt, at)
                .SetProperty(r => r.LastError, (string?)null), ct);
        return updated == 1;
    }

    public async Task SetErrorAsync(Guid id, string error, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var trimmed = Trim(error);
        await db.OnboardingRequests.Where(r => r.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.LastError, trimmed), ct);
    }

    public async Task RecordVerificationFailureAsync(Guid id, string error, bool final, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var trimmed = Trim(error);
        var status = final ? OnboardingStatus.Failed : OnboardingStatus.Verifying;
        await db.OnboardingRequests.Where(r => r.Id == id && r.Status == OnboardingStatus.Verifying)
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.LastError, trimmed)
                .SetProperty(r => r.Status, status)
                .SetProperty(r => r.VerificationAttempts, r => r.VerificationAttempts + 1), ct);
    }

    public async Task<Tenant> CompleteAsync(Guid id, Tenant tenant, IReadOnlyList<string> grantedPermissions, DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var request = await db.OnboardingRequests.FirstOrDefaultAsync(r => r.Id == id, ct)
            ?? throw new InvalidOperationException($"Onboarding request {id} not found.");
        if (request.Status != OnboardingStatus.Verifying)
            throw new InvalidOperationException($"Onboarding request {id} is {request.Status}, not Verifying.");
        if (request.Kind != OnboardingKind.Assessment)
            throw new InvalidOperationException($"Onboarding request {id} is a {request.Kind} request; use CompleteRemediationAsync.");
        if (tenant.EntraTenantId != request.EntraTenantId)
            throw new ArgumentException("Tenant does not match the onboarding request's Entra tenant.", nameof(tenant));

        var stored = await db.Tenants.FirstOrDefaultAsync(t => t.EntraTenantId == tenant.EntraTenantId, ct);
        if (stored is null)
        {
            stored = tenant.ToEntity();
            db.Tenants.Add(stored);
        }
        else
        {
            // Re-consent (e.g. after revocation): keep the tenant's identity, names and history.
            stored.CredentialReference = tenant.CredentialReference;
            if (stored.ConsentState != TenantConsentState.RemediationGranted)
                stored.ConsentState = tenant.ConsentState;
        }

        request.Status = OnboardingStatus.Completed;
        request.CompletedAt = at;
        request.TenantId = stored.Id;
        request.LastError = null;
        request.GrantedPermissions = [.. grantedPermissions];
        request.ProtectedState = null; // the link is spent; no reason to keep it

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return stored.ToModel();
    }

    public async Task<Tenant?> CompleteRemediationAsync(Guid id, string remediationCredentialReference, IReadOnlyList<string> grantedPermissions,
        DateTimeOffset at, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var request = await db.OnboardingRequests.FirstOrDefaultAsync(r => r.Id == id, ct)
            ?? throw new InvalidOperationException($"Onboarding request {id} not found.");
        if (request.Status != OnboardingStatus.Verifying || request.Kind != OnboardingKind.Remediation)
            throw new InvalidOperationException($"Onboarding request {id} isn't a remediation request being verified.");

        var stored = await db.Tenants.FirstOrDefaultAsync(t => t.EntraTenantId == request.EntraTenantId
            && (t.ConsentState == TenantConsentState.ReadOnlyGranted || t.ConsentState == TenantConsentState.RemediationGranted), ct);
        if (stored is null)
        {
            // Remediation is only added to a connected tenant; it never connects one on its own.
            request.Status = OnboardingStatus.Failed;
            request.LastError = "The tenant isn't connected for assessment any more, so remediation access can't be added.";
            request.ProtectedState = null;
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            return null;
        }

        stored.ConsentState = TenantConsentState.RemediationGranted;
        stored.RemediationCredentialReference = remediationCredentialReference;
        request.Status = OnboardingStatus.Completed;
        request.CompletedAt = at;
        request.TenantId = stored.Id;
        request.LastError = null;
        request.GrantedPermissions = [.. grantedPermissions];
        request.ProtectedState = null;

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return stored.ToModel();
    }

    public async Task<bool> SetWazuhAgentGroupAsync(Guid tenantId, string? group, CancellationToken ct = default)
    {
        if (group is not null && WazuhAgentGroups.Problem(group) is { } problem) throw new ArgumentException(problem, nameof(group));
        await using var db = await factory.CreateDbContextAsync(ct);
        try
        {
            var changed = await db.Tenants.Where(t => t.Id == tenantId)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.WazuhAgentGroup, group), ct);
            return changed > 0 ? true : throw new KeyNotFoundException($"Tenant {tenantId} not found.");
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return false; // another tenant already reads this group
        }
    }

    public async Task<bool> DisableRemediationAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.Tenants.Where(t => t.Id == tenantId && t.ConsentState == TenantConsentState.RemediationGranted)
            .ExecuteUpdateAsync(s => s
                .SetProperty(t => t.ConsentState, TenantConsentState.ReadOnlyGranted)
                .SetProperty(t => t.RemediationCredentialReference, (string?)null), ct) > 0;
    }

    public async Task CancelAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await db.OnboardingRequests
            .Where(r => r.Id == id && (r.Status == OnboardingStatus.AwaitingConsent || r.Status == OnboardingStatus.Failed))
            .ExecuteUpdateAsync(s => s
                .SetProperty(r => r.Status, OnboardingStatus.Cancelled)
                .SetProperty(r => r.ProtectedState, (string?)null), ct);
    }

    private static string Trim(string error) => error.Length > MaxErrorLength ? error[..MaxErrorLength] : error;
}

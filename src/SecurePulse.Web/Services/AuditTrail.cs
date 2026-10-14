using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

/// <summary>
/// Records security events from the portal, with the current user as the actor unless one is
/// given (sign-in endpoints and the consent callback run outside a Blazor circuit).
/// </summary>
public sealed class AuditTrail(IAuditLog log, IUserContextAccessor users, TimeProvider time, ILogger<AuditTrail> logger)
{
    /// <summary>Shown as the actor for the consent callback, which comes from a client's admin who isn't a portal user.</summary>
    public static readonly UserContext ConsentingAdmin = new(null, null, null, "Client admin (not signed in to SecurePulse)");

    /// <summary>
    /// Fail-closed variant for authorising a write: the entry is written first, and if it can't
    /// be, this throws <see cref="AuditUnavailableException"/> so the caller doesn't go ahead.
    /// </summary>
    public async Task RecordOrThrowAsync(string action, AuditOutcome outcome, string summary, Guid? tenantId, string? targetType, string? targetId,
        IReadOnlyDictionary<string, string>? details, UserContext actor)
    {
        try
        {
            await log.RecordAsync(Build(action, outcome, summary, tenantId, targetType, targetId, details, actor, null));
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex, "Audit write failed for {Action} by {Actor}; the action was not taken: {Summary}", action, actor.Name, summary);
            throw new AuditUnavailableException(ex);
        }
    }

    private AuditEvent Build(string action, AuditOutcome outcome, string summary, Guid? tenantId, string? targetType, string? targetId,
        IReadOnlyDictionary<string, string>? details, UserContext actor, string? ipAddress) => new()
    {
        Id = Guid.NewGuid(),
        OccurredAt = time.GetUtcNow(),
        Action = action,
        Outcome = outcome,
        ActorUserId = actor.UserId,
        ActorName = actor.Name,
        TenantId = tenantId,
        TargetType = targetType,
        TargetId = targetId,
        Summary = summary,
        Details = details ?? new Dictionary<string, string>(),
        IpAddress = ipAddress
    };

    public async Task RecordAsync(
        string action,
        AuditOutcome outcome,
        string summary,
        Guid? tenantId = null,
        string? targetType = null,
        string? targetId = null,
        IReadOnlyDictionary<string, string>? details = null,
        UserContext? actor = null,
        string? ipAddress = null)
    {
        actor ??= await users.GetAsync();
        var auditEvent = Build(action, outcome, summary, tenantId, targetType, targetId, details, actor, ipAddress);

        try
        {
            await log.RecordAsync(auditEvent);
        }
        catch (Exception ex)
        {
            // These events record something that already happened, so the action stands; make
            // sure the gap is loud in the application log. Remote actions must instead write
            // their audit entry first and abort if it fails.
            logger.LogCritical(ex, "Audit write failed for {Action} ({Outcome}) by {Actor}: {Summary}", action, outcome, actor.Name, summary);
        }
    }
}

public sealed class AuditUnavailableException(Exception inner)
    : Exception("The audit log couldn't be written, so the action wasn't taken. Try again in a moment.", inner);

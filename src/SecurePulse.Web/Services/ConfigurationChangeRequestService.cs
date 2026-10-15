using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

public sealed record ConfigurationChangeOutcome(bool Ok, string Message, ConfigurationChangeRequest? Request = null);

public sealed record ConfigurationChangeView(ConfigurationChangeRequest Request, ConfigurationFix? Fix, string TenantName, string? WhyCannotApprove,
    bool CanCancel);

/// <summary>A catalog fix and its finding playbook (if any).</summary>
public sealed record FindingPlaybookView(ConfigurationFix Fix, FindingPlaybook? Playbook, string Scope, int ProposedLastMonth, int Waiting);

/// <summary>
/// Portal side of configuration fixes: requests (from a failed finding), approvals by another Owner, rejections,
/// cancellations, and the finding playbooks that propose them. Nothing here calls Graph; the Worker applies approved fixes.
/// </summary>
public sealed class ConfigurationChangeRequestService(
    IConfigurationChangeRepository changes,
    IFindingPlaybookRepository playbooks,
    ITenantRepository tenants,
    IFindingRepository findings,
    IUserContextAccessor users,
    AuditTrail audit,
    TimeProvider time)
{
    public async Task<IReadOnlyList<ConfigurationChangeView>> GetQueueAsync(Guid? tenantId = null, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator) return [];
        var names = (await tenants.GetAllAsync(ct)).ToDictionary(t => t.Id, t => t.DisplayName);
        var list = await changes.QueryAsync(new ConfigurationChangeQuery { TenantId = tenantId, Limit = 200 }, ct);
        return list.Where(c => user.CanSee(c.TenantId)).Select(c => View(c, names.GetValueOrDefault(c.TenantId, "Removed tenant"), user)).ToList();
    }

    public async Task<int> CountAwaitingMyApprovalAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner) return 0;
        var open = await changes.QueryAsync(new ConfigurationChangeQuery { OpenOnly = true }, ct);
        return open.Count(c => c.Status == DeviceActionStatus.PendingApproval && ConfigurationChangePolicy.WhyCannotApprove(c, user.UserId, user.Role) is null);
    }

    /// <summary>The catalog fix an operator could request for this finding right now, or null.</summary>
    public async Task<ConfigurationFix?> FixForAsync(Finding finding, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!ConfigurationChangePolicy.CanRequest(user.Role) || finding.Status != FindingStatus.Failed) return null;
        if (ConfigurationFixes.ForCheck(finding.SourceCheckId) is not { } fix) return null;
        return await tenants.GetAsync(finding.TenantId, ct) is { CanConfigure: true } ? fix : null;
    }

    /// <summary>Requests the catalog fix for a failed check. Only for a check that is failing in this tenant right now.</summary>
    public async Task<ConfigurationChangeOutcome> RequestAsync(Guid tenantId, string checkId, string? reason, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!ConfigurationChangePolicy.CanRequest(user.Role) || user.UserId is not { } userId)
            return new(false, "Only Owners and MSP admins can request configuration changes.");
        if (!user.CanSee(tenantId) || await tenants.GetAsync(tenantId, ct) is not { } tenant) return new(false, "Tenant not found.");
        if (!tenant.CanConfigure)
            return new(false, $"{tenant.DisplayName} hasn't granted configuration access, so configuration fixes can't be requested.");
        if (ConfigurationFixes.ForCheck(checkId) is not { } fix) return new(false, "SecurePulse has no reviewed fix for this check.");
        var failing = (await findings.GetForTenantAsync(tenantId, ct))
            .FirstOrDefault(f => f.Status == FindingStatus.Failed && string.Equals(f.SourceCheckId, checkId, StringComparison.OrdinalIgnoreCase));
        if (failing is null) return new(false, $"{checkId} isn't failing for {tenant.DisplayName} at the moment.");
        var why = reason?.Trim();
        if (string.IsNullOrEmpty(why)) return new(false, "Give a reason: the approving Owner sees it and it's kept in the audit log.");
        if (why.Length > DeviceActionPolicy.MaxReasonLength) return new(false, $"Keep the reason under {DeviceActionPolicy.MaxReasonLength} characters.");

        var now = time.GetUtcNow();
        var (request, created) = await changes.AddAsync(new ConfigurationChangeRequest
        {
            Id = Guid.NewGuid(), TenantId = tenantId, FixId = fix.Id, CheckId = failing.SourceCheckId, Reason = why,
            Status = DeviceActionStatus.PendingApproval, RequestedAt = now, RequestedByUserId = userId, RequestedByName = user.Name,
            ExpiresAt = now + ConfigurationChangePolicy.ApprovalWindow
        }, ct);
        if (!created)
            return new(false, $"\"{fix.Title}\" is already {DeviceActionRequestService.Label(request.Status).ToLowerInvariant()} for {tenant.DisplayName}.", request);

        await audit.RecordAsync(AuditActions.ConfigChangeRequested, AuditOutcome.Success,
            $"Requested \"{fix.PolicyDisplayName}\" for {tenant.DisplayName}: {why}", tenantId, "ConfigurationChange", request.Id.ToString(), Details(request), user);
        return new(true, $"\"{fix.Title}\" requested for {tenant.DisplayName}. An Owner other than you has to approve it.", request);
    }

    /// <summary>Approval authorises a change to the tenant's sign-in policy, so it's fail-closed: audit first.</summary>
    public async Task<ConfigurationChangeOutcome> ApproveAsync(Guid id, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } c) return new(false, "Request not found.");
        if (c.Status != DeviceActionStatus.PendingApproval) return new(false, "This request isn't waiting for approval.");
        if (ConfigurationChangePolicy.WhyCannotApprove(c, user.UserId, user.Role) is { } refusal) return new(false, refusal);
        if (await tenants.GetAsync(c.TenantId, ct) is not { CanConfigure: true }) return new(false, "Configuration access for this tenant was turned off.");
        if (Note(note) is { Error: { } bad }) return new(false, bad);

        try
        {
            await audit.RecordOrThrowAsync(AuditActions.ConfigChangeApproved, AuditOutcome.Success,
                $"Approved \"{Policy(c)}\" requested by {c.RequestedByName}", c.TenantId, "ConfigurationChange", c.Id.ToString(),
                WithNote(Details(c), Note(note).Text), user);
        }
        catch (AuditUnavailableException ex)
        {
            return new(false, ex.Message);
        }

        var decided = await changes.DecideAsync(c.Id, approve: true, user.UserId!.Value, user.Name, user.Role!.Value, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null)
        {
            await audit.RecordAsync(AuditActions.ConfigChangeApproved, AuditOutcome.Failure,
                $"Approval of \"{Policy(c)}\" wasn't applied: the request was no longer pending", c.TenantId, "ConfigurationChange", c.Id.ToString(),
                Details(c), user);
            return new(false, "The request changed before your approval applied (someone else decided, it was cancelled, or it expired).");
        }
        return new(true, "Approved. SecurePulse creates the policy in report-only mode within a minute.", decided);
    }

    public async Task<ConfigurationChangeOutcome> RejectAsync(Guid id, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } c) return new(false, "Request not found.");
        if (!user.IsOperator) return new(false, "Only Owners and MSP admins can reject configuration changes.");
        if (user.UserId == c.RequestedByUserId) return new(false, "Cancel your own request instead of rejecting it.");
        if (Note(note) is { Error: { } bad }) return new(false, bad);
        if (string.IsNullOrWhiteSpace(note)) return new(false, "Say why you're rejecting it; the requester sees this.");

        var decided = await changes.DecideAsync(c.Id, approve: false, user.UserId!.Value, user.Name, user.Role!.Value, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null) return new(false, "This request is no longer waiting for approval.");
        await audit.RecordAsync(AuditActions.ConfigChangeRejected, AuditOutcome.Success, $"Rejected \"{Policy(c)}\" requested by {c.RequestedByName}",
            c.TenantId, "ConfigurationChange", c.Id.ToString(), WithNote(Details(c), Note(note).Text), user);
        return new(true, "Rejected.", decided);
    }

    public async Task<ConfigurationChangeOutcome> CancelAsync(Guid id, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(id, user, ct) is not { } c) return new(false, "Request not found.");
        if (!user.IsOperator) return new(false, "Only Owners and MSP admins can cancel configuration changes.");
        var cancelled = await changes.CancelAsync(c.Id, user.Name, $"Cancelled by {user.Name}.", time.GetUtcNow(), ct);
        if (cancelled is null) return new(false, "Too late to cancel: it's already being applied, or it's finished.");
        await audit.RecordAsync(AuditActions.ConfigChangeCancelled, AuditOutcome.Success, $"Cancelled \"{Policy(c)}\"", c.TenantId, "ConfigurationChange",
            c.Id.ToString(), Details(c), user);
        return new(true, "Cancelled.", cancelled);
    }

    // --- Finding playbooks ------------------------------------------------------------------------

    public async Task<IReadOnlyList<FindingPlaybookView>> GetPlaybooksAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator) return [];
        var names = (await tenants.GetAllAsync(ct)).ToDictionary(t => t.Id, t => t.DisplayName);
        var all = await playbooks.GetAllAsync(ct);
        var recent = (await changes.QueryAsync(new ConfigurationChangeQuery { Limit = 1000 }, ct)).Where(c => c.PlaybookId is not null).ToList();
        var monthAgo = time.GetUtcNow().AddDays(-30);
        var views = new List<FindingPlaybookView>();
        foreach (var fix in ConfigurationFixes.All)
        {
            var mine = all.Where(p => p.FixId == fix.Id).ToList();
            if (mine.Count == 0) views.Add(new(fix, null, "", 0, 0));
            foreach (var p in mine)
                views.Add(new(fix, p, p.TenantId is { } id ? names.GetValueOrDefault(id, "Removed tenant") : "Every tenant with configuration access",
                    recent.Count(c => c.PlaybookId == p.Id && c.RequestedAt >= monthAgo),
                    recent.Count(c => c.PlaybookId == p.Id && c.Status == DeviceActionStatus.PendingApproval)));
        }
        return views;
    }

    public async Task<ConfigurationChangeOutcome> CreatePlaybookAsync(string fixId, Guid? tenantId, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner || user.UserId is not { } userId) return new(false, "Only Owners can create finding playbooks.");
        if (ConfigurationFixes.Find(fixId) is not { } fix) return new(false, "Unknown fix.");
        if (tenantId is { } id && await tenants.GetAsync(id, ct) is null) return new(false, "Tenant not found.");
        if ((await playbooks.GetAllAsync(ct)).Any(p => p.FixId == fixId && p.TenantId == tenantId))
            return new(false, "There's already a playbook for this fix and scope.");
        var now = time.GetUtcNow();
        var p = new FindingPlaybook
        {
            Id = Guid.NewGuid(), FixId = fix.Id, Enabled = true, TenantId = tenantId, CreatedAt = now, UpdatedAt = now,
            UpdatedByUserId = userId, UpdatedByName = user.Name
        };
        await playbooks.AddAsync(p, ct);
        await audit.RecordAsync(AuditActions.FindingPlaybookCreated, AuditOutcome.Success,
            $"Created finding playbook \"{fix.Title}\" for {(tenantId is null ? "every tenant with configuration access" : "one tenant")}", tenantId,
            "FindingPlaybook", p.Id.ToString(), PlaybookDetails(p), user);
        return new(true, $"\"{fix.Title}\" will be proposed after scans that find {string.Join(" or ", fix.CheckIds)} failing.");
    }

    public async Task<ConfigurationChangeOutcome> SetPlaybookEnabledAsync(Guid id, bool enabled, DateTimeOffset expectedUpdatedAt, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner || user.UserId is not { } userId) return new(false, "Only Owners can change finding playbooks.");
        if (await playbooks.GetAsync(id, ct) is not { } p) return new(false, "Playbook not found.");
        if (p.Enabled == enabled) return new(true, "No change.");
        var updated = p with { Enabled = enabled, UpdatedAt = time.GetUtcNow(), UpdatedByUserId = userId, UpdatedByName = user.Name };
        if (!await playbooks.UpdateAsync(updated, expectedUpdatedAt, ct))
            return new(false, "Someone else changed or deleted this playbook since you opened it. Reload and try again.");
        await audit.RecordAsync(AuditActions.FindingPlaybookChanged, AuditOutcome.Success,
            $"{(enabled ? "Switched on" : "Switched off")} finding playbook \"{ConfigurationFixes.Find(p.FixId)?.Title ?? p.FixId}\"", p.TenantId,
            "FindingPlaybook", id.ToString(), PlaybookDetails(updated), user);
        return new(true, enabled ? "Switched on." : "Switched off.");
    }

    public async Task<ConfigurationChangeOutcome> DeletePlaybookAsync(Guid id, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner) return new(false, "Only Owners can delete finding playbooks.");
        if (await playbooks.GetAsync(id, ct) is not { } p || !await playbooks.DeleteAsync(id, ct)) return new(false, "Playbook not found.");
        await audit.RecordAsync(AuditActions.FindingPlaybookDeleted, AuditOutcome.Success,
            $"Deleted finding playbook \"{ConfigurationFixes.Find(p.FixId)?.Title ?? p.FixId}\"", p.TenantId, "FindingPlaybook", id.ToString(),
            PlaybookDetails(p), user);
        return new(true, "Deleted. Changes it already proposed stay in the queue.");
    }

    private async Task<ConfigurationChangeRequest?> LoadAsync(Guid id, UserContext user, CancellationToken ct) =>
        await changes.GetAsync(id, ct) is { } c && user.CanSee(c.TenantId) ? c : null;

    private static ConfigurationChangeView View(ConfigurationChangeRequest c, string tenantName, UserContext user) => new(c,
        ConfigurationFixes.Find(c.FixId), tenantName,
        c.Status == DeviceActionStatus.PendingApproval ? ConfigurationChangePolicy.WhyCannotApprove(c, user.UserId, user.Role) : "It isn't waiting for approval.",
        user.IsOperator && c.Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved);

    private static string Policy(ConfigurationChangeRequest c) => ConfigurationFixes.Find(c.FixId)?.PolicyDisplayName ?? c.FixId;

    private static (string? Text, string? Error) Note(string? note)
    {
        var text = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        return text is { Length: > DeviceActionPolicy.MaxNoteLength } ? (null, $"Keep the note under {DeviceActionPolicy.MaxNoteLength} characters.") : (text, null);
    }

    private static Dictionary<string, string> Details(ConfigurationChangeRequest c) => new()
    {
        ["fix"] = c.FixId,
        ["checkId"] = c.CheckId ?? "",
        ["reason"] = c.Reason,
        ["requestedBy"] = c.RequestedByName
    };

    private static Dictionary<string, string> WithNote(Dictionary<string, string> details, string? note)
    {
        if (note is not null) details["note"] = note;
        return details;
    }

    private static Dictionary<string, string> PlaybookDetails(FindingPlaybook p) => new()
    {
        ["fix"] = p.FixId,
        ["enabled"] = p.Enabled ? "true" : "false",
        ["tenantId"] = p.TenantId?.ToString() ?? "all"
    };
}

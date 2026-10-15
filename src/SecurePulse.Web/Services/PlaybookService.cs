using SecurePulse.Core.Abstractions;
using SecurePulse.Core.Models;
using SecurePulse.Web.Security;

namespace SecurePulse.Web.Services;

/// <summary>What the playbook editor submits.</summary>
public sealed record PlaybookDraft(string Name, bool Enabled, PlaybookTrigger Trigger, int? Days, DeviceAction Action, Guid? TenantId,
    int MaxPerRun, TimeSpan Cooldown);

/// <summary>A playbook with what the page shows next to it.</summary>
public sealed record PlaybookView(RemediationPlaybook Playbook, string Scope, int ProposedLastWeek, int WaitingForApproval);

public sealed record PlaybookOutcome(bool Ok, string Message, RemediationPlaybook? Playbook = null);

/// <summary>
/// Remediation playbooks in the portal. Owners create, change and delete them (audited); MSP admins can see them.
/// Playbooks only ever propose device actions: the Worker adds them to the approval queue after each device sync.
/// </summary>
public sealed class PlaybookService(
    IPlaybookRepository playbooks,
    IDeviceActionRepository actions,
    ITenantRepository tenants,
    IUserContextAccessor users,
    AuditTrail audit,
    TimeProvider time)
{
    public async Task<IReadOnlyList<PlaybookView>> GetAllAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator) return [];
        var names = (await tenants.GetAllAsync(ct)).ToDictionary(t => t.Id, t => t.DisplayName);
        var weekAgo = time.GetUtcNow().AddDays(-7);
        var fromPlaybooks = (await actions.QueryAsync(new DeviceActionQuery { Limit = 1000 }, ct)).Where(a => a.PlaybookId is not null).ToList();
        return (await playbooks.GetAllAsync(ct)).Select(p => new PlaybookView(p,
                p.TenantId is { } id ? names.GetValueOrDefault(id, "Removed tenant") : "Every tenant with remediation access",
                fromPlaybooks.Count(a => a.PlaybookId == p.Id && a.RequestedAt >= weekAgo),
                fromPlaybooks.Count(a => a.PlaybookId == p.Id && a.Status == DeviceActionStatus.PendingApproval)))
            .ToList();
    }

    public async Task<PlaybookOutcome> CreateAsync(PlaybookDraft draft, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner || user.UserId is not { } userId) return new(false, "Only Owners can create playbooks.");
        var now = time.GetUtcNow();
        var playbook = Apply(draft, new RemediationPlaybook
        {
            Id = Guid.NewGuid(), Name = "", Trigger = draft.Trigger, Action = draft.Action,
            CreatedAt = now, UpdatedAt = now, UpdatedByUserId = userId, UpdatedByName = user.Name
        });
        if (await ProblemAsync(playbook, ct) is { } problem) return new(false, problem);

        await playbooks.AddAsync(playbook, ct);
        await audit.RecordAsync(AuditActions.PlaybookCreated, AuditOutcome.Success, $"Created playbook \"{playbook.Name}\": {Describe(playbook)}",
            playbook.TenantId, "Playbook", playbook.Id.ToString(), Details(playbook), user);
        return new(true, $"Playbook \"{playbook.Name}\" saved{(playbook.Enabled ? "; it runs after the next device sync" : " (off)")}.", playbook);
    }

    /// <param name="expectedUpdatedAt">The version the editor started from; someone else's newer save wins.</param>
    public async Task<PlaybookOutcome> UpdateAsync(Guid id, PlaybookDraft draft, DateTimeOffset expectedUpdatedAt, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner || user.UserId is not { } userId) return new(false, "Only Owners can change playbooks.");
        if (await playbooks.GetAsync(id, ct) is not { } current) return new(false, "Playbook not found.");
        var updated = Apply(draft, current with { UpdatedAt = time.GetUtcNow(), UpdatedByUserId = userId, UpdatedByName = user.Name });
        if (await ProblemAsync(updated, ct) is { } problem) return new(false, problem);

        if (!await playbooks.UpdateAsync(updated, expectedUpdatedAt, ct))
            return new(false, "Someone else changed or deleted this playbook since you opened it. Reload and try again.");
        var details = Details(updated);
        details["previous"] = Describe(current);
        await audit.RecordAsync(AuditActions.PlaybookChanged, AuditOutcome.Success,
            $"Changed playbook \"{updated.Name}\": {Describe(updated)}", updated.TenantId ?? current.TenantId, "Playbook", id.ToString(), details, user);
        return new(true, $"Playbook \"{updated.Name}\" saved.", updated);
    }

    public async Task<PlaybookOutcome> SetEnabledAsync(Guid id, bool enabled, DateTimeOffset expectedUpdatedAt, CancellationToken ct = default)
    {
        if (await playbooks.GetAsync(id, ct) is not { } p) return new(false, "Playbook not found.");
        if (p.Enabled == enabled) return new(true, "No change.", p);
        return await UpdateAsync(id, new PlaybookDraft(p.Name, enabled, p.Trigger, p.Days, p.Action, p.TenantId, p.MaxPerRun, p.Cooldown),
            expectedUpdatedAt, ct);
    }

    /// <summary>Deleting stops new proposals; pending ones stay in the queue for a person to decide.</summary>
    public async Task<PlaybookOutcome> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner) return new(false, "Only Owners can delete playbooks.");
        if (await playbooks.GetAsync(id, ct) is not { } p || !await playbooks.DeleteAsync(id, ct)) return new(false, "Playbook not found.");
        await audit.RecordAsync(AuditActions.PlaybookDeleted, AuditOutcome.Success, $"Deleted playbook \"{p.Name}\" ({Describe(p)})",
            p.TenantId, "Playbook", id.ToString(), Details(p), user);
        return new(true, $"Playbook \"{p.Name}\" deleted. Actions it already proposed stay in the queue.");
    }

    private static RemediationPlaybook Apply(PlaybookDraft d, RemediationPlaybook p) => p with
    {
        Name = d.Name?.Trim() ?? "",
        Enabled = d.Enabled,
        Trigger = d.Trigger,
        Days = d.Trigger == PlaybookTrigger.NotCheckedIn ? d.Days : null,
        Action = d.Action,
        TenantId = d.TenantId,
        MaxPerRun = d.MaxPerRun,
        Cooldown = d.Cooldown
    };

    private async Task<string?> ProblemAsync(RemediationPlaybook p, CancellationToken ct)
    {
        if (PlaybookRules.Problem(p) is { } problem) return problem;
        if (p.TenantId is { } id && await tenants.GetAsync(id, ct) is null) return "Tenant not found.";
        return null;
    }

    public static string TriggerLabel(PlaybookTrigger trigger, int? days = null) => trigger switch
    {
        PlaybookTrigger.NotCheckedIn => days is { } d ? $"Not checked in for {d} day{(d == 1 ? "" : "s")}" : "Not checked in for a number of days",
        PlaybookTrigger.Noncompliant => "Noncompliant in Intune",
        PlaybookTrigger.DefenderSignaturesOutOfDate => "Defender signatures out of date",
        PlaybookTrigger.DefenderQuickScanOverdue => "Defender quick scan overdue",
        _ => "Defender needs a restart"
    };

    public static string Describe(RemediationPlaybook p) =>
        $"when \"{TriggerLabel(p.Trigger, p.Days)}\", propose {DeviceActions.Label(p.Action)}; up to {p.MaxPerRun} per sync, " +
        $"once per device every {Cooldown(p.Cooldown)}; {(p.Enabled ? "on" : "off")}";

    public static string Cooldown(TimeSpan t) => t.TotalHours % 24 == 0 ? $"{t.TotalDays:0} day{(t.TotalDays == 1 ? "" : "s")}" : $"{t.TotalHours:0} hours";

    private static Dictionary<string, string> Details(RemediationPlaybook p) => new()
    {
        ["name"] = p.Name,
        ["enabled"] = p.Enabled ? "true" : "false",
        ["trigger"] = p.Trigger.ToString(),
        ["days"] = p.Days?.ToString() ?? "",
        ["action"] = p.Action.ToString(),
        ["tenantId"] = p.TenantId?.ToString() ?? "all",
        ["maxPerRun"] = p.MaxPerRun.ToString(),
        ["cooldownHours"] = ((int)p.Cooldown.TotalHours).ToString()
    };
}

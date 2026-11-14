using System.Globalization;
using Hasinix.Core.Abstractions;
using Hasinix.Core.Models;
using Hasinix.Web.Security;

namespace Hasinix.Web.Services;

public sealed record TrackingOutcome(bool Ok, string Message, FindingTracking? Tracking = null);

/// <summary>
/// Portal side of finding tracking: owners, due dates and risk acceptances. Every rule is enforced here, not
/// just in the UI, and every change is audited. Accepting a risk never changes the score or the finding;
/// it records who decided to leave it open, why and until when.
/// </summary>
public sealed class FindingTrackingService(
    IFindingTrackingRepository tracking,
    IFindingRepository findings,
    ITenantRepository tenants,
    IUserContextAccessor users,
    AuditTrail audit,
    ReportSettings reports,
    TimeProvider time)
{
    /// <summary>Today in the report time zone (Reports:TimeZone): due dates and end dates are whole days there.</summary>
    public DateOnly Today => DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(time.GetUtcNow(), reports.TimeZone).DateTime);

    /// <summary>Tracking for every finding the user may see, by tenant and finding ID.</summary>
    public async Task<IReadOnlyDictionary<(Guid TenantId, string FindingId), FindingTracking>> GetAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOperator && user.ClientTenantId is null) return new Dictionary<(Guid, string), FindingTracking>();
        return (await tracking.GetAllAsync(user.IsOperator ? null : user.ClientTenantId, ct))
            .Where(t => user.CanSee(t.TenantId))
            .ToDictionary(t => (t.TenantId, t.FindingId));
    }

    /// <summary>Requests the current user could approve right now (for the "waiting for you" note).</summary>
    public async Task<int> CountAwaitingMyDecisionAsync(CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!user.IsOwner) return 0;
        return (await tracking.GetAllAsync(null, ct)).Count(t => FindingTrackingPolicy.WhyCannotDecide(t, user.UserId, user.Role) is null);
    }

    public async Task<TrackingOutcome> SetOwnerAsync(Guid tenantId, string findingId, string? owner, DateOnly? dueDate, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!FindingTrackingPolicy.CanEdit(user.Role)) return new(false, "Only Owners and MSP admins can assign findings.");
        if (await LoadFindingAsync(tenantId, findingId, user, ct) is not { } finding) return new(false, "Finding not found.");
        var name = string.IsNullOrWhiteSpace(owner) ? null : owner.Trim();
        if (name is { Length: > FindingTrackingPolicy.MaxOwnerLength })
            return new(false, $"Keep the owner under {FindingTrackingPolicy.MaxOwnerLength} characters.");

        var saved = await tracking.SetOwnerAsync(tenantId, findingId, finding.Title, name, dueDate, time.GetUtcNow(), ct);
        var summary = (name, dueDate) switch
        {
            (null, null) => $"Cleared the owner and due date of \"{finding.Title}\"",
            (null, { } due) => $"Set \"{finding.Title}\" due {Day(due)} with no owner",
            ({ } who, null) => $"Assigned \"{finding.Title}\" to {who} with no due date",
            ({ } who, { } due) => $"Assigned \"{finding.Title}\" to {who}, due {Day(due)}"
        };
        await audit.RecordAsync(AuditActions.FindingOwnerChanged, AuditOutcome.Success, summary, tenantId, "Finding", findingId,
            new Dictionary<string, string> { ["finding"] = finding.Title, ["owner"] = name ?? "", ["dueDate"] = dueDate?.ToString("O") ?? "" }, user);
        return new(true, name is null && dueDate is null ? "Owner and due date cleared." : "Saved.", saved);
    }

    public async Task<TrackingOutcome> RequestAcceptanceAsync(Guid tenantId, string findingId, string? reason, DateOnly? until, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!FindingTrackingPolicy.CanEdit(user.Role) || user.UserId is not { } userId)
            return new(false, "Only Owners and MSP admins can ask for a risk to be accepted.");
        if (await LoadFindingAsync(tenantId, findingId, user, ct) is not { } finding) return new(false, "Finding not found.");
        if (!FindingTrackingPolicy.CanBeAccepted(finding.Status))
            return new(false, "Only checks that failed or need review have a risk to accept.");
        var why = reason?.Trim();
        if (string.IsNullOrEmpty(why)) return new(false, "Give a reason: the approving Owner sees it and it's kept in the audit log.");
        if (why.Length > FindingTrackingPolicy.MaxReasonLength)
            return new(false, $"Keep the reason under {FindingTrackingPolicy.MaxReasonLength} characters.");
        if (until is not { } end) return new(false, "Choose an end date: a risk is never accepted for good.");
        var today = Today;
        if (end <= today) return new(false, "The end date has to be after today.");
        if (end > today.AddDays(FindingTrackingPolicy.MaxAcceptanceDays))
            return new(false, $"A risk can be accepted for at most {FindingTrackingPolicy.MaxAcceptanceDays} days. Choose an earlier end date.");

        var saved = await tracking.RequestAcceptanceAsync(tenantId, findingId, finding.Title, why, EndOf(end), userId, user.Name, time.GetUtcNow(), ct);
        if (saved is null) return new(false, "This finding already has a risk acceptance waiting or running. End that one first.");

        await audit.RecordAsync(AuditActions.RiskAcceptanceRequested, AuditOutcome.Success,
            $"Asked to accept the risk of \"{finding.Title}\" until {Day(end)}: {why}", tenantId, "Finding", findingId, Details(saved), user);
        return new(true, "Requested. An Owner other than you has to approve it.", saved);
    }

    /// <summary>
    /// Approval leaves a risk open on someone's authority, and the audit log is the only history of it,
    /// so it is fail-closed: the audit entry is written first and the approval only applies if that succeeded.
    /// </summary>
    public async Task<TrackingOutcome> ApproveAsync(Guid tenantId, string findingId, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(tenantId, findingId, user, ct) is not { } t) return new(false, "Request not found.");
        if (FindingTrackingPolicy.WhyCannotDecide(t, user.UserId, user.Role) is { } refusal) return new(false, refusal);
        if (await LoadFindingAsync(tenantId, findingId, user, ct) is not { } finding || !FindingTrackingPolicy.CanBeAccepted(finding.Status))
            return new(false, "This check no longer fails, so there's no risk to accept. Reject or withdraw the request.");
        if (!(t.AcceptanceExpiresAt > time.GetUtcNow()))
            return new(false, "The requested end date has passed. Reject it; a new request can set a later date.");
        if (Note(note) is { Error: { } bad }) return new(false, bad);

        try
        {
            await audit.RecordOrThrowAsync(AuditActions.RiskAcceptanceApproved, AuditOutcome.Success,
                $"Accepted the risk of \"{t.FindingTitle}\" until {Day(t.AcceptanceExpiresAt)}, requested by {t.RequestedByName}",
                tenantId, "Finding", findingId, WithNote(Details(t), Note(note).Text), user);
        }
        catch (AuditUnavailableException ex)
        {
            return new(false, ex.Message);
        }

        var decided = await tracking.DecideAcceptanceAsync(tenantId, findingId, approve: true, user.UserId!.Value, user.Name, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null)
        {
            await audit.RecordAsync(AuditActions.RiskAcceptanceApproved, AuditOutcome.Failure,
                $"Accepting the risk of \"{t.FindingTitle}\" wasn't applied: the request was no longer waiting", tenantId, "Finding", findingId, Details(t), user);
            return new(false, "The request changed before your approval applied (someone else decided, or it was withdrawn).");
        }
        return new(true, $"Risk accepted until {Day(decided.AcceptanceExpiresAt)}. It still counts against the score.", decided);
    }

    public async Task<TrackingOutcome> RejectAsync(Guid tenantId, string findingId, string? note, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (await LoadAsync(tenantId, findingId, user, ct) is not { } t) return new(false, "Request not found.");
        if (FindingTrackingPolicy.WhyCannotDecide(t, user.UserId, user.Role) is { } refusal) return new(false, refusal);
        if (Note(note) is { Error: { } bad }) return new(false, bad);
        if (string.IsNullOrWhiteSpace(note)) return new(false, "Say why you're rejecting it; the requester sees this.");

        var decided = await tracking.DecideAcceptanceAsync(tenantId, findingId, approve: false, user.UserId!.Value, user.Name, Note(note).Text, time.GetUtcNow(), ct);
        if (decided is null) return new(false, "This request is no longer waiting for a decision.");
        await audit.RecordAsync(AuditActions.RiskAcceptanceRejected, AuditOutcome.Success,
            $"Rejected accepting the risk of \"{t.FindingTitle}\", requested by {t.RequestedByName}", tenantId, "Finding", findingId,
            WithNote(Details(t), Note(note).Text), user);
        return new(true, "Rejected.", decided);
    }

    /// <summary>Any operator can withdraw a waiting request or end an acceptance early: ending one only ever removes an exception.</summary>
    public async Task<TrackingOutcome> EndAsync(Guid tenantId, string findingId, CancellationToken ct = default)
    {
        var user = await users.GetAsync();
        if (!FindingTrackingPolicy.CanEdit(user.Role)) return new(false, "Only Owners and MSP admins can end a risk acceptance.");
        if (await LoadAsync(tenantId, findingId, user, ct) is not { } t) return new(false, "There's no risk acceptance to end.");
        var ended = await tracking.EndAcceptanceAsync(tenantId, findingId, time.GetUtcNow(), ct);
        if (ended is null) return new(false, "There's no risk acceptance to end.");

        var wasWaiting = t.Acceptance == RiskAcceptanceStatus.Requested;
        await audit.RecordAsync(AuditActions.RiskAcceptanceEnded, AuditOutcome.Success,
            wasWaiting
                ? $"Withdrew the request to accept the risk of \"{t.FindingTitle}\""
                : $"Ended the risk acceptance of \"{t.FindingTitle}\" (approved by {t.DecidedByName} until {Day(t.AcceptanceExpiresAt)})",
            tenantId, "Finding", findingId, Details(t), user);
        return new(true, wasWaiting ? "Request withdrawn." : "Risk acceptance ended.", ended);
    }

    /// <summary>"14 Nov 2026" in the report time zone.</summary>
    public string Day(DateTimeOffset? at) => at is { } value
        ? Day(DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(value, reports.TimeZone).AddTicks(-1).DateTime))
        : "";

    public static string Day(DateOnly day) => day.ToString("d MMM yyyy", CultureInfo.InvariantCulture);

    /// <summary>Names are stored as "Name &lt;sign-in name&gt;" for the audit log; on screen (clients read this) only the name is shown.</summary>
    public static string Person(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "someone";
        var bracket = name.IndexOf(" <", StringComparison.Ordinal);
        return bracket > 0 ? name[..bracket] : name;
    }

    /// <summary>The acceptance runs to the end of <paramref name="day"/> in the report time zone.</summary>
    private DateTimeOffset EndOf(DateOnly day) =>
        new(TimeZoneInfo.ConvertTimeToUtc(day.AddDays(1).ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified), reports.TimeZone), TimeSpan.Zero);

    private async Task<FindingTracking?> LoadAsync(Guid tenantId, string findingId, UserContext user, CancellationToken ct) =>
        user.CanSee(tenantId) ? await tracking.GetAsync(tenantId, findingId, ct) : null;

    private async Task<Finding?> LoadFindingAsync(Guid tenantId, string findingId, UserContext user, CancellationToken ct) =>
        user.CanSee(tenantId) && await tenants.GetAsync(tenantId, ct) is not null
            ? (await findings.GetForTenantAsync(tenantId, ct)).FirstOrDefault(f => f.Id == findingId)
            : null;

    private static (string? Text, string? Error) Note(string? note)
    {
        var text = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        return text is { Length: > FindingTrackingPolicy.MaxNoteLength }
            ? (null, $"Keep the note under {FindingTrackingPolicy.MaxNoteLength} characters.")
            : (text, null);
    }

    private static Dictionary<string, string> Details(FindingTracking t) => new()
    {
        ["finding"] = t.FindingTitle,
        ["reason"] = t.AcceptanceReason ?? "",
        ["until"] = t.AcceptanceExpiresAt?.ToString("O") ?? "",
        ["requestedBy"] = t.RequestedByName ?? ""
    };

    private static Dictionary<string, string> WithNote(Dictionary<string, string> details, string? note)
    {
        if (note is not null) details["note"] = note;
        return details;
    }
}

namespace Hasinix.Core.Models;

public enum RiskAcceptanceStatus
{
    None,

    /// <summary>Asked for, waiting for an Owner's decision.</summary>
    Requested,

    /// <summary>Approved until <see cref="FindingTracking.AcceptanceExpiresAt"/>; after that it counts as expired.</summary>
    Accepted,

    Rejected
}

/// <summary>
/// What people decided about one finding: who owns fixing it, by when, and whether the risk is accepted for now.
/// Kept apart from the finding (keyed by tenant and finding ID) because every scan replaces the findings.
/// An accepted risk still counts against the score; it is only labelled.
/// </summary>
public sealed record FindingTracking
{
    public required Guid TenantId { get; init; }
    public required string FindingId { get; init; }

    /// <summary>The finding's title when it was last tracked, so lists and reports read well if the check later disappears.</summary>
    public required string FindingTitle { get; init; }

    /// <summary>Who is fixing it: a name or email, typed by an admin (client staff usually aren't portal users).</summary>
    public string? Owner { get; init; }

    public DateOnly? DueDate { get; init; }

    public RiskAcceptanceStatus Acceptance { get; init; }
    public string? AcceptanceReason { get; init; }
    public DateTimeOffset? AcceptanceExpiresAt { get; init; }
    public Guid? RequestedByUserId { get; init; }
    public string? RequestedByName { get; init; }
    public DateTimeOffset? RequestedAt { get; init; }
    public Guid? DecidedByUserId { get; init; }
    public string? DecidedByName { get; init; }
    public DateTimeOffset? DecidedAt { get; init; }
    public string? DecisionNote { get; init; }

    public required DateTimeOffset UpdatedAt { get; init; }

    public bool IsAccepted(DateTimeOffset now) => Acceptance == RiskAcceptanceStatus.Accepted && AcceptanceExpiresAt > now;

    /// <summary>Approved once, but the end date has passed: the risk needs fixing or a new decision.</summary>
    public bool IsExpired(DateTimeOffset now) => Acceptance == RiskAcceptanceStatus.Accepted && !(AcceptanceExpiresAt > now);

    /// <summary>A request may replace anything except a pending request or an acceptance that is still running.</summary>
    public bool CanRequest(DateTimeOffset now) => Acceptance != RiskAcceptanceStatus.Requested && !IsAccepted(now);

    public bool IsOverdue(DateOnly today) => DueDate < today;
}

/// <summary>
/// Who may track findings and accept risks. Four eyes: an Owner other than the requester approves a
/// risk acceptance, and every acceptance has an end date.
/// </summary>
public static class FindingTrackingPolicy
{
    public const int MaxOwnerLength = 200;
    public const int MaxReasonLength = 500;
    public const int MaxNoteLength = 500;

    /// <summary>The longest a risk can be accepted before someone has to look at it again.</summary>
    public const int MaxAcceptanceDays = 365;

    public const int DefaultAcceptanceDays = 90;

    public static bool CanEdit(PortalRole? role) => role is PortalRole.Owner or PortalRole.MspAdmin;

    /// <summary>Only checks that failed or need review have a risk to accept.</summary>
    public static bool CanBeAccepted(FindingStatus status) => status is FindingStatus.Failed or FindingStatus.Investigate;

    /// <summary>Why <paramref name="approverId"/> can't decide <paramref name="tracking"/>'s request, or null if they can.</summary>
    public static string? WhyCannotDecide(FindingTracking tracking, Guid? approverId, PortalRole? approverRole)
    {
        if (tracking.Acceptance != RiskAcceptanceStatus.Requested)
            return "No risk acceptance is waiting for a decision.";
        if (approverId is null || approverRole != PortalRole.Owner)
            return "Accepting a risk leaves it open, so an Owner has to decide.";
        if (approverId == tracking.RequestedByUserId)
            return "You can't decide your own request: another Owner has to.";
        return null;
    }
}

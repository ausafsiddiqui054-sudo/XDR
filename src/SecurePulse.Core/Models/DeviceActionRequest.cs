namespace SecurePulse.Core.Models;

/// <summary>Intune remote actions. Write actions: remediation consent, an approval and an audit entry each (CLAUDE.md rule 5).</summary>
public enum DeviceAction
{
    Sync,
    Restart,
    Retire,
    Wipe,

    /// <summary>Defender Antivirus quick scan (Windows).</summary>
    DefenderQuickScan,

    /// <summary>Defender Antivirus security intelligence (signature) update (Windows).</summary>
    DefenderUpdateSignatures
}

public enum DeviceActionStatus
{
    /// <summary>Waiting for a second person to approve.</summary>
    PendingApproval,

    /// <summary>Approved; the Worker sends it on its next pass.</summary>
    Approved,

    Rejected,

    /// <summary>Withdrawn by the requester or an operator, or because remediation access was turned off.</summary>
    Cancelled,

    /// <summary>Not approved in time, or approved but not sent in time.</summary>
    Expired,

    /// <summary>Claimed by the Worker; the Graph call is in progress.</summary>
    Sending,

    /// <summary>Intune accepted the action (it reaches the device when the device next checks in).</summary>
    Sent,

    Failed
}

/// <summary>One requested remote action on one device, from request through approval to the Graph call.</summary>
public sealed record DeviceActionRequest
{
    public required Guid Id { get; init; }
    public required Guid TenantId { get; init; }

    /// <summary>Intune managed device ID (a GUID).</summary>
    public required string DeviceId { get; init; }

    public required string DeviceName { get; init; }
    public required DeviceAction Action { get; init; }
    public required string Reason { get; init; }
    public required DeviceActionStatus Status { get; init; }

    public required DateTimeOffset RequestedAt { get; init; }
    public required Guid RequestedByUserId { get; init; }
    public required string RequestedByName { get; init; }

    /// <summary>Approval deadline: after this a pending request expires.</summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset? DecidedAt { get; init; }
    public Guid? DecidedByUserId { get; init; }
    public string? DecidedByName { get; init; }

    /// <summary>The approver's role when they approved; the Worker re-checks the policy against it.</summary>
    public PortalRole? DecidedByRole { get; init; }

    public string? DecisionNote { get; init; }

    public DateTimeOffset? CancelledAt { get; init; }
    public string? CancelledBy { get; init; }

    public DateTimeOffset? SentAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public string? Error { get; init; }

    /// <summary>The playbook that proposed it; null for a manual request.</summary>
    public Guid? PlaybookId { get; init; }

    /// <summary>Approved by the playbook's pre-approval rather than a person deciding this request.</summary>
    public bool AutoApproved { get; init; }

    public bool IsOpen => Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved or DeviceActionStatus.Sending;
}

public sealed record DeviceActionQuery
{
    public Guid? TenantId { get; init; }
    public string? DeviceId { get; init; }
    public bool OpenOnly { get; init; }
    public int Limit { get; init; } = 200;
}

/// <summary>
/// Who may request and approve remote actions. Four eyes: the requester never approves their own
/// request; retire and wipe (which remove company data) need an Owner's approval.
/// </summary>
public static class DeviceActionPolicy
{
    /// <summary>How long a request waits for approval before it expires.</summary>
    public static readonly TimeSpan ApprovalWindow = TimeSpan.FromHours(24);

    /// <summary>An approved action not sent within this time expires instead of going out late.</summary>
    public static readonly TimeSpan SendWindow = TimeSpan.FromHours(1);

    public const int MaxReasonLength = 500;
    public const int MaxNoteLength = 500;

    public static bool IsDestructive(DeviceAction action) => action is DeviceAction.Retire or DeviceAction.Wipe;

    /// <summary>Whether <paramref name="action"/> exists for devices on <paramref name="platform"/>: the Defender actions are Windows only.</summary>
    public static bool AppliesTo(DeviceAction action, DevicePlatform platform) =>
        action is not (DeviceAction.DefenderQuickScan or DeviceAction.DefenderUpdateSignatures) || platform == DevicePlatform.Windows;

    public static bool CanRequest(PortalRole? role) => role is PortalRole.Owner or PortalRole.MspAdmin;

    /// <summary>Why <paramref name="approverId"/> can't approve <paramref name="request"/>, or null if they can.</summary>
    public static string? WhyCannotApprove(DeviceActionRequest request, Guid? approverId, PortalRole? approverRole)
    {
        if (approverId is null || approverRole is not (PortalRole.Owner or PortalRole.MspAdmin))
            return "Only Owners and MSP admins can approve device actions.";
        if (approverId == request.RequestedByUserId)
            return "You can't approve your own request: another admin has to.";
        if (IsDestructive(request.Action) && approverRole != PortalRole.Owner)
            return $"{request.Action} removes company data, so an Owner has to approve it.";
        return null;
    }
}

/// <summary>
/// The separate remediation app may hold exactly these application permissions: the one Intune
/// permission every remote action needs, and nothing else.
/// </summary>
public static class RemediationPermissions
{
    public const string PrivilegedOperations = "DeviceManagementManagedDevices.PrivilegedOperations.All";

    public static readonly IReadOnlyList<string> Required = [PrivilegedOperations];

    public static IReadOnlyList<string> MissingFrom(IEnumerable<string> granted)
    {
        var set = new HashSet<string>(granted, StringComparer.OrdinalIgnoreCase);
        return Required.Where(p => !set.Contains(p)).ToList();
    }

    /// <summary>Granted permissions beyond <see cref="Required"/>: the remediation app must not hold any.</summary>
    public static IReadOnlyList<string> Unexpected(IEnumerable<string> granted) =>
        granted.Where(p => !Required.Contains(p, StringComparer.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToList();
}

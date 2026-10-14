namespace SecurePulse.Core.Models;

public enum AuditOutcome
{
    Success,

    /// <summary>Tried and didn't happen (e.g. consent declined, verification failed).</summary>
    Failure,

    /// <summary>Refused for authorization reasons (e.g. no access, not allowed, wrong tenant).</summary>
    Denied
}

/// <summary>
/// One security-relevant event. Append-only: never updated or deleted, and deliberately not linked
/// by foreign key to tenants or users, so it outlives them.
/// </summary>
public sealed record AuditEvent
{
    public required Guid Id { get; init; }
    public required DateTimeOffset OccurredAt { get; init; }

    /// <summary>One of <see cref="AuditActions"/>, e.g. "people.invited".</summary>
    public required string Action { get; init; }

    public required AuditOutcome Outcome { get; init; }

    /// <summary>Portal user who acted, if any (null for anonymous visitors and the Worker).</summary>
    public Guid? ActorUserId { get; init; }

    /// <summary>Who acted, as shown at the time ("Name &lt;upn&gt;", "SecurePulse Worker", "Anonymous").</summary>
    public required string ActorName { get; init; }

    /// <summary>The SecurePulse tenant the event concerns, if any.</summary>
    public Guid? TenantId { get; init; }

    public string? TargetType { get; init; }
    public string? TargetId { get; init; }

    /// <summary>One readable sentence.</summary>
    public required string Summary { get; init; }

    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>();

    public string? IpAddress { get; init; }

    public string Category => AuditActions.CategoryOf(Action);
}

/// <summary>Every audited action. Stored as these strings, so never rename one; add new ones instead.</summary>
public static class AuditActions
{
    public const string SignIn = "auth.sign-in";
    public const string SignOut = "auth.sign-out";

    public const string InvitationAccepted = "people.invitation-accepted";
    public const string Invited = "people.invited";
    public const string RoleChanged = "people.role-changed";
    public const string Removed = "people.removed";

    public const string LinkCreated = "onboarding.link-created";
    public const string LinkCancelled = "onboarding.cancelled";
    public const string ConsentReceived = "onboarding.consent-received";
    public const string ConsentDeclined = "onboarding.consent-declined";
    public const string ConsentWrongTenant = "onboarding.consent-wrong-tenant";
    public const string ConsentLinkUnusable = "onboarding.consent-link-unusable";
    public const string TenantConnected = "onboarding.tenant-connected";
    public const string VerificationFailed = "onboarding.verification-failed";

    public const string DeviceActionRequested = "device.action-requested";

    public const string AuditExported = "audit.exported";

    public const string ScanRequested = "scan.requested";

    public const string ReportDownloaded = "report.downloaded";

    public static readonly IReadOnlyDictionary<string, string> Categories = new Dictionary<string, string>
    {
        ["auth"] = "Sign-in",
        ["people"] = "People",
        ["onboarding"] = "Onboarding",
        ["device"] = "Devices",
        ["audit"] = "Audit log",
        ["scan"] = "Scans",
        ["report"] = "Reports"
    };

    public static string CategoryOf(string action) => action.Split('.', 2)[0];

    public static string Label(string action) => action switch
    {
        SignIn => "Sign-in",
        SignOut => "Sign-out",
        InvitationAccepted => "Invitation accepted",
        Invited => "Person invited",
        RoleChanged => "Role changed",
        Removed => "Access removed",
        LinkCreated => "Consent link created",
        LinkCancelled => "Connection cancelled",
        ConsentReceived => "Consent received",
        ConsentDeclined => "Consent declined",
        ConsentWrongTenant => "Consent from wrong tenant",
        ConsentLinkUnusable => "Expired or used link",
        TenantConnected => "Tenant connected",
        VerificationFailed => "Verification failed",
        DeviceActionRequested => "Device action requested",
        AuditExported => "Audit log exported",
        ScanRequested => "Scan requested",
        ReportDownloaded => "Report downloaded",
        _ => action
    };
}

public sealed record AuditQuery
{
    public DateTimeOffset? From { get; init; }
    public DateTimeOffset? To { get; init; }

    /// <summary>Action category: "auth", "people" or "onboarding".</summary>
    public string? Category { get; init; }

    public AuditOutcome? Outcome { get; init; }
    public Guid? TenantId { get; init; }

    /// <summary>Case-insensitive text match on actor and summary.</summary>
    public string? Search { get; init; }

    /// <summary>Keyset cursor: only events older than this one (newest first).</summary>
    public (DateTimeOffset OccurredAt, Guid Id)? Before { get; init; }

    public int Limit { get; init; } = 50;
}

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
/// One security-relevant event. Append-only: never updated, and deleted only by the retention job
/// once older than the configured period (<see cref="AuditRetention"/>). Deliberately not linked by
/// foreign key to tenants or users, so it outlives them.
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

    /// <summary>
    /// When the database stored it (the database's clock, not the writer's). Null until stored.
    /// Exports to a SIEM follow this order, so events from hosts with skewed clocks aren't skipped.
    /// </summary>
    public DateTimeOffset? RecordedAt { get; init; }

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
    public const string DeviceActionApproved = "device.action-approved";
    public const string DeviceActionRejected = "device.action-rejected";
    public const string DeviceActionCancelled = "device.action-cancelled";
    public const string DeviceActionExpired = "device.action-expired";

    /// <summary>Written by the Worker before the Graph call; if it can't be written, nothing is sent.</summary>
    public const string DeviceActionSending = "device.action-sending";

    public const string DeviceActionResult = "device.action-result";

    public const string RemediationEnabled = "onboarding.remediation-enabled";
    public const string RemediationDisabled = "onboarding.remediation-disabled";

    public const string AuditExported = "audit.exported";

    /// <summary>Written before the retention job deletes anything; nothing is deleted if this can't be written.</summary>
    public const string AuditPurgeStarted = "audit.purge-started";

    /// <summary>The retention job's outcome: how many events older than the cutoff it deleted.</summary>
    public const string AuditPurged = "audit.purged";

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
        DeviceActionApproved => "Device action approved",
        DeviceActionRejected => "Device action rejected",
        DeviceActionCancelled => "Device action cancelled",
        DeviceActionExpired => "Device action expired",
        DeviceActionSending => "Device action sending",
        DeviceActionResult => "Device action result",
        RemediationEnabled => "Remediation access granted",
        RemediationDisabled => "Remediation access turned off",
        AuditExported => "Audit log exported",
        AuditPurgeStarted => "Audit retention started",
        AuditPurged => "Old audit events removed",
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

    /// <summary>One exact action, e.g. <see cref="AuditActions.AuditPurged"/>.</summary>
    public string? Action { get; init; }

    public AuditOutcome? Outcome { get; init; }
    public Guid? TenantId { get; init; }

    /// <summary>Case-insensitive text match on actor and summary.</summary>
    public string? Search { get; init; }

    /// <summary>Keyset cursor: only events older than this one (newest first).</summary>
    public (DateTimeOffset OccurredAt, Guid Id)? Before { get; init; }

    public int Limit { get; init; } = 50;
}

/// <summary>
/// How long audit events are kept. Deleting them is an organisational decision, so nothing is
/// deleted until a period is configured, and never anything younger than <see cref="Minimum"/>
/// (the database enforces the same floor).
/// </summary>
public static class AuditRetention
{
    /// <summary>The shortest period that can be configured. Matches the floor in the audit_events trigger.</summary>
    public static readonly TimeSpan Minimum = TimeSpan.FromDays(90);

    /// <summary>Why <paramref name="retainFor"/> can't be used, or null.</summary>
    public static string? Problem(TimeSpan retainFor) =>
        retainFor < Minimum ? $"must be at least {Minimum.TotalDays:0} days (it's {retainFor.TotalDays:0.##})." : null;
}

/// <summary>Where audit events are exported to, and how far each export has got.</summary>
public static class AuditExportDestinations
{
    /// <summary>Microsoft Sentinel (a Log Analytics workspace) through the Azure Monitor Logs Ingestion API.</summary>
    public const string Sentinel = "sentinel";
}

/// <summary>An export destination's progress, for the Audit log page.</summary>
public sealed record AuditExportStatus
{
    public required string Destination { get; init; }

    /// <summary>Events sent so far (counted by SecurePulse; duplicates after a retry count twice).</summary>
    public long ExportedCount { get; init; }

    /// <summary>Stored events not exported yet (including the newest ones still inside the export lag).</summary>
    public long Pending { get; init; }

    public DateTimeOffset? LastExportedAt { get; init; }
    public DateTimeOffset? LastAttemptAt { get; init; }

    /// <summary>The last attempt's error; null once an attempt succeeds.</summary>
    public string? LastError { get; init; }
}

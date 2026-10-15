namespace SecurePulse.Core.Models;

/// <summary>The device conditions a playbook watches for, checked against the inventory after each device sync.</summary>
public enum PlaybookTrigger
{
    /// <summary>The device hasn't checked in with Intune for <see cref="RemediationPlaybook.Days"/> days.</summary>
    NotCheckedIn,

    /// <summary>Intune reports the device noncompliant.</summary>
    Noncompliant,

    /// <summary>Defender Antivirus reports its security intelligence (signatures) out of date.</summary>
    DefenderSignaturesOutOfDate,

    /// <summary>Defender Antivirus reports its quick scan overdue.</summary>
    DefenderQuickScanOverdue,

    /// <summary>Defender Antivirus needs a restart to finish (an update or a remediation).</summary>
    DefenderRebootRequired
}

/// <summary>
/// A remediation playbook: when a device matches <see cref="Trigger"/>, propose <see cref="Action"/> for it.
/// Each proposal is a pending device action that a second person approves (<see cref="DeviceActionPolicy"/>),
/// exactly like a manual request, unless another Owner pre-approved the playbook (<see cref="PlaybookPreApproval"/>).
/// </summary>
public sealed record RemediationPlaybook
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public bool Enabled { get; init; }

    public required PlaybookTrigger Trigger { get; init; }

    /// <summary>Only for <see cref="PlaybookTrigger.NotCheckedIn"/>: how many days without a check-in.</summary>
    public int? Days { get; init; }

    public required DeviceAction Action { get; init; }

    /// <summary>One tenant, or null for every tenant with remediation access.</summary>
    public Guid? TenantId { get; init; }

    /// <summary>At most this many proposals per tenant per sync, so a bad day can't flood the approval queue.</summary>
    public int MaxPerRun { get; init; } = PlaybookRules.DefaultMaxPerRun;

    /// <summary>A device gets at most one proposal from this playbook per cooldown, whatever happened to the last one.</summary>
    public TimeSpan Cooldown { get; init; } = PlaybookRules.DefaultCooldown;

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Whoever last saved the playbook. Its proposals are requested in their name, so they can't approve
    /// them: four eyes, as with manual requests.
    /// </summary>
    public required Guid UpdatedByUserId { get; init; }

    public required string UpdatedByName { get; init; }
    public required DateTimeOffset UpdatedAt { get; init; }

    /// <summary>When the Worker last checked a tenant's devices against this playbook.</summary>
    public DateTimeOffset? LastRunAt { get; init; }

    /// <summary>
    /// Pre-approved playbooks send at most this many actions per tenant in any 24 hours without a person
    /// approving each one; proposals beyond it wait in the queue as usual.
    /// </summary>
    public int DailyAutoLimit { get; init; } = PlaybookPreApproval.DefaultDailyLimit;

    /// <summary>
    /// The Owner (not the last editor) who pre-approved this exact version. Any save clears it, so what was
    /// approved is what runs. See <see cref="PlaybookPreApproval"/>.
    /// </summary>
    public Guid? PreApprovedByUserId { get; init; }

    public string? PreApprovedByName { get; init; }
    public DateTimeOffset? PreApprovedAt { get; init; }
    public DateTimeOffset? PreApprovalExpiresAt { get; init; }
}

/// <summary>
/// Pre-approval lets a playbook's proposals go out without a person approving each one. Four eyes move to the
/// playbook: an Owner other than its last editor approves the rule itself, for <see cref="Validity"/>, and only
/// for actions that don't interrupt the person using the device.
/// </summary>
public static class PlaybookPreApproval
{
    public static readonly TimeSpan Validity = TimeSpan.FromDays(90);
    public const int DefaultDailyLimit = 25;
    public const int MaxDailyLimit = 100;

    /// <summary>Sync and the Defender actions. Restart loses unsaved work, so it always needs a person; retire and wipe can't be in a playbook.</summary>
    public static bool IsEligible(DeviceAction action) =>
        action is DeviceAction.Sync or DeviceAction.DefenderQuickScan or DeviceAction.DefenderUpdateSignatures;

    /// <summary>Why <paramref name="granterId"/> can't pre-approve <paramref name="p"/>, or null.</summary>
    public static string? WhyCannotGrant(RemediationPlaybook p, Guid? granterId, PortalRole? granterRole)
    {
        if (granterId is null || granterRole != PortalRole.Owner) return "Only Owners can pre-approve playbooks.";
        if (granterId == p.UpdatedByUserId) return "You saved this playbook last, so another Owner has to pre-approve it.";
        if (!IsEligible(p.Action)) return $"{p.Action} can't be pre-approved: each one needs a person's approval.";
        if (PlaybookRules.Problem(p) is { } problem) return problem;
        return null;
    }

    /// <summary>
    /// Whether <paramref name="p"/>'s proposals may be approved automatically at <paramref name="now"/>.
    /// <paramref name="granterIsOwner"/>: the pre-approving person is still an Owner today.
    /// </summary>
    public static bool IsActive(RemediationPlaybook p, DateTimeOffset now, bool granterIsOwner) =>
        p.Enabled && granterIsOwner && IsEligible(p.Action) && PlaybookRules.Problem(p) is null
        && p.PreApprovedByUserId is { } by && by != p.UpdatedByUserId
        && p.PreApprovedAt is { } at && at <= now
        && p.PreApprovalExpiresAt is { } until && until > now && until <= at + Validity;
}

/// <summary>What a playbook may do. Only non-destructive actions that fit the trigger; retire and wipe are never automated.</summary>
public static class PlaybookRules
{
    public const int MaxNameLength = 100;
    public const int DefaultMaxPerRun = 20;
    public const int MaxMaxPerRun = 100;
    public const int MaxDays = 90;
    public static readonly TimeSpan DefaultCooldown = TimeSpan.FromDays(1);
    public static readonly TimeSpan MinCooldown = TimeSpan.FromHours(1);
    public static readonly TimeSpan MaxCooldown = TimeSpan.FromDays(30);

    /// <summary>The actions that make sense for each trigger. Never retire or wipe.</summary>
    public static IReadOnlyList<DeviceAction> ActionsFor(PlaybookTrigger trigger) => trigger switch
    {
        PlaybookTrigger.NotCheckedIn => [DeviceAction.Sync, DeviceAction.Restart],
        PlaybookTrigger.Noncompliant => [DeviceAction.Sync, DeviceAction.Restart],
        PlaybookTrigger.DefenderSignaturesOutOfDate => [DeviceAction.DefenderUpdateSignatures, DeviceAction.Sync],
        PlaybookTrigger.DefenderQuickScanOverdue => [DeviceAction.DefenderQuickScan],
        PlaybookTrigger.DefenderRebootRequired => [DeviceAction.Restart],
        _ => []
    };

    /// <summary>Why <paramref name="p"/> can't be saved, or null.</summary>
    public static string? Problem(RemediationPlaybook p)
    {
        if (string.IsNullOrWhiteSpace(p.Name)) return "Give the playbook a name.";
        if (p.Name.Trim().Length > MaxNameLength) return $"Keep the name under {MaxNameLength} characters.";
        if (!Enum.IsDefined(p.Trigger)) return "Choose a trigger.";
        if (DeviceActionPolicy.IsDestructive(p.Action)) return $"{p.Action} removes company data, so it can't be automated.";
        if (!ActionsFor(p.Trigger).Contains(p.Action)) return $"{p.Action} isn't an action for this trigger.";
        if (p.Trigger == PlaybookTrigger.NotCheckedIn)
        {
            if (p.Days is not (>= 1 and <= MaxDays)) return $"Days without a check-in must be between 1 and {MaxDays}.";
        }
        else if (p.Days is not null) return "Days only applies to the \"not checked in\" trigger.";
        if (p.MaxPerRun is < 1 or > MaxMaxPerRun) return $"Proposals per sync must be between 1 and {MaxMaxPerRun}.";
        if (p.Cooldown < MinCooldown || p.Cooldown > MaxCooldown) return "The cooldown must be between 1 hour and 30 days.";
        if (p.DailyAutoLimit is < 1 or > PlaybookPreApproval.MaxDailyLimit)
            return $"The daily limit for pre-approved actions must be between 1 and {PlaybookPreApproval.MaxDailyLimit}.";
        return null;
    }
}

/// <summary>One device a playbook wants an action for, with the reason the approver sees.</summary>
public sealed record PlaybookProposal(ManagedDevice Device, string Reason);

/// <summary>
/// Matches a tenant's synced inventory against a playbook. Pure: no I/O, no clock of its own, so the
/// Worker and the tests run the same rules.
/// </summary>
public static class PlaybookEvaluator
{
    /// <param name="recentlyProposed">Device IDs this playbook proposed something for within its cooldown.</param>
    public static IReadOnlyList<PlaybookProposal> Evaluate(RemediationPlaybook playbook, Tenant tenant, IEnumerable<ManagedDevice> devices,
        IReadOnlySet<string> recentlyProposed, DateTimeOffset now)
    {
        if (!playbook.Enabled || PlaybookRules.Problem(playbook) is not null || !tenant.CanRemediate) return [];
        if (playbook.TenantId is { } only && only != tenant.Id) return [];

        return devices
            .Where(d => d.TenantId == tenant.Id && !recentlyProposed.Contains(d.Id) && DeviceActionPolicy.AppliesTo(playbook.Action, d.Platform))
            .Select(d => (Device: d, Why: Why(playbook, d, now)))
            .Where(x => x.Why is not null)
            .OrderBy(x => x.Device.DeviceName, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Device.Id, StringComparer.Ordinal)
            .Take(playbook.MaxPerRun)
            .Select(x => new PlaybookProposal(x.Device, Clip($"Playbook \"{playbook.Name.Trim()}\": {x.Why}")))
            .ToList();
    }

    /// <summary>Why the device matches the trigger, or null if it doesn't.</summary>
    public static string? Why(RemediationPlaybook playbook, ManagedDevice d, DateTimeOffset now)
    {
        var av = d.DefenderDetails?.Antivirus;
        return playbook.Trigger switch
        {
            PlaybookTrigger.NotCheckedIn when d.LastSyncAt is { } last && now - last >= TimeSpan.FromDays(playbook.Days ?? int.MaxValue) =>
                $"hasn't checked in with Intune for {(int)(now - last).TotalDays} days (last {last.UtcDateTime:yyyy-MM-dd}).",
            PlaybookTrigger.Noncompliant when d.ComplianceState == DeviceComplianceState.Noncompliant =>
                "Intune reports it noncompliant.",
            PlaybookTrigger.DefenderSignaturesOutOfDate when av?.SignaturesOutOfDate == true =>
                $"Defender security intelligence is out of date{(av.SignatureVersion is { Length: > 0 } v ? $" (version {v})" : "")}.",
            PlaybookTrigger.DefenderQuickScanOverdue when av?.QuickScanOverdue == true =>
                $"Defender quick scan is overdue{(av.LastQuickScanAt is { } scan ? $" (last {scan.UtcDateTime:yyyy-MM-dd})" : "")}.",
            PlaybookTrigger.DefenderRebootRequired when av?.RebootRequired == true || av?.ThreatState == DefenderThreatState.RebootPending =>
                "Defender needs a restart to finish an update or remediation.",
            _ => null
        };
    }

    private static string Clip(string s) => s.Length > DeviceActionPolicy.MaxReasonLength ? s[..(DeviceActionPolicy.MaxReasonLength - 1)] + "…" : s;
}

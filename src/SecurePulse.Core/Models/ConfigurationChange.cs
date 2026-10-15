namespace SecurePulse.Core.Models;

/// <summary>
/// The separate configuration app may hold exactly these application permissions: reading policies and writing
/// Conditional Access, which Graph requires together to create a policy. Nothing else.
/// </summary>
public static class ConfigurationPermissions
{
    public const string PolicyRead = "Policy.Read.All";
    public const string ConditionalAccessWrite = "Policy.ReadWrite.ConditionalAccess";

    public static readonly IReadOnlyList<string> Required = [PolicyRead, ConditionalAccessWrite];

    public static IReadOnlyList<string> MissingFrom(IEnumerable<string> granted)
    {
        var set = new HashSet<string>(granted, StringComparer.OrdinalIgnoreCase);
        return Required.Where(p => !set.Contains(p)).ToList();
    }

    /// <summary>Granted permissions beyond <see cref="Required"/>: the configuration app must not hold any.</summary>
    public static IReadOnlyList<string> Unexpected(IEnumerable<string> granted) =>
        granted.Where(p => !Required.Contains(p, StringComparer.OrdinalIgnoreCase)).Order(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>
/// One reviewed fix: a Conditional Access policy created in report-only mode, which changes no sign-in until a
/// tenant admin switches it on in Entra. The policy body is a constant; nothing from a finding or a tenant goes into it.
/// </summary>
public sealed record ConfigurationFix(
    string Id,
    string Title,
    string Description,
    IReadOnlyList<string> CheckIds,
    string PolicyDisplayName,
    string PolicyJson);

/// <summary>The catalog of fixes SecurePulse can apply. Adding one is a reviewed code change, never configuration.</summary>
public static class ConfigurationFixes
{
    /// <summary>Every policy SecurePulse creates starts with this, so they're easy to find (and to recognise as already created).</summary>
    public const string PolicyNamePrefix = "SecurePulse - ";

    public const string ReportOnly = "enabledForReportingButNotEnforced";

    /// <summary>Highly privileged roles, as CISA's SCuBA baseline lists them (role template IDs).</summary>
    public static readonly IReadOnlyList<string> PrivilegedRoleTemplateIds =
    [
        "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
        "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
        "fe930be7-5e62-47db-91af-98c3a49a38b1", // User Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", // SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de", // Exchange Administrator
        "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", // Hybrid Identity Administrator
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
        "158c047a-c907-4556-b7ef-446551a6b5f7"  // Cloud Application Administrator
    ];

    /// <summary>Built-in "Phishing-resistant MFA" authentication strength.</summary>
    public const string PhishingResistantStrengthId = "00000000-0000-0000-0000-000000000004";

    public static readonly ConfigurationFix BlockLegacyAuth = new(
        "block-legacy-auth",
        "Block legacy authentication",
        "Creates a Conditional Access policy, in report-only mode, that blocks Exchange ActiveSync and other legacy authentication " +
        "clients for all users. Legacy protocols can't do MFA, so they're the usual way into accounts with a leaked password.",
        ["MS.AAD.1.1v1"],
        PolicyNamePrefix + "Block legacy authentication (report-only)",
        $$$$"""
        {"displayName":"{{{{PolicyNamePrefix}}}}Block legacy authentication (report-only)","state":"{{{{ReportOnly}}}}",
         "conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["exchangeActiveSync","other"]},
         "grantControls":{"operator":"OR","builtInControls":["block"]}}
        """);

    public static readonly ConfigurationFix MfaForAllUsers = new(
        "mfa-all-users",
        "Require MFA for all users",
        "Creates a Conditional Access policy, in report-only mode, that requires multifactor authentication for all users and apps.",
        ["MS.AAD.3.2v1"],
        PolicyNamePrefix + "Require MFA for all users (report-only)",
        $$$$"""
        {"displayName":"{{{{PolicyNamePrefix}}}}Require MFA for all users (report-only)","state":"{{{{ReportOnly}}}}",
         "conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},
         "grantControls":{"operator":"OR","builtInControls":["mfa"]}}
        """);

    public static readonly ConfigurationFix PhishingResistantMfaForAdmins = new(
        "phishing-resistant-mfa-admins",
        "Require phishing-resistant MFA for highly privileged roles",
        "Creates a Conditional Access policy, in report-only mode, that requires the built-in phishing-resistant MFA strength " +
        "(passkeys, FIDO2 keys, Windows Hello, certificates) for the highly privileged roles in CISA's baseline.",
        ["MS.AAD.3.6v1"],
        PolicyNamePrefix + "Phishing-resistant MFA for privileged roles (report-only)",
        $$$$"""
        {"displayName":"{{{{PolicyNamePrefix}}}}Phishing-resistant MFA for privileged roles (report-only)","state":"{{{{ReportOnly}}}}",
         "conditions":{"users":{"includeRoles":["{{{{string.Join("\",\"", PrivilegedRoleTemplateIds)}}}}"]},"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},
         "grantControls":{"operator":"OR","authenticationStrength":{"id":"{{{{PhishingResistantStrengthId}}}}"}}}
        """);

    public static readonly IReadOnlyList<ConfigurationFix> All = [BlockLegacyAuth, MfaForAllUsers, PhishingResistantMfaForAdmins];

    public static ConfigurationFix? Find(string? id) => All.FirstOrDefault(f => f.Id == id);

    /// <summary>The fix for a failed check, by its engine check ID (ScubaGear and Maester's CISA tests share the IDs).</summary>
    public static ConfigurationFix? ForCheck(string? checkId) =>
        checkId is null ? null : All.FirstOrDefault(f => f.CheckIds.Contains(checkId, StringComparer.OrdinalIgnoreCase));
}

/// <summary>One requested configuration fix for one tenant, from request through an Owner's approval to the Graph call.</summary>
public sealed record ConfigurationChangeRequest
{
    public required Guid Id { get; init; }
    public required Guid TenantId { get; init; }

    /// <summary><see cref="ConfigurationFix.Id"/>.</summary>
    public required string FixId { get; init; }

    /// <summary>The failed check that prompted it.</summary>
    public string? CheckId { get; init; }

    public required string Reason { get; init; }
    public required DeviceActionStatus Status { get; init; }

    public required DateTimeOffset RequestedAt { get; init; }
    public required Guid RequestedByUserId { get; init; }
    public required string RequestedByName { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }

    public DateTimeOffset? DecidedAt { get; init; }
    public Guid? DecidedByUserId { get; init; }
    public string? DecidedByName { get; init; }
    public PortalRole? DecidedByRole { get; init; }
    public string? DecisionNote { get; init; }

    public DateTimeOffset? CancelledAt { get; init; }
    public string? CancelledBy { get; init; }
    public DateTimeOffset? SentAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
    public string? Error { get; init; }

    /// <summary>The Conditional Access policy's ID once created (or found already created).</summary>
    public string? PolicyId { get; init; }

    /// <summary>The finding playbook that proposed it; null for a manual request.</summary>
    public Guid? PlaybookId { get; init; }

    public bool IsOpen => Status is DeviceActionStatus.PendingApproval or DeviceActionStatus.Approved or DeviceActionStatus.Sending;
}

public sealed record ConfigurationChangeQuery
{
    public Guid? TenantId { get; init; }
    public bool OpenOnly { get; init; }
    public int Limit { get; init; } = 200;
}

/// <summary>
/// Who may request and approve configuration fixes. They change a tenant's sign-in policy, so every one needs an
/// Owner other than the requester, every time: there's no pre-approval for configuration changes.
/// </summary>
public static class ConfigurationChangePolicy
{
    public static readonly TimeSpan ApprovalWindow = TimeSpan.FromHours(72);
    public static readonly TimeSpan SendWindow = TimeSpan.FromHours(1);

    public static bool CanRequest(PortalRole? role) => role is PortalRole.Owner or PortalRole.MspAdmin;

    public static string? WhyCannotApprove(ConfigurationChangeRequest request, Guid? approverId, PortalRole? approverRole)
    {
        if (approverId is null || approverRole != PortalRole.Owner)
            return "Configuration changes need an Owner's approval.";
        if (approverId == request.RequestedByUserId)
            return "You can't approve your own request: another Owner has to.";
        return null;
    }
}

/// <summary>
/// When a check from the catalog fails for a tenant, propose its fix. Proposals always wait for another Owner's
/// approval; there is no pre-approval for configuration changes.
/// </summary>
public sealed record FindingPlaybook
{
    public required Guid Id { get; init; }

    /// <summary><see cref="ConfigurationFix.Id"/>.</summary>
    public required string FixId { get; init; }

    public bool Enabled { get; init; }

    /// <summary>One tenant, or null for every tenant that granted configuration access.</summary>
    public Guid? TenantId { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>Proposals are requested in this person's name, so they can't approve them.</summary>
    public required Guid UpdatedByUserId { get; init; }

    public required string UpdatedByName { get; init; }
    public required DateTimeOffset UpdatedAt { get; init; }
    public DateTimeOffset? LastRunAt { get; init; }
}

public static class FindingPlaybookRules
{
    /// <summary>A tenant gets at most one proposal per fix from a playbook in this time, whatever happened to the last one.</summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromDays(7);

    /// <summary>The fix's reason for <paramref name="tenant"/>, or null when nothing should be proposed.</summary>
    public static string? Proposal(FindingPlaybook playbook, ConfigurationFix fix, Tenant tenant, IEnumerable<Finding> findings)
    {
        if (!playbook.Enabled || playbook.FixId != fix.Id || !tenant.CanConfigure) return null;
        if (playbook.TenantId is { } only && only != tenant.Id) return null;
        var failed = findings
            .Where(f => f.TenantId == tenant.Id && f.Status == FindingStatus.Failed && fix.CheckIds.Contains(f.SourceCheckId ?? "", StringComparer.OrdinalIgnoreCase))
            .OrderBy(f => f.Source, StringComparer.Ordinal)
            .ToList();
        if (failed.Count == 0) return null;
        var checks = string.Join(", ", failed.Select(f => $"{f.Source} {f.SourceCheckId}").Distinct());
        var text = $"Finding playbook \"{fix.Title}\": {checks} failed ({failed[0].Title}).";
        return text.Length > DeviceActionPolicy.MaxReasonLength ? text[..(DeviceActionPolicy.MaxReasonLength - 1)] + "…" : text;
    }
}

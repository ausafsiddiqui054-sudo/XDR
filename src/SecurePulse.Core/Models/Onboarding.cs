namespace SecurePulse.Core.Models;

/// <summary>What a consent link asks for.</summary>
public enum OnboardingKind
{
    /// <summary>Read-only assessment consent to the main app; connects the tenant.</summary>
    Assessment,

    /// <summary>Write consent to the separate remediation app, for an already connected tenant.</summary>
    Remediation,

    /// <summary>Consent to the separate configuration app (Conditional Access), for an already connected tenant.</summary>
    Configuration
}

public enum OnboardingStatus
{
    /// <summary>Link created; waiting for the client's admin to grant consent.</summary>
    AwaitingConsent,

    /// <summary>Consent callback received; the Worker is confirming it with a real token.</summary>
    Verifying,

    Completed,
    Failed,
    Cancelled
}

/// <summary>
/// One attempt to connect a client tenant through Entra admin consent. The tenant record is
/// created only after the Worker has verified the consent with an app-only token.
/// </summary>
public sealed record OnboardingRequest
{
    public required Guid Id { get; init; }
    public OnboardingKind Kind { get; init; } = OnboardingKind.Assessment;
    public required string DisplayName { get; init; }
    public required string PrimaryDomain { get; init; }
    public string? PartnerName { get; init; }
    public string Industry { get; init; } = "General";

    /// <summary>The Entra tenant the domain resolved to. Consent from any other tenant is rejected.</summary>
    public required Guid EntraTenantId { get; init; }

    public required OnboardingStatus Status { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? ConsentReceivedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }

    /// <summary>The connected tenant, once completed.</summary>
    public Guid? TenantId { get; init; }

    public string? LastError { get; init; }

    /// <summary>Portal user who created the consent link (audit).</summary>
    public string? StartedBy { get; init; }

    public IReadOnlyList<string> GrantedPermissions { get; init; } = [];
    public int VerificationAttempts { get; init; }

    /// <summary>
    /// The consent link's state value, encrypted with the portal's data-protection keys so the
    /// link can be shown again. Lookups use a hash of the state, never this value.
    /// </summary>
    public string? ProtectedState { get; init; }

    public bool IsExpired(DateTimeOffset now) => Status == OnboardingStatus.AwaitingConsent && now >= ExpiresAt;
}

public sealed record GraphPermission(string Name, string Purpose, string Group);

/// <summary>
/// Read-only Microsoft Graph application permissions the assessment app needs. One list shared
/// by the portal (shown to admins before they consent) and the Worker (checked after consent and
/// before every scan). Maester's list follows its documentation for unattended runs (v2.3.0);
/// its optional privileged extras (ReportSettings.ReadWrite.All, Exchange.ManageAsApp,
/// Sites.FullControl.All) are deliberately not requested. ScubaGear's list is what its Entra ID
/// (aad) baseline needs (v1.8.0); its other products need Exchange.ManageAsApp, Sites.FullControl.All
/// or directory roles, so they aren't assessed.
/// </summary>
public static class AssessmentPermissions
{
    public const string DevicesGroup = "Devices (Intune)";
    public const string SecurityChecksGroup = "Security checks (Maester)";
    public const string CisaBaselineGroup = "CISA baseline checks (ScubaGear)";

    public static readonly IReadOnlyList<GraphPermission> Required =
    [
        new("DeviceManagementManagedDevices.Read.All", "Read Intune device inventory, compliance and Defender Antivirus state", DevicesGroup),
        new("DeviceManagementConfiguration.Read.All", "Read device configuration and compliance policies", DevicesGroup),
        new("ThreatHunting.Read.All", "Read Defender for Endpoint sensor health with read-only advanced hunting queries", DevicesGroup),

        new("AuditLog.Read.All", "Read sign-in and audit logs", SecurityChecksGroup),
        new("DeviceManagementRBAC.Read.All", "Read Intune role assignments", SecurityChecksGroup),
        new("DeviceManagementServiceConfig.Read.All", "Read Intune enrollment and service settings", SecurityChecksGroup),
        new("Directory.Read.All", "Read users, groups, apps and directory settings", SecurityChecksGroup),
        new("DirectoryRecommendations.Read.All", "Read Entra recommendations", SecurityChecksGroup),
        new("EntitlementManagement.Read.All", "Read access packages and reviews", SecurityChecksGroup),
        new("IdentityRiskEvent.Read.All", "Read identity risk detections", SecurityChecksGroup),
        new("NetworkAccess.Read.All", "Read Global Secure Access settings", SecurityChecksGroup),
        new("OnPremDirectorySynchronization.Read.All", "Read directory sync settings", SecurityChecksGroup),
        new("OrgSettings-AppsAndServices.Read.All", "Read organization app and service settings", SecurityChecksGroup),
        new("OrgSettings-Forms.Read.All", "Read Microsoft Forms settings", SecurityChecksGroup),
        new("Policy.Read.All", "Read authentication and authorization policies", SecurityChecksGroup),
        new("Policy.Read.ConditionalAccess", "Read Conditional Access policies", SecurityChecksGroup),
        new("Reports.Read.All", "Read usage and registration reports", SecurityChecksGroup),
        new("ReportSettings.Read.All", "Read report privacy settings", SecurityChecksGroup),
        new("RoleEligibilitySchedule.Read.Directory", "Read PIM eligible role assignments", SecurityChecksGroup),
        new("RoleManagement.Read.All", "Read directory role assignments", SecurityChecksGroup),
        new("RoleManagementAlert.Read.Directory", "Read PIM alerts", SecurityChecksGroup),
        new("SecurityIdentitiesSensors.Read.All", "Read Defender for Identity sensors", SecurityChecksGroup),
        new("SecurityIdentitiesHealth.Read.All", "Read Defender for Identity health", SecurityChecksGroup),
        new("SharePointTenantSettings.Read.All", "Read SharePoint tenant settings", SecurityChecksGroup),
        new("UserAuthenticationMethod.Read.All", "Read users' registered sign-in methods", SecurityChecksGroup),

        new("PrivilegedAccess.Read.AzureADGroup", "Read PIM for Groups settings", CisaBaselineGroup),
        new("PrivilegedEligibilitySchedule.Read.AzureADGroup", "Read PIM for Groups eligible assignments", CisaBaselineGroup),
        new("RoleManagement.Read.Directory", "Read directory roles and their members", CisaBaselineGroup),
        new("RoleManagementPolicy.Read.AzureADGroup", "Read PIM for Groups activation rules", CisaBaselineGroup),
        new("User.Read.All", "Read user accounts", CisaBaselineGroup)
    ];

    /// <summary>What each engine needs, so a tenant missing one engine's permissions can still run the others.</summary>
    private static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ByEngine = new Dictionary<string, IReadOnlyList<string>>
    {
        [ScanEngines.Maester] = Required.Where(p => p.Group is DevicesGroup or SecurityChecksGroup).Select(p => p.Name).ToList(),
        [ScanEngines.ScubaGear] =
        [
            "Directory.Read.All", "Policy.Read.All", "PrivilegedAccess.Read.AzureADGroup", "PrivilegedEligibilitySchedule.Read.AzureADGroup",
            "RoleManagement.Read.Directory", "RoleManagementPolicy.Read.AzureADGroup", "User.Read.All"
        ]
    };

    /// <summary>The permissions <paramref name="engine"/> needs; every required permission for an unknown engine.</summary>
    public static IReadOnlyList<string> RequiredFor(string engine) =>
        ByEngine.TryGetValue(engine, out var names) ? names : Required.Select(p => p.Name).ToList();

    /// <summary>Permissions in <paramref name="needed"/> (default: all required) that aren't in <paramref name="granted"/>.</summary>
    public static IReadOnlyList<string> MissingFrom(IEnumerable<string> granted, IEnumerable<string>? needed = null)
    {
        var set = new HashSet<string>(granted, StringComparer.OrdinalIgnoreCase);
        return (needed ?? Required.Select(p => p.Name)).Where(p => !set.Contains(p)).ToList();
    }

    /// <summary>Granted permissions that aren't read-only.</summary>
    public static IReadOnlyList<string> NotReadOnly(IEnumerable<string> granted) =>
        granted.Where(p => !IsReadOnly(p)).Order(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// Assessment consent must be read-only (CLAUDE.md rule 5). An allowlist, not a blocklist:
    /// only names with a Read/ReadBasic segment and no write-like segment count, so action
    /// permissions such as Mail.Send or Sites.FullControl.All are rejected too.
    /// </summary>
    public static bool IsReadOnly(string permission)
    {
        var segments = permission.Split('.');
        return segments.Any(s => s is "Read" or "ReadBasic")
               && !segments.Any(s => s.Contains("Write", StringComparison.OrdinalIgnoreCase)
                                     || s.Contains("PrivilegedOperations", StringComparison.OrdinalIgnoreCase));
    }
}

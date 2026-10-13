namespace SecurePulse.Core.Models;

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
    public IReadOnlyList<string> GrantedPermissions { get; init; } = [];
    public int VerificationAttempts { get; init; }

    /// <summary>
    /// The consent link's state value, encrypted with the portal's data-protection keys so the
    /// link can be shown again. Lookups use a hash of the state, never this value.
    /// </summary>
    public string? ProtectedState { get; init; }

    public bool IsExpired(DateTimeOffset now) => Status == OnboardingStatus.AwaitingConsent && now >= ExpiresAt;
}

public sealed record GraphPermission(string Name, string Purpose);

/// <summary>
/// Read-only Microsoft Graph application permissions the assessment app needs. One list shared
/// by the portal (shown to admins before they consent) and the Worker (checked after consent).
/// </summary>
public static class AssessmentPermissions
{
    public static readonly IReadOnlyList<GraphPermission> Required =
    [
        new("DeviceManagementManagedDevices.Read.All", "Read Intune device inventory and compliance state"),
        new("DeviceManagementConfiguration.Read.All", "Read which compliance settings each device passes or fails")
    ];

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
